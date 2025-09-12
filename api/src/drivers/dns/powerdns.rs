use super::{DnsProvider, DnsError, DnsRecord, DnsZone, DnsZoneInfo, DnssecKey};
use async_trait::async_trait;
use reqwest::{Client, header::{HeaderMap, HeaderValue}};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PowerDns {
    client: Client,
    api_key: String,
    base_url: String,
    server_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PowerDnsZone {
    id: Option<String>,
    name: String,
    #[serde(rename = "type")]
    zone_type: String,
    url: Option<String>,
    kind: String,
    rrsets: Option<Vec<PowerDnsRRSet>>,
    serial: Option<u32>,
    notified_serial: Option<u32>,
    edited_serial: Option<u32>,
    masters: Option<Vec<String>>,
    dnssec: Option<bool>,
    nsec3param: Option<String>,
    nsec3narrow: Option<bool>,
    presigned: Option<bool>,
    soa_edit: Option<String>,
    soa_edit_api: Option<String>,
    api_rectify: Option<bool>,
    zone: Option<String>,
    account: Option<String>,
    nameservers: Option<Vec<String>>,
    master_tsig_key_ids: Option<Vec<String>>,
    slave_tsig_key_ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PowerDnsRRSet {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    ttl: Option<u32>,
    changetype: Option<String>,
    records: Option<Vec<PowerDnsRecord>>,
    comments: Option<Vec<PowerDnsComment>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PowerDnsRecord {
    content: String,
    disabled: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PowerDnsComment {
    content: String,
    account: Option<String>,
    modified_at: Option<u64>,
}

#[derive(Debug, Serialize)]
struct CreateZoneRequest {
    name: String,
    kind: String,
    masters: Vec<String>,
    nameservers: Vec<String>,
    soa_edit_api: String,
}

#[derive(Debug, Deserialize)]
struct PowerDnsError {
    error: String,
}

#[derive(Debug, Deserialize)]
struct PowerDnsCryptokey {
    id: Option<u32>,
    keytype: String,
    active: bool,
    published: bool,
    dnskey: String,
    flags: u16,
    tag: u16,
    algorithm: String,
    bits: u16,
    privatekey: Option<String>,
}

impl PowerDns {
    pub fn new(api_key: String, api_url: String, server_id: Option<String>) -> Result<Self, DnsError> {
        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", HeaderValue::from_str(&api_key)
            .map_err(|_| DnsError::AuthenticationFailed)?);
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        Ok(PowerDns {
            client,
            api_key,
            base_url: api_url.trim_end_matches('/').to_string(),
            server_id: server_id.unwrap_or_else(|| "localhost".to_string()),
        })
    }

    async fn handle_response<T>(&self, response: reqwest::Response) -> Result<T, DnsError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();
        
        if status.is_success() {
            response.json().await
                .map_err(|e| DnsError::ParseError(e.to_string()))
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            Err(DnsError::AuthenticationFailed)
        } else if status.as_u16() == 404 {
            Err(DnsError::ZoneNotFound { zone: "unknown".to_string() })
        } else if status.as_u16() == 429 {
            Err(DnsError::RateLimitExceeded)
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| format!("HTTP {}", status));
            
            // Try to parse PowerDNS error format
            if let Ok(pdns_error) = serde_json::from_str::<PowerDnsError>(&error_text) {
                Err(DnsError::ApiError(pdns_error.error))
            } else {
                Err(DnsError::ApiError(format!("HTTP {}: {}", status, error_text)))
            }
        }
    }

    fn zone_url(&self, zone_id: &str) -> String {
        format!("{}/api/v1/servers/{}/zones/{}", self.base_url, self.server_id, zone_id)
    }

    fn zones_url(&self) -> String {
        format!("{}/api/v1/servers/{}/zones", self.base_url, self.server_id)
    }
}

#[async_trait]
impl DnsProvider for PowerDns {
    fn provider_name(&self) -> &'static str {
        "powerdns"
    }

    async fn health_check(&self) -> Result<(), DnsError> {
        let response = self.client
            .get(&format!("{}/api/v1/servers/{}", self.base_url, self.server_id))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(DnsError::AuthenticationFailed)
        }
    }

    async fn create_zone(&self, zone: &DnsZone) -> Result<DnsZoneInfo, DnsError> {
        let create_request = CreateZoneRequest {
            name: if zone.name.ends_with('.') { 
                zone.name.clone() 
            } else { 
                format!("{}.", zone.name) 
            },
            kind: "Native".to_string(),
            masters: vec![],
            nameservers: vec![format!("{}.", zone.primary_ns)],
            soa_edit_api: "INCEPTION-EPOCH".to_string(),
        };

        let response = self.client
            .post(&self.zones_url())
            .json(&create_request)
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let _: serde_json::Value = self.handle_response(response).await?;

        // PowerDNS returns the zone name as the ID
        let zone_id = create_request.name.clone();
        
        // Create SOA record
        let soa_content = format!(
            "{} {} {} {} {} {} {}",
            zone.primary_ns,
            zone.admin_email.replace('@', "."),
            zone.serial,
            zone.refresh,
            zone.retry,
            zone.expire,
            zone.minimum
        );

        let soa_rrset = PowerDnsRRSet {
            name: zone_id.clone(),
            record_type: "SOA".to_string(),
            ttl: Some(zone.minimum),
            changetype: Some("REPLACE".to_string()),
            records: Some(vec![PowerDnsRecord {
                content: soa_content,
                disabled: Some(false),
            }]),
            comments: None,
        };

        // Apply the SOA record
        self.client
            .patch(&self.zone_url(&zone_id))
            .json(&PowerDnsZone {
                id: None,
                name: zone_id.clone(),
                zone_type: "Zone".to_string(),
                url: None,
                kind: "Native".to_string(),
                rrsets: Some(vec![soa_rrset]),
                serial: None,
                notified_serial: None,
                edited_serial: None,
                masters: None,
                dnssec: None,
                nsec3param: None,
                nsec3narrow: None,
                presigned: None,
                soa_edit: None,
                soa_edit_api: None,
                api_rectify: None,
                zone: None,
                account: None,
                nameservers: None,
                master_tsig_key_ids: None,
                slave_tsig_key_ids: None,
            })
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        Ok(DnsZoneInfo {
            id: zone_id,
            name: zone.name.clone(),
            status: "active".to_string(),
            name_servers: vec![zone.primary_ns.clone()],
            dnssec_enabled: zone.dnssec_enabled,
        })
    }

    async fn get_zone(&self, zone_id: &str) -> Result<DnsZoneInfo, DnsError> {
        let response = self.client
            .get(&self.zone_url(zone_id))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let pdns_zone: PowerDnsZone = self.handle_response(response).await?;

        Ok(DnsZoneInfo {
            id: zone_id.to_string(),
            name: pdns_zone.name.trim_end_matches('.').to_string(),
            status: "active".to_string(),
            name_servers: pdns_zone.nameservers.unwrap_or_default(),
            dnssec_enabled: pdns_zone.dnssec.unwrap_or(false),
        })
    }

    async fn list_zones(&self) -> Result<Vec<DnsZoneInfo>, DnsError> {
        let response = self.client
            .get(&self.zones_url())
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let pdns_zones: Vec<PowerDnsZone> = self.handle_response(response).await?;

        Ok(pdns_zones.into_iter().map(|zone| DnsZoneInfo {
            id: zone.name.clone(),
            name: zone.name.trim_end_matches('.').to_string(),
            status: "active".to_string(),
            name_servers: zone.nameservers.unwrap_or_default(),
            dnssec_enabled: zone.dnssec.unwrap_or(false),
        }).collect())
    }

    async fn update_zone(&self, zone_id: &str, zone: &DnsZone) -> Result<(), DnsError> {
        // PowerDNS zone updates are typically done via RRSet modifications
        // Here we could update the SOA record with new values
        Ok(())
    }

    async fn delete_zone(&self, zone_id: &str) -> Result<(), DnsError> {
        let response = self.client
            .delete(&self.zone_url(zone_id))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(DnsError::ApiError(error_text))
        }
    }

    async fn create_record(&self, record: &DnsRecord) -> Result<String, DnsError> {
        let rrset = PowerDnsRRSet {
            name: if record.name.ends_with('.') {
                record.name.clone()
            } else {
                format!("{}.", record.name)
            },
            record_type: record.record_type.clone(),
            ttl: Some(record.ttl),
            changetype: Some("REPLACE".to_string()),
            records: Some(vec![PowerDnsRecord {
                content: record.content.clone(),
                disabled: Some(false),
            }]),
            comments: None,
        };

        let zone_update = PowerDnsZone {
            id: None,
            name: record.zone_id.clone(),
            zone_type: "Zone".to_string(),
            url: None,
            kind: "Native".to_string(),
            rrsets: Some(vec![rrset]),
            serial: None,
            notified_serial: None,
            edited_serial: None,
            masters: None,
            dnssec: None,
            nsec3param: None,
            nsec3narrow: None,
            presigned: None,
            soa_edit: None,
            soa_edit_api: None,
            api_rectify: None,
            zone: None,
            account: None,
            nameservers: None,
            master_tsig_key_ids: None,
            slave_tsig_key_ids: None,
        };

        let response = self.client
            .patch(&self.zone_url(&record.zone_id))
            .json(&zone_update)
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            // PowerDNS doesn't return a record ID, so we generate one based on name+type
            Ok(format!("{}-{}", record.name, record.record_type))
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(DnsError::ApiError(error_text))
        }
    }

    async fn get_record(&self, zone_id: &str, record_id: &str) -> Result<DnsRecord, DnsError> {
        let records = self.list_records(zone_id, None).await?;
        records.into_iter()
            .find(|r| r.id.as_deref() == Some(record_id))
            .ok_or_else(|| DnsError::RecordNotFound { record_id: record_id.to_string() })
    }

    async fn list_records(&self, zone_id: &str, record_type: Option<&str>) -> Result<Vec<DnsRecord>, DnsError> {
        let response = self.client
            .get(&self.zone_url(zone_id))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let pdns_zone: PowerDnsZone = self.handle_response(response).await?;

        let mut dns_records = Vec::new();
        
        if let Some(rrsets) = pdns_zone.rrsets {
            for rrset in rrsets {
                if let Some(filter_type) = record_type {
                    if rrset.record_type != filter_type {
                        continue;
                    }
                }

                if let Some(records) = rrset.records {
                    for (i, record) in records.iter().enumerate() {
                        dns_records.push(DnsRecord {
                            id: Some(format!("{}-{}-{}", rrset.name, rrset.record_type, i)),
                            zone_id: zone_id.to_string(),
                            name: rrset.name.trim_end_matches('.').to_string(),
                            record_type: rrset.record_type.clone(),
                            content: record.content.clone(),
                            ttl: rrset.ttl.unwrap_or(3600),
                            priority: None, // PowerDNS stores priority in content for MX records
                            proxied: None,
                        });
                    }
                }
            }
        }

        Ok(dns_records)
    }

    async fn update_record(&self, record_id: &str, record: &DnsRecord) -> Result<(), DnsError> {
        // For PowerDNS, updating a record is the same as creating it (REPLACE changetype)
        self.create_record(record).await?;
        Ok(())
    }

    async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<(), DnsError> {
        // Parse record_id to get name and type
        let parts: Vec<&str> = record_id.splitn(3, '-').collect();
        if parts.len() < 2 {
            return Err(DnsError::RecordNotFound { record_id: record_id.to_string() });
        }

        let record_name = parts[0];
        let record_type = parts[1];

        let rrset = PowerDnsRRSet {
            name: if record_name.ends_with('.') {
                record_name.to_string()
            } else {
                format!("{}.", record_name)
            },
            record_type: record_type.to_string(),
            changetype: Some("DELETE".to_string()),
            ttl: None,
            records: None,
            comments: None,
        };

        let zone_update = PowerDnsZone {
            id: None,
            name: zone_id.to_string(),
            zone_type: "Zone".to_string(),
            url: None,
            kind: "Native".to_string(),
            rrsets: Some(vec![rrset]),
            serial: None,
            notified_serial: None,
            edited_serial: None,
            masters: None,
            dnssec: None,
            nsec3param: None,
            nsec3narrow: None,
            presigned: None,
            soa_edit: None,
            soa_edit_api: None,
            api_rectify: None,
            zone: None,
            account: None,
            nameservers: None,
            master_tsig_key_ids: None,
            slave_tsig_key_ids: None,
        };

        let response = self.client
            .patch(&self.zone_url(zone_id))
            .json(&zone_update)
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(DnsError::ApiError(error_text))
        }
    }

    async fn set_dnssec(&self, zone_id: &str, enabled: bool) -> Result<(), DnsError> {
        if enabled {
            // Enable DNSSEC by creating keys
            let response = self.client
                .post(&format!("{}/cryptokeys", self.zone_url(zone_id)))
                .json(&serde_json::json!({
                    "keytype": "ksk",
                    "active": true,
                    "published": true
                }))
                .send()
                .await
                .map_err(|e| DnsError::NetworkError(e.to_string()))?;

            let _: serde_json::Value = self.handle_response(response).await?;
        } else {
            // Disable DNSSEC by removing all keys
            let response = self.client
                .get(&format!("{}/cryptokeys", self.zone_url(zone_id)))
                .send()
                .await
                .map_err(|e| DnsError::NetworkError(e.to_string()))?;

            let keys: Vec<PowerDnsCryptokey> = self.handle_response(response).await?;
            
            for key in keys {
                if let Some(key_id) = key.id {
                    self.client
                        .delete(&format!("{}/cryptokeys/{}", self.zone_url(zone_id), key_id))
                        .send()
                        .await
                        .map_err(|e| DnsError::NetworkError(e.to_string()))?;
                }
            }
        }

        Ok(())
    }

    async fn get_dnssec_keys(&self, zone_id: &str) -> Result<Vec<DnssecKey>, DnsError> {
        let response = self.client
            .get(&format!("{}/cryptokeys", self.zone_url(zone_id)))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let keys: Vec<PowerDnsCryptokey> = self.handle_response(response).await?;

        Ok(keys.into_iter().filter_map(|key| {
            Some(DnssecKey {
                id: key.id?.to_string(),
                algorithm: match key.algorithm.as_str() {
                    "RSASHA1" => 5,
                    "RSASHA256" => 8,
                    "RSASHA512" => 10,
                    "ECDSAP256SHA256" => 13,
                    "ECDSAP384SHA384" => 14,
                    _ => 8, // Default to RSA SHA-256
                },
                digest_type: 2, // SHA-256
                digest: "".to_string(), // PowerDNS doesn't provide digest directly
                public_key: key.dnskey,
                key_type: key.keytype.to_uppercase(),
            })
        }).collect())
    }

    async fn import_zone(&self, zone_id: &str, zone_file: &str) -> Result<(), DnsError> {
        // PowerDNS supports zone file import via the zones endpoint
        let response = self.client
            .put(&format!("{}/zone", self.zone_url(zone_id)))
            .header("Content-Type", "text/plain")
            .body(zone_file.to_string())
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Zone import failed".to_string());
            Err(DnsError::ApiError(error_text))
        }
    }

    async fn export_zone(&self, zone_id: &str) -> Result<String, DnsError> {
        let response = self.client
            .get(&format!("{}/export", self.zone_url(zone_id)))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            response.text().await
                .map_err(|e| DnsError::NetworkError(e.to_string()))
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Zone export failed".to_string());
            Err(DnsError::ApiError(error_text))
        }
    }
}