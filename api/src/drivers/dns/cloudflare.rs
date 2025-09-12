use super::{DnsProvider, DnsError, DnsRecord, DnsZone, DnsZoneInfo, DnssecKey};
use async_trait::async_trait;
use reqwest::{Client, header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE}};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CloudflareDns {
    client: Client,
    api_token: String,
    base_url: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    errors: Vec<CloudflareError>,
    messages: Vec<String>,
    result: Option<T>,
    result_info: Option<ResultInfo>,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: u32,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ResultInfo {
    page: u32,
    per_page: u32,
    count: u32,
    total_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct CloudflareZone {
    id: Option<String>,
    name: String,
    status: Option<String>,
    paused: Option<bool>,
    name_servers: Option<Vec<String>>,
    dnssec_status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CloudflareRecord {
    id: Option<String>,
    zone_id: Option<String>,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
    ttl: u32,
    priority: Option<u16>,
    proxied: Option<bool>,
    locked: Option<bool>,
    meta: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct CreateZoneRequest {
    name: String,
    #[serde(rename = "type")]
    zone_type: String,
}

#[derive(Debug, Deserialize)]
struct DnssecResponse {
    status: String,
    flags: u8,
    algorithm: u8,
    key_type: String,
    digest_type: u8,
    digest_algorithm: u8,
    digest: String,
    public_key: String,
    key_tag: u16,
}

impl CloudflareDns {
    pub fn new(api_token: String) -> Result<Self, DnsError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", api_token))
                .map_err(|e| DnsError::AuthenticationFailed)?,
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        Ok(CloudflareDns {
            client,
            api_token,
            base_url: "https://api.cloudflare.com/client/v4".to_string(),
        })
    }

    async fn handle_response<T>(&self, response: reqwest::Response) -> Result<T, DnsError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();
        let text = response.text().await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        if status.is_success() {
            let cf_response: CloudflareResponse<T> = serde_json::from_str(&text)
                .map_err(|e| DnsError::ParseError(e.to_string()))?;

            if cf_response.success {
                cf_response.result.ok_or_else(|| DnsError::ParseError("Missing result data".to_string()))
            } else {
                let error_msg = cf_response.errors.into_iter()
                    .map(|e| format!("{}: {}", e.code, e.message))
                    .collect::<Vec<_>>()
                    .join(", ");
                Err(DnsError::ApiError(error_msg))
            }
        } else if status.as_u16() == 429 {
            Err(DnsError::RateLimitExceeded)
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            Err(DnsError::AuthenticationFailed)
        } else {
            Err(DnsError::ApiError(format!("HTTP {}: {}", status, text)))
        }
    }
}

#[async_trait]
impl DnsProvider for CloudflareDns {
    fn provider_name(&self) -> &'static str {
        "cloudflare"
    }

    async fn health_check(&self) -> Result<(), DnsError> {
        let response = self.client
            .get(&format!("{}/user/tokens/verify", self.base_url))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let cf_response: CloudflareResponse<serde_json::Value> = response
            .json()
            .await
            .map_err(|e| DnsError::ParseError(e.to_string()))?;

        if cf_response.success {
            Ok(())
        } else {
            Err(DnsError::AuthenticationFailed)
        }
    }

    async fn create_zone(&self, zone: &DnsZone) -> Result<DnsZoneInfo, DnsError> {
        let create_request = CreateZoneRequest {
            name: zone.name.clone(),
            zone_type: "full".to_string(),
        };

        let response = self.client
            .post(&format!("{}/zones", self.base_url))
            .json(&create_request)
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let cf_zone: CloudflareZone = self.handle_response(response).await?;

        Ok(DnsZoneInfo {
            id: cf_zone.id.unwrap_or_default(),
            name: cf_zone.name,
            status: cf_zone.status.unwrap_or_default(),
            name_servers: cf_zone.name_servers.unwrap_or_default(),
            dnssec_enabled: cf_zone.dnssec_status.as_deref() == Some("active"),
        })
    }

    async fn get_zone(&self, zone_id: &str) -> Result<DnsZoneInfo, DnsError> {
        let response = self.client
            .get(&format!("{}/zones/{}", self.base_url, zone_id))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let cf_zone: CloudflareZone = self.handle_response(response).await?;

        Ok(DnsZoneInfo {
            id: cf_zone.id.unwrap_or_default(),
            name: cf_zone.name,
            status: cf_zone.status.unwrap_or_default(),
            name_servers: cf_zone.name_servers.unwrap_or_default(),
            dnssec_enabled: cf_zone.dnssec_status.as_deref() == Some("active"),
        })
    }

    async fn list_zones(&self) -> Result<Vec<DnsZoneInfo>, DnsError> {
        let response = self.client
            .get(&format!("{}/zones", self.base_url))
            .query(&[("per_page", "50")])
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let cf_zones: Vec<CloudflareZone> = self.handle_response(response).await?;

        Ok(cf_zones.into_iter().map(|cf_zone| DnsZoneInfo {
            id: cf_zone.id.unwrap_or_default(),
            name: cf_zone.name,
            status: cf_zone.status.unwrap_or_default(),
            name_servers: cf_zone.name_servers.unwrap_or_default(),
            dnssec_enabled: cf_zone.dnssec_status.as_deref() == Some("active"),
        }).collect())
    }

    async fn update_zone(&self, zone_id: &str, zone: &DnsZone) -> Result<(), DnsError> {
        // Cloudflare doesn't allow updating zone name, only settings
        let mut update_data = HashMap::new();
        update_data.insert("paused", false);
        
        let response = self.client
            .patch(&format!("{}/zones/{}", self.base_url, zone_id))
            .json(&update_data)
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let _: CloudflareZone = self.handle_response(response).await?;
        Ok(())
    }

    async fn delete_zone(&self, zone_id: &str) -> Result<(), DnsError> {
        let response = self.client
            .delete(&format!("{}/zones/{}", self.base_url, zone_id))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let _: serde_json::Value = self.handle_response(response).await?;
        Ok(())
    }

    async fn create_record(&self, record: &DnsRecord) -> Result<String, DnsError> {
        let cf_record = CloudflareRecord {
            id: None,
            zone_id: None,
            name: record.name.clone(),
            record_type: record.record_type.clone(),
            content: record.content.clone(),
            ttl: record.ttl,
            priority: record.priority,
            proxied: record.proxied,
            locked: None,
            meta: None,
        };

        let response = self.client
            .post(&format!("{}/zones/{}/dns_records", self.base_url, record.zone_id))
            .json(&cf_record)
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let created_record: CloudflareRecord = self.handle_response(response).await?;
        Ok(created_record.id.unwrap_or_default())
    }

    async fn get_record(&self, zone_id: &str, record_id: &str) -> Result<DnsRecord, DnsError> {
        let response = self.client
            .get(&format!("{}/zones/{}/dns_records/{}", self.base_url, zone_id, record_id))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let cf_record: CloudflareRecord = self.handle_response(response).await?;

        Ok(DnsRecord {
            id: cf_record.id,
            zone_id: zone_id.to_string(),
            name: cf_record.name,
            record_type: cf_record.record_type,
            content: cf_record.content,
            ttl: cf_record.ttl,
            priority: cf_record.priority,
            proxied: cf_record.proxied,
        })
    }

    async fn list_records(&self, zone_id: &str, record_type: Option<&str>) -> Result<Vec<DnsRecord>, DnsError> {
        let mut query_params = vec![("per_page", "100")];
        if let Some(rtype) = record_type {
            query_params.push(("type", rtype));
        }

        let response = self.client
            .get(&format!("{}/zones/{}/dns_records", self.base_url, zone_id))
            .query(&query_params)
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let cf_records: Vec<CloudflareRecord> = self.handle_response(response).await?;

        Ok(cf_records.into_iter().map(|cf_record| DnsRecord {
            id: cf_record.id,
            zone_id: zone_id.to_string(),
            name: cf_record.name,
            record_type: cf_record.record_type,
            content: cf_record.content,
            ttl: cf_record.ttl,
            priority: cf_record.priority,
            proxied: cf_record.proxied,
        }).collect())
    }

    async fn update_record(&self, record_id: &str, record: &DnsRecord) -> Result<(), DnsError> {
        let cf_record = CloudflareRecord {
            id: Some(record_id.to_string()),
            zone_id: None,
            name: record.name.clone(),
            record_type: record.record_type.clone(),
            content: record.content.clone(),
            ttl: record.ttl,
            priority: record.priority,
            proxied: record.proxied,
            locked: None,
            meta: None,
        };

        let response = self.client
            .put(&format!("{}/zones/{}/dns_records/{}", self.base_url, record.zone_id, record_id))
            .json(&cf_record)
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let _: CloudflareRecord = self.handle_response(response).await?;
        Ok(())
    }

    async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<(), DnsError> {
        let response = self.client
            .delete(&format!("{}/zones/{}/dns_records/{}", self.base_url, zone_id, record_id))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let _: serde_json::Value = self.handle_response(response).await?;
        Ok(())
    }

    async fn set_dnssec(&self, zone_id: &str, enabled: bool) -> Result<(), DnsError> {
        let endpoint = if enabled { "enable" } else { "disable" };
        let response = self.client
            .patch(&format!("{}/zones/{}/dnssec/{}", self.base_url, zone_id, endpoint))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let _: serde_json::Value = self.handle_response(response).await?;
        Ok(())
    }

    async fn get_dnssec_keys(&self, zone_id: &str) -> Result<Vec<DnssecKey>, DnsError> {
        let response = self.client
            .get(&format!("{}/zones/{}/dnssec", self.base_url, zone_id))
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(e.to_string()))?;

        let dnssec_response: DnssecResponse = self.handle_response(response).await?;

        Ok(vec![DnssecKey {
            id: format!("{}-{}", zone_id, dnssec_response.key_tag),
            algorithm: dnssec_response.algorithm,
            digest_type: dnssec_response.digest_type,
            digest: dnssec_response.digest,
            public_key: dnssec_response.public_key,
            key_type: dnssec_response.key_type,
        }])
    }

    async fn import_zone(&self, zone_id: &str, zone_file: &str) -> Result<(), DnsError> {
        // Cloudflare doesn't have a direct zone file import, 
        // would need to parse and create records individually
        Err(DnsError::ApiError("Zone file import not supported by Cloudflare API".to_string()))
    }

    async fn export_zone(&self, zone_id: &str) -> Result<String, DnsError> {
        let records = self.list_records(zone_id, None).await?;
        let zone_info = self.get_zone(zone_id).await?;
        
        let mut zone_file = format!(
            "; Zone file for {}\n",
            zone_info.name
        );
        
        for record in records {
            zone_file.push_str(&format!(
                "{}\t{}\tIN\t{}\t{}\n",
                record.name,
                record.ttl,
                record.record_type,
                record.content
            ));
        }
        
        Ok(zone_file)
    }
}