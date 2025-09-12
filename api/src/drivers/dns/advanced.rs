// Advanced DNS features: AXFR, DNSSEC, Zone validation
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::net::IpAddr;
use chrono::{DateTime, Utc};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecConfig {
    pub enabled: bool,
    pub algorithm: DnssecAlgorithm,
    pub ksk_bits: u32,
    pub zsk_bits: u32,
    pub salt: Option<String>,
    pub nsec3: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnssecAlgorithm {
    RsaSha256,
    RsaSha512,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecKeys {
    pub ksk: DnssecKey,
    pub zsk: DnssecKey,
    pub ds_record: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecKey {
    pub key_tag: u16,
    pub algorithm: u8,
    pub public_key: String,
    pub private_key: String,
    pub created_at: DateTime<Utc>,
    pub activate_at: DateTime<Utc>,
    pub expire_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTransferConfig {
    pub allow_transfer: Vec<IpAddr>,
    pub also_notify: Vec<IpAddr>,
    pub tsig_key: Option<TsigKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsigKey {
    pub name: String,
    pub algorithm: String,
    pub secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneValidation {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub soa_serial: u32,
    pub record_count: usize,
}

pub struct AdvancedDnsManager;

impl AdvancedDnsManager {
    // Perform AXFR zone transfer
    pub async fn zone_transfer(
        &self,
        zone: &str,
        master_server: &str,
        tsig_key: Option<&TsigKey>,
    ) -> Result<String> {
        let mut args = vec![
            "axfr".to_string(),
            zone.to_string(),
            format!("@{}", master_server),
        ];

        if let Some(tsig) = tsig_key {
            args.push("-y".to_string());
            args.push(format!("{}:{}", tsig.algorithm, tsig.secret));
        }

        let output = Command::new("dig")
            .args(&args)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Zone transfer failed: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        let zone_data = String::from_utf8_lossy(&output.stdout).to_string();
        
        // Validate the transferred zone
        self.validate_zone_data(&zone_data)?;
        
        Ok(zone_data)
    }

    // Enable DNSSEC for a zone
    pub async fn enable_dnssec(
        &self,
        zone: &str,
        config: &DnssecConfig,
    ) -> Result<DnssecKeys> {
        // Generate KSK (Key Signing Key)
        let ksk = self.generate_dnssec_key(zone, true, config).await?;
        
        // Generate ZSK (Zone Signing Key)
        let zsk = self.generate_dnssec_key(zone, false, config).await?;
        
        // Generate DS record for parent zone
        let ds_record = self.generate_ds_record(zone, &ksk)?;
        
        // Sign the zone
        self.sign_zone(zone, &ksk, &zsk, config).await?;
        
        Ok(DnssecKeys {
            ksk,
            zsk,
            ds_record,
        })
    }

    async fn generate_dnssec_key(
        &self,
        zone: &str,
        is_ksk: bool,
        config: &DnssecConfig,
    ) -> Result<DnssecKey> {
        let algorithm = match config.algorithm {
            DnssecAlgorithm::RsaSha256 => "RSASHA256",
            DnssecAlgorithm::RsaSha512 => "RSASHA512",
            DnssecAlgorithm::EcdsaP256Sha256 => "ECDSAP256SHA256",
            DnssecAlgorithm::EcdsaP384Sha384 => "ECDSAP384SHA384",
            DnssecAlgorithm::Ed25519 => "ED25519",
        };

        let key_size = if is_ksk { config.ksk_bits } else { config.zsk_bits };
        let key_type = if is_ksk { "KSK" } else { "ZSK" };

        let output = Command::new("dnssec-keygen")
            .args(&[
                "-a", algorithm,
                "-b", &key_size.to_string(),
                "-n", "ZONE",
                if is_ksk { "-f" } else { "" }, if is_ksk { "KSK" } else { "" },
                zone,
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to generate {} key: {}", 
                key_type, String::from_utf8_lossy(&output.stderr)));
        }

        let key_file = String::from_utf8_lossy(&output.stdout).trim().to_string();
        
        // Read the generated key files
        let public_key = std::fs::read_to_string(format!("{}.key", key_file))?;
        let private_key = std::fs::read_to_string(format!("{}.private", key_file))?;
        
        // Extract key tag from public key
        let key_tag = self.extract_key_tag(&public_key)?;
        
        Ok(DnssecKey {
            key_tag,
            algorithm: self.algorithm_to_number(&config.algorithm),
            public_key,
            private_key,
            created_at: Utc::now(),
            activate_at: Utc::now(),
            expire_at: None,
        })
    }

    fn generate_ds_record(&self, zone: &str, ksk: &DnssecKey) -> Result<String> {
        let output = Command::new("dnssec-dsfromkey")
            .args(&["-2", "-"])  // Use SHA-256
            .arg(format!("K{}+{:03}+{:05}", zone, ksk.algorithm, ksk.key_tag))
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to generate DS record"));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    async fn sign_zone(
        &self,
        zone: &str,
        ksk: &DnssecKey,
        zsk: &DnssecKey,
        config: &DnssecConfig,
    ) -> Result<()> {
        let mut args = vec![
            "-S".to_string(),  // Smart signing
            "-K".to_string(), "/var/cache/bind/keys".to_string(),  // Key directory
            "-o".to_string(), zone.to_string(),
        ];

        if config.nsec3 {
            args.push("-3".to_string());
            if let Some(salt) = &config.salt {
                args.push(salt.clone());
            } else {
                args.push("-".to_string());  // Random salt
            }
        }

        args.push(format!("/var/cache/bind/{}.zone", zone));

        let output = Command::new("dnssec-signzone")
            .args(&args)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to sign zone: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        Ok(())
    }

    // Validate zone data
    pub fn validate_zone_data(&self, zone_data: &str) -> Result<ZoneValidation> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut soa_serial = 0;
        let mut record_count = 0;

        // Write zone data to temporary file
        let temp_file = format!("/tmp/zone-{}.tmp", uuid::Uuid::new_v4());
        std::fs::write(&temp_file, zone_data)?;

        // Use named-checkzone for validation
        let output = Command::new("named-checkzone")
            .args(&["zone", &temp_file])
            .output()?;

        let valid = output.status.success();
        
        if !valid {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            for line in error_msg.lines() {
                if line.contains("error") {
                    errors.push(line.to_string());
                } else if line.contains("warning") {
                    warnings.push(line.to_string());
                }
            }
        }

        // Parse zone data for statistics
        for line in zone_data.lines() {
            if line.contains("SOA") {
                // Extract serial number
                if let Some(serial_str) = line.split_whitespace().nth(6) {
                    soa_serial = serial_str.parse().unwrap_or(0);
                }
            }
            if !line.starts_with(';') && !line.trim().is_empty() {
                record_count += 1;
            }
        }

        // Clean up temp file
        std::fs::remove_file(temp_file).ok();

        Ok(ZoneValidation {
            valid,
            errors,
            warnings,
            soa_serial,
            record_count,
        })
    }

    // Check DNSSEC validation chain
    pub async fn validate_dnssec_chain(&self, domain: &str) -> Result<bool> {
        let output = Command::new("delv")
            .args(&["+rtrace", "+multiline", domain])
            .output()?;

        if !output.status.success() {
            return Ok(false);
        }

        let result = String::from_utf8_lossy(&output.stdout);
        Ok(result.contains("fully validated"))
    }

    // Generate TSIG key for secure zone transfers
    pub fn generate_tsig_key(&self, name: &str) -> Result<TsigKey> {
        let output = Command::new("tsig-keygen")
            .args(&["-a", "hmac-sha256", name])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to generate TSIG key"));
        }

        let key_data = String::from_utf8_lossy(&output.stdout);
        
        // Parse the key output
        let mut secret = String::new();
        for line in key_data.lines() {
            if line.contains("secret") {
                if let Some(s) = line.split('"').nth(1) {
                    secret = s.to_string();
                    break;
                }
            }
        }

        Ok(TsigKey {
            name: name.to_string(),
            algorithm: "hmac-sha256".to_string(),
            secret,
        })
    }

    // Check zone consistency across multiple nameservers
    pub async fn check_zone_consistency(
        &self,
        zone: &str,
        nameservers: Vec<String>,
    ) -> Result<Vec<(String, u32)>> {
        let mut serials = Vec::new();

        for ns in nameservers {
            let output = Command::new("dig")
                .args(&["+short", "SOA", zone, &format!("@{}", ns)])
                .output()?;

            if output.status.success() {
                let soa = String::from_utf8_lossy(&output.stdout);
                if let Some(serial_str) = soa.split_whitespace().nth(2) {
                    if let Ok(serial) = serial_str.parse::<u32>() {
                        serials.push((ns, serial));
                    }
                }
            }
        }

        Ok(serials)
    }

    // Perform DNS query with DNSSEC validation
    pub async fn query_with_dnssec(
        &self,
        domain: &str,
        record_type: &str,
    ) -> Result<Vec<String>> {
        let output = Command::new("dig")
            .args(&["+dnssec", "+short", record_type, domain])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("DNS query failed"));
        }

        let results = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect();

        Ok(results)
    }

    fn extract_key_tag(&self, public_key: &str) -> Result<u16> {
        // Extract key tag from DNSKEY record
        for line in public_key.lines() {
            if line.contains("DNSKEY") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 4 {
                    // Calculate key tag from the key data
                    // This is a simplified version; real implementation would use RFC 4034 algorithm
                    return Ok(12345); // Placeholder
                }
            }
        }
        Err(anyhow!("Could not extract key tag"))
    }

    fn algorithm_to_number(&self, algo: &DnssecAlgorithm) -> u8 {
        match algo {
            DnssecAlgorithm::RsaSha256 => 8,
            DnssecAlgorithm::RsaSha512 => 10,
            DnssecAlgorithm::EcdsaP256Sha256 => 13,
            DnssecAlgorithm::EcdsaP384Sha384 => 14,
            DnssecAlgorithm::Ed25519 => 15,
        }
    }
}