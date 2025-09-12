// TOTP (Time-based One-Time Password) implementation for 2FA
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use base32;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use qrcode::{QrCode, render::svg};

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecret {
    pub user_id: Uuid,
    pub secret: String,
    pub backup_codes: Vec<String>,
    pub enabled: bool,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSetupData {
    pub secret: String,
    pub qr_code_svg: String,
    pub manual_entry_key: String,
    pub backup_codes: Vec<String>,
}

impl TotpManager {
    pub fn new() -> Self {
        Self
    }

    // Generate a new TOTP secret for a user
    pub fn generate_secret(&self, user_id: Uuid, username: &str, service_name: &str) -> Result<TotpSetupData> {
        // Generate 32-byte (160-bit) secret
        let secret_bytes: Vec<u8> = (0..20).map(|_| rand::random::<u8>()).collect();
        let secret = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret_bytes);
        
        // Generate backup codes (8 codes, 8 characters each)
        let backup_codes: Vec<String> = (0..8)
            .map(|_| {
                (0..8)
                    .map(|_| rand::random::<char>().to_ascii_uppercase())
                    .filter(|c| c.is_ascii_alphanumeric())
                    .take(8)
                    .collect()
            })
            .collect();

        // Create the TOTP URI for QR code
        let totp_uri = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}",
            service_name,
            username,
            secret,
            service_name
        );

        // Generate QR code
        let qr_code = QrCode::new(&totp_uri)?;
        let qr_code_svg = qr_code
            .render()
            .min_dimensions(200, 200)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build();

        // Format secret for manual entry (groups of 4)
        let manual_entry_key = secret
            .chars()
            .collect::<Vec<char>>()
            .chunks(4)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join(" ");

        Ok(TotpSetupData {
            secret,
            qr_code_svg,
            manual_entry_key,
            backup_codes,
        })
    }

    // Verify a TOTP code
    pub fn verify_totp(&self, secret: &str, code: &str, window: u32) -> Result<bool> {
        let code_num: u32 = code.parse().map_err(|_| anyhow!("Invalid TOTP code format"))?;
        
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let current_step = current_time / 30; // 30-second time step
        
        // Check current time step and surrounding windows
        for i in 0..=window {
            // Check current and previous steps
            if current_step >= i {
                let step = current_step - i;
                if self.generate_totp_code(secret, step)? == code_num {
                    return Ok(true);
                }
            }
            
            // Check future steps (in case of clock drift)
            if i > 0 {
                let step = current_step + i;
                if self.generate_totp_code(secret, step)? == code_num {
                    return Ok(true);
                }
            }
        }
        
        Ok(false)
    }

    // Generate TOTP code for a specific time step
    fn generate_totp_code(&self, secret: &str, time_step: u64) -> Result<u32> {
        let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret)
            .ok_or_else(|| anyhow!("Invalid secret"))?;
        
        let time_bytes = time_step.to_be_bytes();
        
        let mut mac = HmacSha1::new_from_slice(&secret_bytes)?;
        mac.update(&time_bytes);
        let result = mac.finalize().into_bytes();
        
        // Dynamic truncation
        let offset = (result[19] & 0x0f) as usize;
        let code = ((result[offset] as u32 & 0x7f) << 24)
            | ((result[offset + 1] as u32 & 0xff) << 16)
            | ((result[offset + 2] as u32 & 0xff) << 8)
            | (result[offset + 3] as u32 & 0xff);
        
        Ok(code % 1_000_000) // 6-digit code
    }

    // Verify backup code
    pub fn verify_backup_code(&self, backup_codes: &mut Vec<String>, code: &str) -> bool {
        if let Some(pos) = backup_codes.iter().position(|x| x == code) {
            backup_codes.remove(pos);
            return true;
        }
        false
    }

    // Generate new backup codes
    pub fn generate_backup_codes(&self) -> Vec<String> {
        (0..8)
            .map(|_| {
                let code: String = (0..8)
                    .map(|_| {
                        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                        chars[rand::random::<usize>() % chars.len()] as char
                    })
                    .collect();
                
                // Format as XXXX-XXXX
                format!("{}-{}", &code[0..4], &code[4..8])
            })
            .collect()
    }

    // Get current TOTP code (for testing)
    pub fn get_current_code(&self, secret: &str) -> Result<String> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let current_step = current_time / 30;
        let code = self.generate_totp_code(secret, current_step)?;
        
        Ok(format!("{:06}", code))
    }

    // Get time remaining until next code
    pub fn get_time_remaining(&self) -> u64 {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        30 - (current_time % 30)
    }

    // Validate secret format
    pub fn validate_secret(&self, secret: &str) -> bool {
        // Check if it's valid base32
        base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret).is_some()
    }

    // Generate QR code for existing secret
    pub fn generate_qr_code(&self, secret: &str, username: &str, service_name: &str) -> Result<String> {
        let totp_uri = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}",
            service_name,
            username,
            secret,
            service_name
        );

        let qr_code = QrCode::new(&totp_uri)?;
        let svg = qr_code
            .render()
            .min_dimensions(200, 200)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build();

        Ok(svg)
    }
}

// WebAuthn support (future enhancement)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnManager {
    rp_id: String,
    rp_name: String,
    origin: String,
}

impl WebAuthnManager {
    pub fn new(rp_id: String, rp_name: String, origin: String) -> Self {
        Self {
            rp_id,
            rp_name,
            origin,
        }
    }

    // Placeholder for WebAuthn implementation
    // This would use the `webauthn-rs` crate in a full implementation
    pub fn start_registration(&self, _user_id: Uuid, _username: &str) -> Result<String> {
        // Implementation would generate a registration challenge
        Ok("webauthn_challenge".to_string())
    }

    pub fn finish_registration(&self, _challenge: &str, _response: &str) -> Result<bool> {
        // Implementation would verify the registration response
        Ok(true)
    }

    pub fn start_authentication(&self, _user_id: Uuid) -> Result<String> {
        // Implementation would generate an authentication challenge
        Ok("webauthn_auth_challenge".to_string())
    }

    pub fn finish_authentication(&self, _challenge: &str, _response: &str) -> Result<bool> {
        // Implementation would verify the authentication response
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation() {
        let manager = TotpManager::new();
        let user_id = Uuid::new_v4();
        
        let setup = manager.generate_secret(user_id, "testuser", "GhostCP").unwrap();
        
        assert!(!setup.secret.is_empty());
        assert_eq!(setup.backup_codes.len(), 8);
        assert!(!setup.qr_code_svg.is_empty());
        assert!(!setup.manual_entry_key.is_empty());
    }

    #[test]
    fn test_totp_verification() {
        let manager = TotpManager::new();
        let secret = "JBSWY3DPEHPK3PXP"; // "Hello!" in base32
        
        // Generate current code
        let current_code = manager.get_current_code(secret).unwrap();
        
        // Verify it works
        assert!(manager.verify_totp(secret, &current_code, 1).unwrap());
        
        // Verify invalid code fails
        assert!(!manager.verify_totp(secret, "000000", 1).unwrap());
    }

    #[test]
    fn test_backup_codes() {
        let manager = TotpManager::new();
        let mut backup_codes = manager.generate_backup_codes();
        
        assert_eq!(backup_codes.len(), 8);
        
        let test_code = backup_codes[0].clone();
        assert!(manager.verify_backup_code(&mut backup_codes, &test_code));
        assert_eq!(backup_codes.len(), 7); // Code should be removed after use
        
        // Same code shouldn't work twice
        assert!(!manager.verify_backup_code(&mut backup_codes, &test_code));
    }
}