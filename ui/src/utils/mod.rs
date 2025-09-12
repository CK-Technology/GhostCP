// Utility functions
use chrono::{DateTime, Utc};

pub fn format_datetime(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

pub fn format_date(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d").to_string()
}

pub fn format_relative_time(dt: &DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(*dt);
    
    if duration.num_seconds() < 60 {
        "just now".to_string()
    } else if duration.num_minutes() < 60 {
        format!("{} minutes ago", duration.num_minutes())
    } else if duration.num_hours() < 24 {
        format!("{} hours ago", duration.num_hours())
    } else if duration.num_days() < 30 {
        format!("{} days ago", duration.num_days())
    } else {
        format_date(dt)
    }
}

pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: u64 = 1024;

    if bytes < THRESHOLD {
        return format!("{} B", bytes);
    }

    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD as f64;
        unit_index += 1;
    }

    format!("{:.1} {}", size, UNITS[unit_index])
}

pub fn validate_domain(domain: &str) -> bool {
    // Basic domain validation
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    
    // Check for valid characters and structure
    domain.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') &&
    !domain.starts_with('.') &&
    !domain.ends_with('.') &&
    !domain.starts_with('-') &&
    !domain.ends_with('-') &&
    domain.contains('.')
}

pub fn validate_email(email: &str) -> bool {
    // Basic email validation
    email.contains('@') && 
    email.len() > 3 &&
    email.len() < 255 &&
    !email.starts_with('@') &&
    !email.ends_with('@')
}

pub fn validate_username(username: &str) -> bool {
    // Username validation: 3-32 chars, alphanumeric + underscore
    username.len() >= 3 &&
    username.len() <= 32 &&
    username.chars().all(|c| c.is_alphanumeric() || c == '_') &&
    !username.starts_with('_') &&
    !username.ends_with('_')
}

pub fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => c,
            _ => '_',
        })
        .collect()
}

pub fn generate_random_password(length: usize) -> String {
    use web_sys::window;
    
    let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    let chars: Vec<char> = chars.chars().collect();
    
    (0..length)
        .map(|_| {
            let crypto = window().unwrap().crypto().unwrap();
            let mut buffer = [0u8; 1];
            crypto.get_random_values_with_u8_array(&mut buffer).unwrap();
            let index = (buffer[0] as usize) % chars.len();
            chars[index]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_domain() {
        assert!(validate_domain("example.com"));
        assert!(validate_domain("sub.example.com"));
        assert!(validate_domain("test-site.co.uk"));
        
        assert!(!validate_domain(""));
        assert!(!validate_domain("invalid"));
        assert!(!validate_domain(".example.com"));
        assert!(!validate_domain("example.com."));
        assert!(!validate_domain("-example.com"));
    }

    #[test]
    fn test_validate_email() {
        assert!(validate_email("user@example.com"));
        assert!(validate_email("test.user+tag@domain.co.uk"));
        
        assert!(!validate_email(""));
        assert!(!validate_email("invalid"));
        assert!(!validate_email("@example.com"));
        assert!(!validate_email("user@"));
    }

    #[test]
    fn test_validate_username() {
        assert!(validate_username("user123"));
        assert!(validate_username("test_user"));
        
        assert!(!validate_username(""));
        assert!(!validate_username("ab"));
        assert!(!validate_username("_invalid"));
        assert!(!validate_username("invalid_"));
        assert!(!validate_username("user-123"));
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
    }
}