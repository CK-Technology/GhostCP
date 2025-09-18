use ghostcp_api::models::*;
use uuid::Uuid;

#[test]
fn test_user_model_validation() {
    let user = User {
        id: Uuid::new_v4(),
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password_hash: "hashed_password".to_string(),
        full_name: Some("Test User".to_string()),
        role: "user".to_string(),
        package_name: "basic".to_string(),
        disk_quota: 1024,
        bandwidth_quota: 10240,
        web_domains_limit: 5,
        dns_domains_limit: 5,
        mail_domains_limit: 3,
        databases_limit: 5,
        cron_jobs_limit: 10,
        disk_used: 0,
        bandwidth_used: 0,
        web_domains_count: 0,
        dns_domains_count: 0,
        mail_domains_count: 0,
        databases_count: 0,
        cron_jobs_count: 0,
        is_active: true,
        is_suspended: false,
        shell: Some("/bin/bash".to_string()),
        language: Some("en".to_string()),
        timezone: Some("UTC".to_string()),
        two_factor_enabled: false,
        two_factor_secret: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, "test@example.com");
    assert_eq!(user.role, "user");
    assert!(user.is_active);
    assert!(!user.is_suspended);
}

#[test]
fn test_dns_record_validation() {
    let record = DnsRecord {
        id: Uuid::new_v4(),
        zone_id: Uuid::new_v4(),
        name: "www".to_string(),
        record_type: "A".to_string(),
        value: "192.168.1.100".to_string(),
        ttl: 3600,
        priority: 0,
        is_active: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    assert_eq!(record.name, "www");
    assert_eq!(record.record_type, "A");
    assert_eq!(record.value, "192.168.1.100");
    assert_eq!(record.ttl, 3600);
}