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
        package_name: "default".to_string(),
        role: UserRole::User,
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
        shell: "/bin/bash".to_string(),
        home_dir: Some("/home/testuser".to_string()),
        language: "en".to_string(),
        timezone: "UTC".to_string(),
        is_active: true,
        is_suspended: false,
        suspended_reason: None,
        suspended_web: false,
        suspended_dns: false,
        suspended_mail: false,
        suspended_db: false,
        suspended_cron: false,
        two_factor_secret: None,
        recovery_key: None,
        login_disabled: false,
        allowed_ips: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_login: None,
        created_by: None,
    };

    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, "test@example.com");
    assert!(matches!(user.role, UserRole::User));
    assert!(user.is_active);
    assert!(!user.is_suspended);

    // Quota/limit helpers should reflect an unsuspended user within limits.
    assert!(user.can_create_web_domain());
    assert!(user.can_create_dns_zone());
    assert!(user.is_within_disk_quota(512));
    assert!(!user.has_admin_access());
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
