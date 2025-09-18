use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::json;

use crate::common::TestContext;
use crate::test_with_context;

test_with_context!(test_health_endpoint, |ctx: &TestContext| async {
    let app = ghostcp_api::create_router(ctx.app_state.clone()).await;
    let server = TestServer::new(app).unwrap();

    let response = server.get("/health").await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["service"], "ghostcp-api");
});

test_with_context!(test_create_user, |ctx: &TestContext| async {
    let app = ghostcp_api::create_router(ctx.app_state.clone()).await;
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "securepassword123",
        "role": "user",
        "package_name": "basic"
    });

    let response = server
        .post("/api/v1/users")
        .json(&user_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);

    let body: serde_json::Value = response.json();
    assert_eq!(body["username"], "newuser");
    assert_eq!(body["email"], "newuser@example.com");
});

test_with_context!(test_dns_zone_crud, |ctx: &TestContext| async {
    let app = ghostcp_api::create_router(ctx.app_state.clone()).await;
    let server = TestServer::new(app).unwrap();

    // Create DNS zone
    let zone_data = json!({
        "domain": "example.com",
        "primary_ns": "ns1.ghostcp.com",
        "admin_email": "admin@example.com",
        "dns_provider": "local"
    });

    let response = server
        .post("/api/v1/dns")
        .json(&zone_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);

    let zone: serde_json::Value = response.json();
    let zone_id = zone["id"].as_str().unwrap();

    // List zones
    let response = server.get("/api/v1/dns").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Create DNS record
    let record_data = json!({
        "name": "www",
        "record_type": "A",
        "value": "192.168.1.100",
        "ttl": 3600
    });

    let response = server
        .post(&format!("/api/v1/dns/{}/records", zone_id))
        .json(&record_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
});