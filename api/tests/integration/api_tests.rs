use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::json;

use crate::test_with_context;

test_with_context!(test_health_endpoint, ctx, {
    let app = ghostcp_api::create_router(ctx.app_state.clone()).await;
    let server = TestServer::new(app).unwrap();

    let response = server.get("/health").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["service"], "ghostcp-api");
});

test_with_context!(test_protected_route_requires_auth, ctx, {
    let app = ghostcp_api::create_router(ctx.app_state.clone()).await;
    let server = TestServer::new(app).unwrap();

    // Listing users is behind the auth middleware; without a token it must be rejected.
    let response = server.get("/api/v1/users").await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
});

test_with_context!(test_create_user_requires_auth, ctx, {
    let app = ghostcp_api::create_router(ctx.app_state.clone()).await;
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "securepassword123",
        "role": "user",
        "package_name": "default"
    });

    let response = server.post("/api/v1/users").json(&user_data).await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
});
