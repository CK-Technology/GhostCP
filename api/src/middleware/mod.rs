// Middleware modules
// pub mod auth;  // TODO: Implement auth middleware module
// pub mod rate_limit;  // TODO: Implement rate limiting

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use crate::handlers::auth::Claims;

pub async fn auth_middleware(
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|auth_header| auth_header.to_str().ok())
        .and_then(|auth_value| {
            if auth_value.starts_with("Bearer ") {
                Some(auth_value[7..].to_owned())
            } else {
                None
            }
        });

    let token = token.ok_or(StatusCode::UNAUTHORIZED)?;

    let claims = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(b"your-secret-key-change-in-production"),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?
    .claims;

    // Add claims to request extensions so handlers can access them
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}