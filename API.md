# GhostCP API Documentation

## Overview

The GhostCP API is a RESTful API built with Rust and Axum that provides programmatic access to all hosting control panel functionality. It follows modern API design principles with JSON request/response bodies, proper HTTP status codes, and consistent error handling.

**Base URL**: `http://localhost:8080/api/v1`  
**Authentication**: JWT Bearer tokens  
**Content Type**: `application/json`  

## Authentication

### JWT Token Authentication

All API endpoints (except health check) require authentication via JWT Bearer tokens.

```http
Authorization: Bearer <jwt_token>
```

### Login

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password",
  "two_factor_code": "123456" // optional
}
```

**Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_at": "2024-12-25T10:30:00Z",
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin"
  }
}
```

## Error Handling

The API uses standard HTTP status codes and returns error details in JSON format:

```json
{
  "error": "Resource not found",
  "status": 404,
  "details": {
    "resource": "user",
    "id": "nonexistent-id"
  }
}
```

**Common Status Codes:**
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `422` - Validation Error
- `500` - Internal Server Error

## API Endpoints

### Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "ghostcp-api",
  "version": "0.1.0"
}
```

## Users Management

### List Users

```http
GET /api/v1/users?page=1&limit=20&role=user&search=john
```

**Query Parameters:**
- `page` (optional): Page number, default 1
- `limit` (optional): Items per page, default 20, max 100
- `role` (optional): Filter by role (`admin`, `user`, `reseller`)
- `search` (optional): Search in username, email, or full name

**Response:**
```json
{
  "users": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "username": "john",
      "email": "john@example.com",
      "full_name": "John Doe",
      "role": "user",
      "package_name": "default",
      "disk_quota": 1024,
      "bandwidth_quota": 10240,
      "web_domains_limit": 5,
      "dns_domains_limit": 5,
      "mail_domains_limit": 3,
      "databases_limit": 5,
      "cron_jobs_limit": 10,
      "disk_used": 512,
      "bandwidth_used": 2048,
      "web_domains_count": 2,
      "dns_domains_count": 2,
      "mail_domains_count": 1,
      "databases_count": 3,
      "cron_jobs_count": 5,
      "is_active": true,
      "is_suspended": false,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 25,
  "page": 1,
  "limit": 20,
  "pages": 2
}
```

### Create User

```http
POST /api/v1/users
Content-Type: application/json

{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "securepassword123",
  "full_name": "New User",
  "package_name": "basic",
  "role": "user",
  "disk_quota": 2048,
  "bandwidth_quota": 20480,
  "web_domains_limit": 10,
  "dns_domains_limit": 10,
  "mail_domains_limit": 5,
  "databases_limit": 10,
  "cron_jobs_limit": 20,
  "shell": "/bin/bash",
  "language": "en",
  "timezone": "UTC"
}
```

**Response:** `201 Created` with user object

### Get User

```http
GET /api/v1/users/{user_id}
```

**Response:** User object (same structure as in list)

### Update User

```http
PUT /api/v1/users/{user_id}
Content-Type: application/json

{
  "email": "updated@example.com",
  "full_name": "Updated Name",
  "disk_quota": 4096,
  "is_suspended": false
}
```

**Response:** Updated user object

### Delete User

```http
DELETE /api/v1/users/{user_id}
```

**Response:** `204 No Content`

## Web Domains Management

### List Web Domains

```http
GET /api/v1/domains?user_id={user_id}&page=1&limit=20
```

**Response:**
```json
{
  "domains": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "user_id": "user-uuid",
      "domain": "example.com",
      "ip_address": "192.168.1.100",
      "ipv6_address": "2001:db8::1",
      "web_template": "default",
      "backend_template": "PHP-8.3",
      "proxy_template": null,
      "document_root": "/home/user/web/example.com/public_html",
      "ssl_enabled": true,
      "ssl_force": true,
      "ssl_hsts": true,
      "letsencrypt_enabled": true,
      "letsencrypt_wildcard": false,
      "aliases": ["www.example.com"],
      "bandwidth_used": 1024,
      "is_active": true,
      "is_suspended": false,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 5,
  "page": 1,
  "limit": 20,
  "pages": 1
}
```

### Create Web Domain

```http
POST /api/v1/domains
Content-Type: application/json

{
  "domain": "newsite.com",
  "ip_address": "192.168.1.100",
  "web_template": "default",
  "backend_template": "PHP-8.3",
  "aliases": ["www.newsite.com"],
  "ssl_enabled": true,
  "letsencrypt_enabled": true
}
```

## DNS Management

### List DNS Zones

```http
GET /api/v1/dns?user_id={user_id}
```

**Response:**
```json
{
  "zones": [
    {
      "id": "zone-uuid",
      "user_id": "user-uuid",
      "domain": "example.com",
      "primary_ns": "ns1.example.com",
      "admin_email": "admin@example.com",
      "serial": 2024010101,
      "refresh_interval": 3600,
      "retry_interval": 1800,
      "expire_interval": 1209600,
      "minimum_ttl": 86400,
      "dns_provider": "cloudflare",
      "provider_zone_id": "cf-zone-id",
      "dnssec_enabled": true,
      "template": "default",
      "is_active": true,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### Create DNS Zone

```http
POST /api/v1/dns
Content-Type: application/json

{
  "domain": "newdomain.com",
  "primary_ns": "ns1.ghostcp.com",
  "admin_email": "admin@newdomain.com",
  "dns_provider": "cloudflare",
  "dnssec_enabled": true,
  "template": "default"
}
```

### List DNS Records

```http
GET /api/v1/dns/{zone_id}/records
```

**Response:**
```json
{
  "records": [
    {
      "id": "record-uuid",
      "zone_id": "zone-uuid",
      "name": "@",
      "record_type": "A",
      "value": "192.168.1.100",
      "ttl": 3600,
      "priority": 0,
      "is_active": true,
      "created_at": "2024-01-01T00:00:00Z"
    },
    {
      "id": "record-uuid-2",
      "zone_id": "zone-uuid",
      "name": "www",
      "record_type": "CNAME",
      "value": "example.com",
      "ttl": 3600,
      "priority": 0,
      "is_active": true,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### Create DNS Record

```http
POST /api/v1/dns/{zone_id}/records
Content-Type: application/json

{
  "name": "mail",
  "record_type": "A",
  "value": "192.168.1.101",
  "ttl": 3600,
  "priority": 0
}
```

## Mail Management

### List Mail Domains

```http
GET /api/v1/mail?user_id={user_id}
```

**Response:**
```json
{
  "domains": [
    {
      "id": "mail-domain-uuid",
      "user_id": "user-uuid",
      "domain": "mail.example.com",
      "dkim_enabled": true,
      "dkim_selector": "default",
      "dkim_public_key": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3...",
      "antispam_enabled": true,
      "antivirus_enabled": false,
      "catchall_enabled": false,
      "rate_limit": 100,
      "ssl_enabled": true,
      "is_active": true,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### Create Mail Domain

```http
POST /api/v1/mail
Content-Type: application/json

{
  "domain": "mail.newdomain.com",
  "dkim_enabled": true,
  "antispam_enabled": true,
  "antivirus_enabled": false,
  "rate_limit": 50
}
```

### List Mail Accounts

```http
GET /api/v1/mail/{domain_id}/accounts
```

**Response:**
```json
{
  "accounts": [
    {
      "id": "account-uuid",
      "domain_id": "mail-domain-uuid",
      "username": "info",
      "email": "info@example.com",
      "quota_mb": 1024,
      "disk_used_mb": 256,
      "forward_to": [],
      "forward_only": false,
      "autoreply_enabled": false,
      "is_active": true,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### Create Mail Account

```http
POST /api/v1/mail/{domain_id}/accounts
Content-Type: application/json

{
  "username": "support",
  "password": "securepassword",
  "quota_mb": 2048,
  "forward_to": ["admin@example.com"],
  "forward_only": false
}
```

## Database Management

### List Databases

```http
GET /api/v1/databases?user_id={user_id}
```

**Response:**
```json
{
  "databases": [
    {
      "id": "db-uuid",
      "user_id": "user-uuid",
      "name": "webapp_db",
      "type": "postgresql",
      "host": "localhost",
      "port": 5432,
      "charset": "utf8mb4",
      "size_mb": 512,
      "is_active": true,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### Create Database

```http
POST /api/v1/databases
Content-Type: application/json

{
  "name": "new_app_db",
  "type": "postgresql",
  "charset": "utf8mb4"
}
```

## SSL Certificate Management

### List SSL Certificates

```http
GET /api/v1/ssl?user_id={user_id}
```

**Response:**
```json
{
  "certificates": [
    {
      "id": "cert-uuid",
      "user_id": "user-uuid",
      "domain": "example.com",
      "issuer": "Let's Encrypt",
      "subject": "CN=example.com",
      "san_domains": ["example.com", "www.example.com"],
      "valid_from": "2024-01-01T00:00:00Z",
      "valid_until": "2024-04-01T00:00:00Z",
      "acme_provider": "letsencrypt",
      "acme_challenge_type": "dns01",
      "auto_renew": true,
      "is_active": true,
      "is_wildcard": false,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### Request SSL Certificate

```http
POST /api/v1/ssl
Content-Type: application/json

{
  "domain": "newsite.com",
  "san_domains": ["newsite.com", "www.newsite.com"],
  "acme_provider": "letsencrypt",
  "acme_challenge_type": "dns01",
  "auto_renew": true,
  "is_wildcard": false
}
```

## System Jobs

### List System Jobs

```http
GET /api/v1/jobs?status=running&job_type=backup
```

**Query Parameters:**
- `status`: Filter by status (`pending`, `running`, `completed`, `failed`)
- `job_type`: Filter by job type (`backup`, `ssl_renew`, `dns_sync`, etc.)
- `user_id`: Filter by user

**Response:**
```json
{
  "jobs": [
    {
      "id": "job-uuid",
      "job_type": "backup",
      "user_id": "user-uuid",
      "status": "completed",
      "parameters": {
        "backup_type": "full",
        "destination": "s3://backups/user123/"
      },
      "started_at": "2024-01-01T02:00:00Z",
      "completed_at": "2024-01-01T02:15:00Z",
      "output_log": "Backup completed successfully...",
      "created_at": "2024-01-01T02:00:00Z"
    }
  ]
}
```

### Create System Job

```http
POST /api/v1/jobs
Content-Type: application/json

{
  "job_type": "backup",
  "user_id": "user-uuid",
  "parameters": {
    "backup_type": "incremental",
    "include_files": true,
    "include_databases": true
  },
  "priority": 1,
  "scheduled_for": "2024-01-01T03:00:00Z"
}
```

## Backup Management

### List Backup Configurations

```http
GET /api/v1/backups?user_id={user_id}
```

**Response:**
```json
{
  "configs": [
    {
      "id": "backup-config-uuid",
      "user_id": "user-uuid",
      "name": "Daily Full Backup",
      "include_files": true,
      "include_databases": true,
      "include_mail": true,
      "backend_type": "s3",
      "backend_config": {
        "bucket": "my-backups",
        "region": "us-east-1",
        "endpoint": "s3.amazonaws.com"
      },
      "schedule_cron": "0 2 * * *",
      "retention_policy": {
        "daily": 7,
        "weekly": 4,
        "monthly": 6,
        "yearly": 2
      },
      "is_active": true,
      "last_backup": "2024-01-01T02:00:00Z",
      "next_backup": "2024-01-02T02:00:00Z",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### Create Backup Configuration

```http
POST /api/v1/backups
Content-Type: application/json

{
  "name": "Website Backup",
  "include_files": true,
  "include_databases": false,
  "include_mail": false,
  "backend_type": "s3",
  "backend_config": {
    "bucket": "website-backups",
    "region": "us-west-2",
    "access_key": "AKIA...",
    "secret_key": "secret..."
  },
  "repository_password": "backup-encryption-key",
  "schedule_cron": "0 3 * * *",
  "retention_policy": {
    "daily": 14,
    "weekly": 8,
    "monthly": 12
  }
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Authentication endpoints**: 5 requests per minute
- **User management**: 60 requests per minute  
- **General API**: 1000 requests per minute
- **File operations**: 100 requests per minute

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## Pagination

List endpoints support pagination with these parameters:

- `page`: Page number (default: 1)
- `limit`: Items per page (default: 20, max: 100)

Pagination info is included in the response:
```json
{
  "data": [...],
  "total": 150,
  "page": 1,
  "limit": 20,
  "pages": 8
}
```

## Filtering and Sorting

Most list endpoints support filtering and sorting:

**Filtering:**
- Use query parameters matching field names
- Multiple values: `?status=active,pending`
- Date ranges: `?created_after=2024-01-01&created_before=2024-12-31`

**Sorting:**
- `sort`: Field name to sort by
- `order`: `asc` or `desc` (default: `asc`)
- Example: `?sort=created_at&order=desc`

## Webhooks

GhostCP supports webhooks for real-time notifications:

```http
POST /api/v1/webhooks
Content-Type: application/json

{
  "url": "https://your-app.com/webhook",
  "events": ["user.created", "domain.ssl.renewed", "backup.completed"],
  "secret": "webhook-secret-key"
}
```

**Webhook Events:**
- `user.created`, `user.updated`, `user.deleted`
- `domain.created`, `domain.updated`, `domain.deleted`
- `dns.zone.created`, `dns.record.updated`
- `mail.domain.created`, `mail.account.created`
- `ssl.certificate.issued`, `ssl.certificate.renewed`
- `backup.started`, `backup.completed`, `backup.failed`
- `job.started`, `job.completed`, `job.failed`

## SDK and Client Libraries

Official SDKs are planned for:
- **JavaScript/TypeScript** - npm package
- **Python** - PyPI package  
- **Go** - Go module
- **PHP** - Composer package

## OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:
```
GET /api/v1/openapi.json
```

Interactive documentation (Swagger UI):
```
GET /api/docs
```