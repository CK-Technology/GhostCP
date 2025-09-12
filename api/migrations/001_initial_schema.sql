-- Initial GhostCP Database Schema
-- Based on HestiaCP data models but modernized for PostgreSQL

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table (core user management)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    
    -- Package and quotas (from HestiaCP user.conf)
    package_name VARCHAR(50) DEFAULT 'default',
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('admin', 'user', 'reseller')),
    
    -- Quotas and limits
    disk_quota BIGINT DEFAULT 0, -- MB, 0 = unlimited
    bandwidth_quota BIGINT DEFAULT 0, -- MB, 0 = unlimited
    web_domains_limit INTEGER DEFAULT 0, -- 0 = unlimited
    dns_domains_limit INTEGER DEFAULT 0,
    mail_domains_limit INTEGER DEFAULT 0,
    databases_limit INTEGER DEFAULT 0,
    cron_jobs_limit INTEGER DEFAULT 0,
    
    -- Usage counters
    disk_used BIGINT DEFAULT 0,
    bandwidth_used BIGINT DEFAULT 0,
    web_domains_count INTEGER DEFAULT 0,
    dns_domains_count INTEGER DEFAULT 0,
    mail_domains_count INTEGER DEFAULT 0,
    databases_count INTEGER DEFAULT 0,
    cron_jobs_count INTEGER DEFAULT 0,
    
    -- System settings
    shell VARCHAR(50) DEFAULT '/bin/bash',
    home_dir VARCHAR(255),
    language VARCHAR(10) DEFAULT 'en',
    timezone VARCHAR(50) DEFAULT 'UTC',
    
    -- Status and suspension
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,
    suspended_reason TEXT,
    suspended_web BOOLEAN DEFAULT FALSE,
    suspended_dns BOOLEAN DEFAULT FALSE,
    suspended_mail BOOLEAN DEFAULT FALSE,
    suspended_db BOOLEAN DEFAULT FALSE,
    suspended_cron BOOLEAN DEFAULT FALSE,
    
    -- Auth and security
    two_factor_secret VARCHAR(255),
    recovery_key VARCHAR(255),
    login_disabled BOOLEAN DEFAULT FALSE,
    allowed_ips TEXT[],
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    created_by UUID REFERENCES users(id)
);

-- Web domains table
CREATE TABLE web_domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    
    -- IP and networking
    ip_address INET,
    ipv6_address INET,
    
    -- Templates and configuration
    web_template VARCHAR(50) DEFAULT 'default',
    backend_template VARCHAR(50) DEFAULT 'default',
    proxy_template VARCHAR(50),
    proxy_extensions TEXT[],
    
    -- Document root and paths
    document_root VARCHAR(500),
    
    -- Features
    ssl_enabled BOOLEAN DEFAULT FALSE,
    ssl_cert_path VARCHAR(500),
    ssl_key_path VARCHAR(500),
    ssl_ca_path VARCHAR(500),
    ssl_force BOOLEAN DEFAULT FALSE,
    ssl_hsts BOOLEAN DEFAULT FALSE,
    letsencrypt_enabled BOOLEAN DEFAULT FALSE,
    letsencrypt_wildcard BOOLEAN DEFAULT FALSE,
    
    -- Aliases and redirects
    aliases TEXT[],
    redirects JSONB DEFAULT '[]',
    
    -- Stats and usage
    bandwidth_used BIGINT DEFAULT 0,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(user_id, domain)
);

-- DNS zones table
CREATE TABLE dns_zones (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    
    -- SOA fields
    primary_ns VARCHAR(255) NOT NULL,
    admin_email VARCHAR(255) NOT NULL,
    serial BIGINT DEFAULT 1,
    refresh_interval INTEGER DEFAULT 3600,
    retry_interval INTEGER DEFAULT 1800,
    expire_interval INTEGER DEFAULT 1209600,
    minimum_ttl INTEGER DEFAULT 86400,
    
    -- DNS provider and settings
    dns_provider VARCHAR(50) DEFAULT 'local', -- local, cloudflare, powerdns, route53
    provider_zone_id VARCHAR(255),
    dnssec_enabled BOOLEAN DEFAULT TRUE,
    
    -- Template and automation
    template VARCHAR(50) DEFAULT 'default',
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(user_id, domain)
);

-- DNS records table
CREATE TABLE dns_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    zone_id UUID NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
    
    -- Record data
    name VARCHAR(255) NOT NULL,
    type VARCHAR(10) NOT NULL CHECK (type IN ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'PTR')),
    value TEXT NOT NULL,
    ttl INTEGER DEFAULT 3600,
    priority INTEGER DEFAULT 0, -- for MX, SRV records
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Mail domains table
CREATE TABLE mail_domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    
    -- DKIM configuration
    dkim_enabled BOOLEAN DEFAULT TRUE,
    dkim_selector VARCHAR(50) DEFAULT 'default',
    dkim_private_key TEXT,
    dkim_public_key TEXT,
    
    -- Anti-spam and virus
    antispam_enabled BOOLEAN DEFAULT TRUE,
    antivirus_enabled BOOLEAN DEFAULT FALSE,
    
    -- Catchall and forwarding
    catchall_enabled BOOLEAN DEFAULT FALSE,
    catchall_destination VARCHAR(255),
    
    -- Rate limiting
    rate_limit INTEGER DEFAULT 100, -- emails per hour
    
    -- SSL/TLS
    ssl_enabled BOOLEAN DEFAULT TRUE,
    ssl_cert_path VARCHAR(500),
    ssl_key_path VARCHAR(500),
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(user_id, domain)
);

-- Mail accounts table
CREATE TABLE mail_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(320) GENERATED ALWAYS AS (username || '@' || (SELECT domain FROM mail_domains WHERE id = domain_id)) STORED,
    
    -- Authentication
    password_hash VARCHAR(255) NOT NULL,
    
    -- Quotas and limits
    quota_mb INTEGER DEFAULT 0, -- 0 = unlimited
    disk_used_mb INTEGER DEFAULT 0,
    
    -- Features
    forward_to TEXT[],
    forward_only BOOLEAN DEFAULT FALSE,
    autoreply_enabled BOOLEAN DEFAULT FALSE,
    autoreply_message TEXT,
    autoreply_subject VARCHAR(255),
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    
    UNIQUE(domain_id, username)
);

-- Databases table
CREATE TABLE databases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(64) NOT NULL,
    type VARCHAR(20) DEFAULT 'postgresql' CHECK (type IN ('postgresql', 'mysql', 'mariadb')),
    
    -- Connection details
    host VARCHAR(255) DEFAULT 'localhost',
    port INTEGER,
    charset VARCHAR(20) DEFAULT 'utf8mb4',
    
    -- Size and limits
    size_mb BIGINT DEFAULT 0,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(user_id, name, type)
);

-- Database users table
CREATE TABLE database_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    database_id UUID NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    username VARCHAR(64) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    
    -- Permissions
    permissions JSONB DEFAULT '["SELECT", "INSERT", "UPDATE", "DELETE"]',
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(database_id, username)
);

-- Cron jobs table
CREATE TABLE cron_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Cron configuration
    minute VARCHAR(20) DEFAULT '*',
    hour VARCHAR(20) DEFAULT '*',
    day VARCHAR(20) DEFAULT '*',
    month VARCHAR(20) DEFAULT '*',
    weekday VARCHAR(20) DEFAULT '*',
    
    -- Command and execution
    command TEXT NOT NULL,
    working_directory VARCHAR(500),
    
    -- Logging and notifications
    log_output BOOLEAN DEFAULT TRUE,
    email_output BOOLEAN DEFAULT FALSE,
    
    -- Status and metadata
    is_active BOOLEAN DEFAULT TRUE,
    last_run TIMESTAMP WITH TIME ZONE,
    next_run TIMESTAMP WITH TIME ZONE,
    run_count INTEGER DEFAULT 0,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- SSL certificates table
CREATE TABLE ssl_certificates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    
    -- Certificate data
    certificate_pem TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    certificate_chain_pem TEXT,
    
    -- Certificate metadata
    issuer VARCHAR(255),
    subject VARCHAR(255),
    san_domains TEXT[],
    valid_from TIMESTAMP WITH TIME ZONE,
    valid_until TIMESTAMP WITH TIME ZONE,
    
    -- ACME/Let's Encrypt
    acme_provider VARCHAR(50), -- letsencrypt, zerossl, buypass
    acme_challenge_type VARCHAR(10), -- http01, dns01
    acme_account_key_id VARCHAR(255),
    
    -- Auto-renewal
    auto_renew BOOLEAN DEFAULT TRUE,
    renew_days_before INTEGER DEFAULT 30,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_wildcard BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(user_id, domain)
);

-- System jobs/tasks queue
CREATE TABLE system_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_type VARCHAR(50) NOT NULL, -- backup, ssl_renew, dns_sync, etc.
    user_id UUID REFERENCES users(id),
    
    -- Job configuration
    parameters JSONB DEFAULT '{}',
    
    -- Execution tracking
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Output and logging
    output_log TEXT,
    error_log TEXT,
    
    -- Retry mechanism
    max_retries INTEGER DEFAULT 3,
    retry_count INTEGER DEFAULT 0,
    next_retry_at TIMESTAMP WITH TIME ZONE,
    
    -- Priority and scheduling
    priority INTEGER DEFAULT 0,
    scheduled_for TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Backup configurations
CREATE TABLE backup_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    
    -- Backup scope
    include_files BOOLEAN DEFAULT TRUE,
    include_databases BOOLEAN DEFAULT TRUE,
    include_mail BOOLEAN DEFAULT TRUE,
    
    -- Specific inclusions/exclusions
    included_paths TEXT[],
    excluded_paths TEXT[],
    included_databases UUID[],
    
    -- Storage backend (Restic-compatible)
    backend_type VARCHAR(20) NOT NULL CHECK (backend_type IN ('s3', 'sftp', 'local', 'b2', 'azure', 'gcs')),
    backend_config JSONB NOT NULL,
    repository_password VARCHAR(255) NOT NULL,
    
    -- Schedule
    schedule_cron VARCHAR(100), -- cron expression
    retention_policy JSONB DEFAULT '{"daily": 7, "weekly": 4, "monthly": 6, "yearly": 2}',
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_backup TIMESTAMP WITH TIME ZONE,
    next_backup TIMESTAMP WITH TIME ZONE,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(user_id, name)
);

-- Audit logs
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    
    -- Action details
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    
    -- Changes
    old_values JSONB,
    new_values JSONB,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_active ON users(is_active);

CREATE INDEX idx_web_domains_user ON web_domains(user_id);
CREATE INDEX idx_web_domains_domain ON web_domains(domain);
CREATE INDEX idx_web_domains_active ON web_domains(is_active);

CREATE INDEX idx_dns_zones_user ON dns_zones(user_id);
CREATE INDEX idx_dns_zones_domain ON dns_zones(domain);
CREATE INDEX idx_dns_records_zone ON dns_records(zone_id);
CREATE INDEX idx_dns_records_type ON dns_records(type);

CREATE INDEX idx_mail_domains_user ON mail_domains(user_id);
CREATE INDEX idx_mail_accounts_domain ON mail_accounts(domain_id);
CREATE INDEX idx_mail_accounts_email ON mail_accounts(email);

CREATE INDEX idx_databases_user ON databases(user_id);
CREATE INDEX idx_database_users_db ON database_users(database_id);

CREATE INDEX idx_cron_jobs_user ON cron_jobs(user_id);
CREATE INDEX idx_cron_jobs_active ON cron_jobs(is_active);
CREATE INDEX idx_cron_jobs_next_run ON cron_jobs(next_run);

CREATE INDEX idx_ssl_certs_user ON ssl_certificates(user_id);
CREATE INDEX idx_ssl_certs_domain ON ssl_certificates(domain);
CREATE INDEX idx_ssl_certs_expiry ON ssl_certificates(valid_until);

CREATE INDEX idx_system_jobs_status ON system_jobs(status);
CREATE INDEX idx_system_jobs_scheduled ON system_jobs(scheduled_for);
CREATE INDEX idx_system_jobs_type ON system_jobs(job_type);

CREATE INDEX idx_backup_configs_user ON backup_configs(user_id);
CREATE INDEX idx_backup_configs_next ON backup_configs(next_backup);

CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers to automatically update updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_web_domains_updated_at BEFORE UPDATE ON web_domains 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_dns_zones_updated_at BEFORE UPDATE ON dns_zones 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_dns_records_updated_at BEFORE UPDATE ON dns_records 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_mail_domains_updated_at BEFORE UPDATE ON mail_domains 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_mail_accounts_updated_at BEFORE UPDATE ON mail_accounts 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_databases_updated_at BEFORE UPDATE ON databases 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_database_users_updated_at BEFORE UPDATE ON database_users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_cron_jobs_updated_at BEFORE UPDATE ON cron_jobs 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_ssl_certificates_updated_at BEFORE UPDATE ON ssl_certificates 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_system_jobs_updated_at BEFORE UPDATE ON system_jobs 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_backup_configs_updated_at BEFORE UPDATE ON backup_configs 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();