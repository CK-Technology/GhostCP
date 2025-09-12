-- System metrics storage for historical monitoring
CREATE TABLE IF NOT EXISTS system_metrics (
    id BIGSERIAL PRIMARY KEY,
    cpu_usage FLOAT NOT NULL,
    memory_total BIGINT NOT NULL,
    memory_used BIGINT NOT NULL,
    memory_available BIGINT NOT NULL,
    disk_total BIGINT NOT NULL,
    disk_used BIGINT NOT NULL,
    disk_available BIGINT NOT NULL,
    network_rx_bytes BIGINT NOT NULL,
    network_tx_bytes BIGINT NOT NULL,
    load_average_1m FLOAT NOT NULL,
    load_average_5m FLOAT NOT NULL,
    load_average_15m FLOAT NOT NULL,
    uptime_seconds BIGINT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Service status tracking
CREATE TABLE IF NOT EXISTS service_statuses (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    memory_usage BIGINT,
    cpu_usage FLOAT,
    pid INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_system_metrics_timestamp ON system_metrics(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_service_statuses_name_timestamp ON service_statuses(name, timestamp DESC);

-- Cleanup old data automatically (keep last 30 days)
CREATE OR REPLACE FUNCTION cleanup_old_metrics()
RETURNS void AS $$
BEGIN
    DELETE FROM system_metrics WHERE timestamp < NOW() - INTERVAL '30 days';
    DELETE FROM service_statuses WHERE timestamp < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;

-- Schedule cleanup to run daily
-- Note: This would typically be handled by a background task or cron job