use axum::{
    extract::{State, Query},
    http::StatusCode,
    response::IntoResponse,
    Json,
    Extension,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::AppState;
use crate::handlers::auth::Claims;
use crate::system::monitoring::{SystemMonitor, SystemMetrics, ServiceStatus};

#[derive(Debug, Serialize, Deserialize)]
pub struct MonitoringQuery {
    pub since: Option<i64>, // Unix timestamp
    pub service: Option<String>,
    pub metric_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub current_metrics: SystemMetrics,
    pub historical_metrics: Vec<SystemMetrics>,
    pub services: Vec<ServiceStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceResponse {
    pub name: String,
    pub status: ServiceStatus,
    pub history: Vec<ServiceStatus>,
}

// Get current system metrics
pub async fn get_current_metrics(
    State(_state): State<AppState>,
    Extension(_claims): Extension<Claims>,
) -> Result<impl IntoResponse, StatusCode> {
    let monitor = SystemMonitor::new();
    
    match monitor.collect_metrics().await {
        Ok(metrics) => Ok(Json(metrics)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// Get historical metrics
pub async fn get_metrics_history(
    State(state): State<AppState>,
    Extension(_claims): Extension<Claims>,
    Query(params): Query<MonitoringQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let monitor = SystemMonitor::new();
    let current_metrics = monitor.collect_metrics().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Get historical metrics from database
    let since_time = params.since.unwrap_or_else(|| {
        chrono::Utc::now().timestamp() - 3600 // Default: last hour
    });
    
    let historical_metrics = sqlx::query_as!(
        SystemMetrics,
        r#"
        SELECT 
            cpu_usage,
            memory_total,
            memory_used,
            memory_available,
            disk_total,
            disk_used,
            disk_available,
            network_rx_bytes,
            network_tx_bytes,
            load_average_1m,
            load_average_5m,
            load_average_15m,
            uptime_seconds,
            timestamp
        FROM system_metrics 
        WHERE timestamp >= $1 
        ORDER BY timestamp ASC
        "#,
        chrono::DateTime::from_timestamp(since_time, 0).unwrap_or_default()
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    
    // Get service statuses
    let services = monitor.get_service_statuses(&[
        "nginx", "postgresql", "redis", "fail2ban", "vsftpd"
    ]).await.unwrap_or_default();
    
    let response = MetricsResponse {
        current_metrics,
        historical_metrics,
        services,
    };
    
    Ok(Json(response))
}

// Get service status
pub async fn get_service_status(
    State(state): State<AppState>,
    Extension(_claims): Extension<Claims>,
    Query(params): Query<MonitoringQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let service_name = params.service.ok_or(StatusCode::BAD_REQUEST)?;
    let monitor = SystemMonitor::new();
    
    let current_status = monitor.get_service_statuses(&[&service_name]).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .next()
        .ok_or(StatusCode::NOT_FOUND)?;
    
    // Get service history from database
    let since_time = params.since.unwrap_or_else(|| {
        chrono::Utc::now().timestamp() - 3600
    });
    
    let history = sqlx::query!(
        r#"
        SELECT name, status, memory_usage, cpu_usage, pid, timestamp
        FROM service_statuses 
        WHERE name = $1 AND timestamp >= $2 
        ORDER BY timestamp ASC
        "#,
        service_name,
        chrono::DateTime::from_timestamp(since_time, 0).unwrap_or_default()
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|row| ServiceStatus {
        name: row.name,
        status: row.status,
        memory_usage: row.memory_usage.map(|m| m as u64),
        cpu_usage: row.cpu_usage,
        pid: row.pid.map(|p| p as u32),
        timestamp: row.timestamp,
    })
    .collect();
    
    let response = ServiceResponse {
        name: service_name.clone(),
        status: current_status,
        history,
    };
    
    Ok(Json(response))
}

// Get system processes
pub async fn get_processes(
    State(_state): State<AppState>,
    Extension(_claims): Extension<Claims>,
) -> Result<impl IntoResponse, StatusCode> {
    let monitor = SystemMonitor::new();
    
    match monitor.get_process_list().await {
        Ok(processes) => Ok(Json(processes)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// Get disk usage breakdown
pub async fn get_disk_usage(
    State(_state): State<AppState>,
    Extension(_claims): Extension<Claims>,
) -> Result<impl IntoResponse, StatusCode> {
    let monitor = SystemMonitor::new();
    
    match monitor.get_disk_usage().await {
        Ok(usage) => Ok(Json(usage)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// Get network statistics
pub async fn get_network_stats(
    State(_state): State<AppState>,
    Extension(_claims): Extension<Claims>,
) -> Result<impl IntoResponse, StatusCode> {
    let monitor = SystemMonitor::new();
    
    match monitor.get_network_stats().await {
        Ok(stats) => Ok(Json(stats)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// Prometheus metrics endpoint (text format)
pub async fn prometheus_metrics(
    State(_state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let monitor = SystemMonitor::new();
    
    let metrics = monitor.collect_metrics().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let prometheus_format = format!(
        r#"# HELP ghostcp_cpu_usage CPU usage percentage
# TYPE ghostcp_cpu_usage gauge
ghostcp_cpu_usage {{}} {}

# HELP ghostcp_memory_usage Memory usage in bytes
# TYPE ghostcp_memory_usage gauge
ghostcp_memory_usage {{type="used"}} {}
ghostcp_memory_usage {{type="total"}} {}
ghostcp_memory_usage {{type="available"}} {}

# HELP ghostcp_disk_usage Disk usage in bytes
# TYPE ghostcp_disk_usage gauge
ghostcp_disk_usage {{type="used"}} {}
ghostcp_disk_usage {{type="total"}} {}
ghostcp_disk_usage {{type="available"}} {}

# HELP ghostcp_network_bytes Network traffic in bytes
# TYPE ghostcp_network_bytes counter
ghostcp_network_bytes {{direction="rx"}} {}
ghostcp_network_bytes {{direction="tx"}} {}

# HELP ghostcp_load_average System load average
# TYPE ghostcp_load_average gauge
ghostcp_load_average {{period="1m"}} {}
ghostcp_load_average {{period="5m"}} {}
ghostcp_load_average {{period="15m"}} {}

# HELP ghostcp_uptime_seconds System uptime in seconds
# TYPE ghostcp_uptime_seconds counter
ghostcp_uptime_seconds {}
"#,
        metrics.cpu_usage,
        metrics.memory_used,
        metrics.memory_total,
        metrics.memory_available,
        metrics.disk_used,
        metrics.disk_total,
        metrics.disk_available,
        metrics.network_rx_bytes,
        metrics.network_tx_bytes,
        metrics.load_average_1m,
        metrics.load_average_5m,
        metrics.load_average_15m,
        metrics.uptime_seconds,
    );
    
    Ok((
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4")],
        prometheus_format
    ))
}

// Start metrics collection background task
pub async fn start_metrics_collection(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse, StatusCode> {
    // Only allow admins to start/stop metrics collection
    if claims.role != "Admin" {
        return Err(StatusCode::FORBIDDEN);
    }
    
    let db = state.db.clone();
    let monitor = SystemMonitor::new();
    
    // Spawn background task
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            // Collect and store metrics
            if let Ok(metrics) = monitor.collect_metrics().await {
                let _ = sqlx::query!(
                    r#"
                    INSERT INTO system_metrics (
                        cpu_usage, memory_total, memory_used, memory_available,
                        disk_total, disk_used, disk_available,
                        network_rx_bytes, network_tx_bytes,
                        load_average_1m, load_average_5m, load_average_15m,
                        uptime_seconds, timestamp
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                    "#,
                    metrics.cpu_usage,
                    metrics.memory_total as i64,
                    metrics.memory_used as i64,
                    metrics.memory_available as i64,
                    metrics.disk_total as i64,
                    metrics.disk_used as i64,
                    metrics.disk_available as i64,
                    metrics.network_rx_bytes as i64,
                    metrics.network_tx_bytes as i64,
                    metrics.load_average_1m,
                    metrics.load_average_5m,
                    metrics.load_average_15m,
                    metrics.uptime_seconds as i64,
                    metrics.timestamp
                ).execute(&db).await;
            }
            
            // Collect service statuses
            if let Ok(services) = monitor.get_service_statuses(&[
                "nginx", "postgresql", "redis", "fail2ban", "vsftpd"
            ]).await {
                for service in services {
                    let _ = sqlx::query!(
                        r#"
                        INSERT INTO service_statuses (
                            name, status, memory_usage, cpu_usage, pid, timestamp
                        ) VALUES ($1, $2, $3, $4, $5, $6)
                        "#,
                        service.name,
                        service.status,
                        service.memory_usage.map(|m| m as i64),
                        service.cpu_usage,
                        service.pid.map(|p| p as i32),
                        service.timestamp
                    ).execute(&db).await;
                }
            }
        }
    });
    
    Ok(Json(serde_json::json!({
        "message": "Metrics collection started",
        "interval": "60 seconds"
    })))
}