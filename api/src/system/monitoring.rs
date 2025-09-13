// Resource monitoring system with system metrics
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::fs;
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringManager {
    pub collect_interval: u64, // seconds
    pub retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub timestamp: DateTime<Utc>,
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub disk: Vec<DiskMetrics>,
    pub network: Vec<NetworkMetrics>,
    pub load_average: LoadAverage,
    pub uptime: u64,
    pub processes: ProcessMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuMetrics {
    pub usage_percent: f64,
    pub cores: u32,
    pub frequency_mhz: u32,
    pub temperature_celsius: Option<f64>,
    pub per_core_usage: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMetrics {
    pub total_mb: u64,
    pub used_mb: u64,
    pub free_mb: u64,
    pub available_mb: u64,
    pub cached_mb: u64,
    pub buffers_mb: u64,
    pub swap_total_mb: u64,
    pub swap_used_mb: u64,
    pub usage_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskMetrics {
    pub device: String,
    pub mount_point: String,
    pub filesystem: String,
    pub total_gb: u64,
    pub used_gb: u64,
    pub available_gb: u64,
    pub usage_percent: f64,
    pub inodes_total: u64,
    pub inodes_used: u64,
    pub read_bytes_per_sec: u64,
    pub write_bytes_per_sec: u64,
    pub io_util_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub interface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadAverage {
    pub one_minute: f64,
    pub five_minutes: f64,
    pub fifteen_minutes: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMetrics {
    pub total_processes: u32,
    pub running_processes: u32,
    pub sleeping_processes: u32,
    pub zombie_processes: u32,
    pub top_cpu_processes: Vec<ProcessInfo>,
    pub top_memory_processes: Vec<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f64,
    pub memory_mb: u64,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub status: String,
    pub active: bool,
    pub enabled: bool,
    pub memory_usage_mb: Option<u64>,
    pub cpu_usage_percent: Option<f64>,
    // Additional fields for handler compatibility
    pub memory_usage: Option<u64>,
    pub cpu_usage: Option<f64>,
    pub pid: Option<u32>,
    pub timestamp: DateTime<Utc>,
}

// Alias for backwards compatibility
pub type SystemMonitor = MonitoringManager;

// Flatter SystemMetrics for compatibility with handlers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlatSystemMetrics {
    pub cpu_usage: f64,
    pub memory_total: u64,
    pub memory_used: u64,
    pub memory_available: u64,
    pub disk_total: u64,
    pub disk_used: u64,
    pub disk_available: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub load_average_1m: f64,
    pub load_average_5m: f64,
    pub load_average_15m: f64,
    pub uptime_seconds: u64,
    pub timestamp: DateTime<Utc>,
}

impl From<SystemMetrics> for FlatSystemMetrics {
    fn from(metrics: SystemMetrics) -> Self {
        FlatSystemMetrics {
            cpu_usage: metrics.cpu.usage_percent,
            memory_total: metrics.memory.total_mb * 1024 * 1024, // Convert to bytes
            memory_used: metrics.memory.used_mb * 1024 * 1024,
            memory_available: metrics.memory.available_mb * 1024 * 1024,
            disk_total: metrics.disk.first().map(|d| d.total_gb * 1024 * 1024 * 1024).unwrap_or(0),
            disk_used: metrics.disk.first().map(|d| d.used_gb * 1024 * 1024 * 1024).unwrap_or(0),
            disk_available: metrics.disk.first().map(|d| d.available_gb * 1024 * 1024 * 1024).unwrap_or(0),
            network_rx_bytes: metrics.network.first().map(|n| n.rx_bytes).unwrap_or(0),
            network_tx_bytes: metrics.network.first().map(|n| n.tx_bytes).unwrap_or(0),
            load_average_1m: metrics.load_average.one_minute,
            load_average_5m: metrics.load_average.five_minutes,
            load_average_15m: metrics.load_average.fifteen_minutes,
            uptime_seconds: metrics.uptime,
            timestamp: metrics.timestamp,
        }
    }
}

impl MonitoringManager {
    pub fn new() -> Self {
        Self {
            collect_interval: 60, // 1 minute
            retention_days: 30,
        }
    }

    // Collect comprehensive system metrics
    pub async fn collect_metrics(&self) -> Result<SystemMetrics> {
        let timestamp = Utc::now();
        
        // Collect all metrics in parallel for better performance
        let (cpu, memory, disk, network, load_average, uptime, processes) = tokio::join!(
            self.collect_cpu_metrics(),
            self.collect_memory_metrics(),
            self.collect_disk_metrics(),
            self.collect_network_metrics(),
            self.collect_load_average(),
            self.collect_uptime(),
            self.collect_process_metrics()
        );

        Ok(SystemMetrics {
            timestamp,
            cpu: cpu?,
            memory: memory?,
            disk: disk?,
            network: network?,
            load_average: load_average?,
            uptime: uptime?,
            processes: processes?,
        })
    }

    // CPU metrics collection
    async fn collect_cpu_metrics(&self) -> Result<CpuMetrics> {
        // Read /proc/stat for CPU usage
        let stat_content = fs::read_to_string("/proc/stat")?;
        let cpu_line = stat_content.lines().next().ok_or_else(|| anyhow!("No CPU info found"))?;
        
        let values: Vec<u64> = cpu_line
            .split_whitespace()
            .skip(1)
            .take(7)
            .map(|s| s.parse().unwrap_or(0))
            .collect();

        let total = values.iter().sum::<u64>();
        let idle = values[3];
        let usage_percent = if total > 0 {
            100.0 - (idle as f64 / total as f64 * 100.0)
        } else {
            0.0
        };

        // Get CPU info
        let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let cores = cpuinfo.matches("processor").count() as u32;
        
        // Extract frequency from first processor
        let frequency_mhz = cpuinfo
            .lines()
            .find(|line| line.starts_with("cpu MHz"))
            .and_then(|line| line.split(':').nth(1))
            .and_then(|freq| freq.trim().parse::<f32>().ok())
            .map(|f| f as u32)
            .unwrap_or(0);

        // Try to get temperature
        let temperature_celsius = self.get_cpu_temperature().await.ok();

        // Per-core usage (simplified - would need more complex calculation)
        let per_core_usage = vec![usage_percent; cores as usize];

        Ok(CpuMetrics {
            usage_percent,
            cores,
            frequency_mhz,
            temperature_celsius,
            per_core_usage,
        })
    }

    async fn get_cpu_temperature(&self) -> Result<f64> {
        // Try different temperature sources
        let temp_paths = [
            "/sys/class/thermal/thermal_zone0/temp",
            "/sys/devices/platform/coretemp.0/hwmon/hwmon*/temp1_input",
        ];

        for path in &temp_paths {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(temp_millidegree) = content.trim().parse::<f64>() {
                    return Ok(temp_millidegree / 1000.0);
                }
            }
        }

        Err(anyhow!("Temperature not available"))
    }

    // Memory metrics collection
    async fn collect_memory_metrics(&self) -> Result<MemoryMetrics> {
        let meminfo = fs::read_to_string("/proc/meminfo")?;
        let mut values = HashMap::new();

        for line in meminfo.lines() {
            if let Some((key, value)) = line.split_once(':') {
                let kb_value = value
                    .trim()
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                values.insert(key.trim(), kb_value);
            }
        }

        let total_kb = values.get("MemTotal").copied().unwrap_or(0);
        let free_kb = values.get("MemFree").copied().unwrap_or(0);
        let available_kb = values.get("MemAvailable").copied().unwrap_or(free_kb);
        let cached_kb = values.get("Cached").copied().unwrap_or(0);
        let buffers_kb = values.get("Buffers").copied().unwrap_or(0);
        let swap_total_kb = values.get("SwapTotal").copied().unwrap_or(0);
        let swap_free_kb = values.get("SwapFree").copied().unwrap_or(0);

        let used_kb = total_kb - available_kb;
        let swap_used_kb = swap_total_kb - swap_free_kb;
        
        let usage_percent = if total_kb > 0 {
            (used_kb as f64 / total_kb as f64) * 100.0
        } else {
            0.0
        };

        Ok(MemoryMetrics {
            total_mb: total_kb / 1024,
            used_mb: used_kb / 1024,
            free_mb: free_kb / 1024,
            available_mb: available_kb / 1024,
            cached_mb: cached_kb / 1024,
            buffers_mb: buffers_kb / 1024,
            swap_total_mb: swap_total_kb / 1024,
            swap_used_mb: swap_used_kb / 1024,
            usage_percent,
        })
    }

    // Disk metrics collection
    async fn collect_disk_metrics(&self) -> Result<Vec<DiskMetrics>> {
        let output = Command::new("df")
            .args(&["-h", "-T", "--exclude-type=tmpfs", "--exclude-type=devtmpfs"])
            .output()?;

        let df_output = String::from_utf8_lossy(&output.stdout);
        let mut disk_metrics = Vec::new();

        for line in df_output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 7 {
                let device = parts[0].to_string();
                let filesystem = parts[1].to_string();
                let mount_point = parts[6].to_string();
                
                // Parse sizes (remove suffix and convert)
                let total_gb = self.parse_size_to_gb(parts[2])?;
                let used_gb = self.parse_size_to_gb(parts[3])?;
                let available_gb = self.parse_size_to_gb(parts[4])?;
                
                let usage_percent = parts[5]
                    .trim_end_matches('%')
                    .parse::<f64>()
                    .unwrap_or(0.0);

                // Get inode information
                let (inodes_total, inodes_used) = self.get_inode_info(&mount_point).await.unwrap_or((0, 0));

                // Get I/O statistics (simplified)
                let (read_bytes_per_sec, write_bytes_per_sec, io_util_percent) = 
                    self.get_io_stats(&device).await.unwrap_or((0, 0, 0.0));

                disk_metrics.push(DiskMetrics {
                    device,
                    mount_point,
                    filesystem,
                    total_gb,
                    used_gb,
                    available_gb,
                    usage_percent,
                    inodes_total,
                    inodes_used,
                    read_bytes_per_sec,
                    write_bytes_per_sec,
                    io_util_percent,
                });
            }
        }

        Ok(disk_metrics)
    }

    fn parse_size_to_gb(&self, size_str: &str) -> Result<u64> {
        let size_str = size_str.trim();
        if size_str.is_empty() || size_str == "-" {
            return Ok(0);
        }

        let (number, suffix) = if let Some(last_char) = size_str.chars().last() {
            if last_char.is_alphabetic() {
                (&size_str[..size_str.len()-1], last_char.to_uppercase().to_string())
            } else {
                (size_str, "B".to_string())
            }
        } else {
            return Ok(0);
        };

        let number: f64 = number.parse()?;
        
        let gb = match suffix.as_str() {
            "K" => number / 1_048_576.0, // KB to GB
            "M" => number / 1024.0,      // MB to GB
            "G" => number,               // GB
            "T" => number * 1024.0,      // TB to GB
            _ => number / 1_073_741_824.0, // Bytes to GB
        };

        Ok(gb as u64)
    }

    async fn get_inode_info(&self, mount_point: &str) -> Result<(u64, u64)> {
        let output = Command::new("df")
            .args(&["-i", mount_point])
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = output_str.lines().nth(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let total = parts[1].parse().unwrap_or(0);
                let used = parts[2].parse().unwrap_or(0);
                return Ok((total, used));
            }
        }

        Ok((0, 0))
    }

    async fn get_io_stats(&self, device: &str) -> Result<(u64, u64, f64)> {
        // Read /proc/diskstats for I/O statistics
        let diskstats = fs::read_to_string("/proc/diskstats").unwrap_or_default();
        
        let device_name = device.split('/').last().unwrap_or(device);
        
        for line in diskstats.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 14 && parts[2] == device_name {
                let read_bytes = parts[5].parse::<u64>().unwrap_or(0) * 512; // sectors to bytes
                let write_bytes = parts[9].parse::<u64>().unwrap_or(0) * 512;
                let io_time = parts[12].parse::<u64>().unwrap_or(0);
                
                // These would need to be calculated as rates over time
                let read_bytes_per_sec = 0; // Simplified
                let write_bytes_per_sec = 0; // Simplified
                let io_util_percent = (io_time as f64 / 1000.0).min(100.0); // Simplified
                
                return Ok((read_bytes_per_sec, write_bytes_per_sec, io_util_percent));
            }
        }

        Ok((0, 0, 0.0))
    }

    // Network metrics collection
    async fn collect_network_metrics(&self) -> Result<Vec<NetworkMetrics>> {
        let net_dev = fs::read_to_string("/proc/net/dev")?;
        let mut network_metrics = Vec::new();

        for line in net_dev.lines().skip(2) {
            if let Some((interface, stats)) = line.split_once(':') {
                let interface = interface.trim().to_string();
                
                // Skip loopback and virtual interfaces
                if interface == "lo" || interface.starts_with("veth") {
                    continue;
                }
                
                let values: Vec<u64> = stats
                    .split_whitespace()
                    .take(16)
                    .map(|s| s.parse().unwrap_or(0))
                    .collect();

                if values.len() >= 16 {
                    network_metrics.push(NetworkMetrics {
                        interface,
                        rx_bytes: values[0],
                        rx_packets: values[1],
                        rx_errors: values[2],
                        tx_bytes: values[8],
                        tx_packets: values[9],
                        tx_errors: values[10],
                        rx_bytes_per_sec: 0, // Would calculate as rate
                        tx_bytes_per_sec: 0, // Would calculate as rate
                    });
                }
            }
        }

        Ok(network_metrics)
    }

    // Load average collection
    async fn collect_load_average(&self) -> Result<LoadAverage> {
        let loadavg = fs::read_to_string("/proc/loadavg")?;
        let values: Vec<f64> = loadavg
            .split_whitespace()
            .take(3)
            .map(|s| s.parse().unwrap_or(0.0))
            .collect();

        Ok(LoadAverage {
            one_minute: values.get(0).copied().unwrap_or(0.0),
            five_minutes: values.get(1).copied().unwrap_or(0.0),
            fifteen_minutes: values.get(2).copied().unwrap_or(0.0),
        })
    }

    // System uptime
    async fn collect_uptime(&self) -> Result<u64> {
        let uptime = fs::read_to_string("/proc/uptime")?;
        let uptime_seconds = uptime
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow!("Invalid uptime format"))?
            .parse::<f64>()?;

        Ok(uptime_seconds as u64)
    }

    // Process metrics collection
    async fn collect_process_metrics(&self) -> Result<ProcessMetrics> {
        let output = Command::new("ps")
            .args(&["aux", "--sort=-pcpu"])
            .output()?;

        let ps_output = String::from_utf8_lossy(&output.stdout);
        let mut processes = Vec::new();
        let mut total_processes = 0;
        let mut running_processes = 0;
        let mut sleeping_processes = 0;
        let mut zombie_processes = 0;

        for line in ps_output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 11 {
                total_processes += 1;
                
                let status = parts.get(7).unwrap_or(&"");
                match status.chars().next().unwrap_or(' ') {
                    'R' => running_processes += 1,
                    'S' | 'I' => sleeping_processes += 1,
                    'Z' => zombie_processes += 1,
                    _ => {}
                }

                if processes.len() < 10 {
                    let pid = parts[1].parse().unwrap_or(0);
                    let user = parts[0].to_string();
                    let cpu_percent = parts[2].parse().unwrap_or(0.0);
                    let memory_mb = parts[5].parse::<u64>().unwrap_or(0) / 1024; // KB to MB
                    let name = parts[10..].join(" ");

                    processes.push(ProcessInfo {
                        pid,
                        name,
                        cpu_percent,
                        memory_mb,
                        user,
                    });
                }
            }
        }

        // Sort by memory usage for top memory processes
        let mut memory_processes = processes.clone();
        memory_processes.sort_by(|a, b| b.memory_mb.cmp(&a.memory_mb));

        Ok(ProcessMetrics {
            total_processes,
            running_processes,
            sleeping_processes,
            zombie_processes,
            top_cpu_processes: processes,
            top_memory_processes: memory_processes,
        })
    }

    // Get service statuses
    pub async fn get_service_status(&self, services: &[&str]) -> Result<Vec<ServiceStatus>> {
        let mut statuses = Vec::new();

        for service in services {
            let output = Command::new("systemctl")
                .args(&["status", service, "--no-pager", "-l"])
                .output()?;

            let status_output = String::from_utf8_lossy(&output.stdout);
            let active = status_output.contains("Active: active");
            let enabled = self.is_service_enabled(service).await?;
            
            // Extract memory usage if available
            let memory_usage_mb = self.get_service_memory_usage(service).await.ok();
            let cpu_usage_percent = self.get_service_cpu_usage(service).await.ok();

            statuses.push(ServiceStatus {
                name: service.to_string(),
                status: if active { "active".to_string() } else { "inactive".to_string() },
                active,
                enabled,
                memory_usage_mb,
                cpu_usage_percent,
                // Additional fields for compatibility
                memory_usage: memory_usage_mb,
                cpu_usage: cpu_usage_percent,
                pid: None, // TODO: Get actual PID from systemctl
                timestamp: Utc::now(),
            });
        }

        Ok(statuses)
    }

    async fn is_service_enabled(&self, service: &str) -> Result<bool> {
        let output = Command::new("systemctl")
            .args(&["is-enabled", service])
            .output()?;

        Ok(output.status.success())
    }

    async fn get_service_memory_usage(&self, service: &str) -> Result<u64> {
        let output = Command::new("systemctl")
            .args(&["show", service, "--property=MemoryCurrent"])
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = output_str.lines().next() {
            if let Some(value) = line.split('=').nth(1) {
                let bytes = value.parse::<u64>()?;
                return Ok(bytes / 1024 / 1024); // Convert to MB
            }
        }

        Err(anyhow!("Could not get memory usage"))
    }

    async fn get_service_cpu_usage(&self, service: &str) -> Result<f64> {
        let output = Command::new("systemctl")
            .args(&["show", service, "--property=CPUUsageNSec"])
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = output_str.lines().next() {
            if let Some(value) = line.split('=').nth(1) {
                let nanosecs = value.parse::<u64>()?;
                // This would need to be calculated as a rate over time
                return Ok(nanosecs as f64 / 1_000_000_000.0); // Simplified
            }
        }

        Err(anyhow!("Could not get CPU usage"))
    }

    // Store metrics in database (for time series data)
    pub async fn store_metrics(&self, metrics: &SystemMetrics, db: &sqlx::PgPool) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO system_metrics (
                timestamp, cpu_usage_percent, memory_usage_percent, 
                memory_total_mb, memory_used_mb, load_avg_1m, 
                load_avg_5m, load_avg_15m, uptime_seconds
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            metrics.timestamp,
            metrics.cpu.usage_percent,
            metrics.memory.usage_percent,
            metrics.memory.total_mb as i64,
            metrics.memory.used_mb as i64,
            metrics.load_average.one_minute,
            metrics.load_average.five_minutes,
            metrics.load_average.fifteen_minutes,
            metrics.uptime as i64
        )
        .execute(db)
        .await?;

        Ok(())
    }

    // Get historical metrics
    pub async fn get_metrics_history(
        &self,
        db: &sqlx::PgPool,
        hours: i64,
    ) -> Result<Vec<SystemMetrics>> {
        let since = Utc::now() - Duration::hours(hours);
        
        let rows = sqlx::query!(
            "SELECT * FROM system_metrics WHERE timestamp >= $1 ORDER BY timestamp ASC",
            since
        )
        .fetch_all(db)
        .await?;

        // Convert database rows back to SystemMetrics
        // This is simplified - you'd need to store and retrieve all metric components
        Ok(vec![]) // Placeholder
    }

    // Alias method for compatibility
    pub async fn get_service_statuses(&self, services: &[&str]) -> Result<Vec<ServiceStatus>> {
        self.get_service_status(services).await
    }

    // Get process list
    pub async fn get_process_list(&self) -> Result<Vec<ProcessInfo>> {
        let output = Command::new("ps")
            .args(&["aux", "--sort=-pcpu"])
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut processes = Vec::new();

        for line in output_str.lines().skip(1).take(10) { // Top 10 processes
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 11 {
                if let (Ok(pid), Ok(cpu), Ok(mem)) = (
                    fields[1].parse::<u32>(),
                    fields[2].parse::<f64>(),
                    fields[3].parse::<f64>(),
                ) {
                    processes.push(ProcessInfo {
                        pid,
                        name: fields[10].to_string(),
                        cpu_percent: cpu,
                        memory_mb: (mem * 1024.0) as u64, // Simplified conversion
                        user: fields[0].to_string(),
                    });
                }
            }
        }

        Ok(processes)
    }

    // Get disk usage breakdown
    pub async fn get_disk_usage(&self) -> Result<Vec<DiskMetrics>> {
        self.collect_disk_metrics().await
    }

    // Get network statistics
    pub async fn get_network_stats(&self) -> Result<Vec<NetworkMetrics>> {
        self.collect_network_metrics().await
    }

    // Collect metrics in flat format for handlers
    pub async fn collect_flat_metrics(&self) -> Result<FlatSystemMetrics> {
        let metrics = self.collect_metrics().await?;
        Ok(metrics.into())
    }
}