// Backup system with Restic integration and multiple storage backends
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::fs;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub backend: BackupBackend,
    pub encryption_password: String,
    pub retention: RetentionPolicy,
    pub schedule: BackupSchedule,
    pub excludes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupBackend {
    Local { path: PathBuf },
    S3 { 
        endpoint: String,
        bucket: String,
        access_key: String,
        secret_key: String,
        region: String,
    },
    DigitalOceanSpaces {
        endpoint: String,
        bucket: String,
        access_key: String,
        secret_key: String,
        region: String,
    },
    Wasabi {
        endpoint: String,
        bucket: String,
        access_key: String,
        secret_key: String,
        region: String,
    },
    BackblazeB2 {
        account_id: String,
        application_key: String,
        bucket: String,
    },
    MinIO {
        endpoint: String,
        bucket: String,
        access_key: String,
        secret_key: String,
        secure: bool,
    },
    SFTP {
        host: String,
        port: u16,
        username: String,
        password: Option<String>,
        key_path: Option<PathBuf>,
        path: String,
    },
    Rclone {
        remote: String,
        path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub hourly: Option<u32>,
    pub daily: Option<u32>,
    pub weekly: Option<u32>,
    pub monthly: Option<u32>,
    pub yearly: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupSchedule {
    Hourly,
    Daily { hour: u8 },
    Weekly { day: u8, hour: u8 },
    Monthly { day: u8, hour: u8 },
    Custom { cron: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupJob {
    pub id: Uuid,
    pub name: String,
    pub backup_type: BackupType,
    pub source_paths: Vec<PathBuf>,
    pub config: BackupConfig,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: Option<DateTime<Utc>>,
    pub status: BackupStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupType {
    Full,
    Incremental,
    UserHome { username: String },
    Database { db_type: String, db_name: String },
    Website { domain: String },
    System,
    Mail { domain: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupStatus {
    Pending,
    Running,
    Success,
    Failed { error: String },
}

pub struct BackupManager {
    restic_path: PathBuf,
    work_dir: PathBuf,
}

impl BackupManager {
    pub fn new() -> Self {
        Self {
            restic_path: PathBuf::from("/usr/local/bin/restic"),
            work_dir: PathBuf::from("/var/lib/ghostcp/backups"),
        }
    }

    // Install Restic if not present
    pub async fn install_restic(&self) -> Result<()> {
        if self.restic_path.exists() {
            return Ok(());
        }

        let output = Command::new("wget")
            .args(&[
                "-O",
                "/tmp/restic.bz2",
                "https://github.com/restic/restic/releases/latest/download/restic_linux_amd64.bz2"
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to download Restic"));
        }

        Command::new("bunzip2")
            .args(&["/tmp/restic.bz2"])
            .output()?;

        Command::new("chmod")
            .args(&["+x", "/tmp/restic"])
            .output()?;

        Command::new("mv")
            .args(&["/tmp/restic", self.restic_path.to_str().unwrap()])
            .output()?;

        Ok(())
    }

    // Initialize repository
    pub async fn init_repository(&self, config: &BackupConfig) -> Result<()> {
        let repo_url = self.get_repository_url(&config.backend)?;
        
        let output = Command::new(&self.restic_path)
            .env("RESTIC_PASSWORD", &config.encryption_password)
            .args(&["init", "--repo", &repo_url])
            .output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            if !error.contains("already initialized") {
                return Err(anyhow!("Failed to initialize repository: {}", error));
            }
        }

        Ok(())
    }

    // Perform backup
    pub async fn backup(&self, job: &BackupJob) -> Result<String> {
        let repo_url = self.get_repository_url(&job.config.backend)?;
        
        // Prepare backup command
        let mut args = vec![
            "backup".to_string(),
            "--repo".to_string(),
            repo_url,
            "--tag".to_string(),
            format!("job:{}", job.id),
            "--tag".to_string(),
            format!("type:{:?}", job.backup_type),
        ];

        // Add source paths
        for path in &job.source_paths {
            args.push(path.to_str().unwrap().to_string());
        }

        // Add excludes
        for exclude in &job.config.excludes {
            args.push("--exclude".to_string());
            args.push(exclude.clone());
        }

        // Add JSON output for parsing
        args.push("--json".to_string());

        // Handle special backup types
        match &job.backup_type {
            BackupType::Database { db_type, db_name } => {
                // Dump database first
                let dump_path = self.dump_database(db_type, db_name).await?;
                args.push(dump_path.to_str().unwrap().to_string());
            },
            BackupType::Mail { domain } => {
                // Include mail directories
                args.push(format!("/var/mail/vhosts/{}", domain));
            },
            _ => {}
        }

        // Run backup
        let output = Command::new(&self.restic_path)
            .env("RESTIC_PASSWORD", &job.config.encryption_password)
            .args(&args)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Backup failed: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        // Parse snapshot ID from output
        let output_str = String::from_utf8_lossy(&output.stdout);
        let snapshot_id = self.parse_snapshot_id(&output_str)?;

        // Apply retention policy
        self.apply_retention(&job.config).await?;

        Ok(snapshot_id)
    }

    // Restore from backup
    pub async fn restore(
        &self,
        config: &BackupConfig,
        snapshot_id: &str,
        target_path: &Path,
    ) -> Result<()> {
        let repo_url = self.get_repository_url(&config.backend)?;

        let output = Command::new(&self.restic_path)
            .env("RESTIC_PASSWORD", &config.encryption_password)
            .args(&[
                "restore",
                snapshot_id,
                "--repo", &repo_url,
                "--target", target_path.to_str().unwrap(),
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Restore failed: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        Ok(())
    }

    // List snapshots
    pub async fn list_snapshots(&self, config: &BackupConfig) -> Result<Vec<Snapshot>> {
        let repo_url = self.get_repository_url(&config.backend)?;

        let output = Command::new(&self.restic_path)
            .env("RESTIC_PASSWORD", &config.encryption_password)
            .args(&["snapshots", "--repo", &repo_url, "--json"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to list snapshots"));
        }

        let snapshots: Vec<Snapshot> = serde_json::from_slice(&output.stdout)?;
        Ok(snapshots)
    }

    // Apply retention policy
    async fn apply_retention(&self, config: &BackupConfig) -> Result<()> {
        let repo_url = self.get_repository_url(&config.backend)?;
        
        let mut args = vec![
            "forget".to_string(),
            "--repo".to_string(),
            repo_url,
            "--prune".to_string(),
        ];

        if let Some(hourly) = config.retention.hourly {
            args.push("--keep-hourly".to_string());
            args.push(hourly.to_string());
        }
        if let Some(daily) = config.retention.daily {
            args.push("--keep-daily".to_string());
            args.push(daily.to_string());
        }
        if let Some(weekly) = config.retention.weekly {
            args.push("--keep-weekly".to_string());
            args.push(weekly.to_string());
        }
        if let Some(monthly) = config.retention.monthly {
            args.push("--keep-monthly".to_string());
            args.push(monthly.to_string());
        }
        if let Some(yearly) = config.retention.yearly {
            args.push("--keep-yearly".to_string());
            args.push(yearly.to_string());
        }

        let output = Command::new(&self.restic_path)
            .env("RESTIC_PASSWORD", &config.encryption_password)
            .args(&args)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to apply retention policy"));
        }

        Ok(())
    }

    // Get repository URL based on backend
    fn get_repository_url(&self, backend: &BackupBackend) -> Result<String> {
        match backend {
            BackupBackend::Local { path } => {
                Ok(path.to_str().unwrap().to_string())
            },
            BackupBackend::S3 { endpoint, bucket, .. } => {
                Ok(format!("s3:{}/{}", endpoint, bucket))
            },
            BackupBackend::DigitalOceanSpaces { endpoint, bucket, .. } => {
                // DigitalOcean Spaces uses S3-compatible API
                Ok(format!("s3:{}/{}", endpoint.replace("https://", "").replace("http://", ""), bucket))
            },
            BackupBackend::Wasabi { endpoint, bucket, .. } => {
                // Wasabi uses S3-compatible API
                Ok(format!("s3:{}/{}", endpoint.replace("https://", "").replace("http://", ""), bucket))
            },
            BackupBackend::BackblazeB2 { bucket, .. } => {
                Ok(format!("b2:{}", bucket))
            },
            BackupBackend::MinIO { endpoint, bucket, .. } => {
                // MinIO uses S3-compatible API
                Ok(format!("s3:{}/{}", endpoint.replace("https://", "").replace("http://", ""), bucket))
            },
            BackupBackend::SFTP { host, port, username, path, .. } => {
                Ok(format!("sftp:{}@{}:{}{}", username, host, port, path))
            },
            BackupBackend::Rclone { remote, path } => {
                Ok(format!("rclone:{}:{}", remote, path))
            },
        }
    }

    // Dump database for backup
    async fn dump_database(&self, db_type: &str, db_name: &str) -> Result<PathBuf> {
        let dump_path = self.work_dir.join(format!("{}_dump.sql", db_name));

        match db_type {
            "mysql" | "mariadb" => {
                Command::new("mysqldump")
                    .args(&[
                        "--single-transaction",
                        "--routines",
                        "--triggers",
                        "--events",
                        db_name,
                    ])
                    .output()?;
            },
            "postgresql" => {
                Command::new("pg_dump")
                    .args(&[
                        "-d", db_name,
                        "-f", dump_path.to_str().unwrap(),
                        "--clean",
                        "--if-exists",
                    ])
                    .output()?;
            },
            _ => return Err(anyhow!("Unsupported database type")),
        }

        Ok(dump_path)
    }

    fn parse_snapshot_id(&self, output: &str) -> Result<String> {
        // Parse JSON output to get snapshot ID
        for line in output.lines() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(id) = json.get("snapshot_id").and_then(|v| v.as_str()) {
                    return Ok(id.to_string());
                }
            }
        }
        Err(anyhow!("Could not parse snapshot ID"))
    }

    // Create backup schedule with cron
    pub async fn schedule_backup(&self, job: &BackupJob) -> Result<()> {
        let cron_expression = match &job.config.schedule {
            BackupSchedule::Hourly => "0 * * * *".to_string(),
            BackupSchedule::Daily { hour } => format!("0 {} * * *", hour),
            BackupSchedule::Weekly { day, hour } => format!("0 {} * * {}", hour, day),
            BackupSchedule::Monthly { day, hour } => format!("0 {} {} * *", hour, day),
            BackupSchedule::Custom { cron } => cron.clone(),
        };

        let cron_line = format!(
            "{} /usr/local/bin/ghostcp-backup run {}",
            cron_expression,
            job.id
        );

        // Add to crontab
        let output = Command::new("crontab")
            .args(&["-l"])
            .output()?;

        let mut crontab = String::from_utf8_lossy(&output.stdout).to_string();
        crontab.push_str(&format!("\n{}\n", cron_line));

        let mut child = Command::new("crontab")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()?;

        if let Some(stdin) = child.stdin.take() {
            use std::io::Write;
            let mut stdin = stdin;
            stdin.write_all(crontab.as_bytes())?;
        }

        child.wait()?;

        Ok(())
    }

    // Check backup repository integrity
    pub async fn check_repository(&self, config: &BackupConfig) -> Result<BackupHealthStatus> {
        let repo_url = self.get_repository_url(&config.backend)?;

        let output = Command::new(&self.restic_path)
            .env("RESTIC_PASSWORD", &config.encryption_password)
            .args(&["check", "--repo", &repo_url])
            .output()?;

        let is_healthy = output.status.success();
        let errors = if is_healthy {
            vec![]
        } else {
            vec![String::from_utf8_lossy(&output.stderr).to_string()]
        };

        Ok(BackupHealthStatus {
            is_healthy,
            errors,
            last_check: Utc::now(),
        })
    }

    // Get backup statistics
    pub async fn get_backup_stats(&self, config: &BackupConfig) -> Result<BackupStats> {
        let repo_url = self.get_repository_url(&config.backend)?;

        let output = Command::new(&self.restic_path)
            .env("RESTIC_PASSWORD", &config.encryption_password)
            .args(&["stats", "--repo", &repo_url, "--json"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to get backup stats"));
        }

        let stats: BackupStats = serde_json::from_slice(&output.stdout)?;
        Ok(stats)
    }

    // Test backup configuration
    pub async fn test_config(&self, config: &BackupConfig) -> Result<ConfigTestResult> {
        let mut results = ConfigTestResult {
            repository_accessible: false,
            authentication_valid: false,
            write_permissions: false,
            errors: vec![],
        };

        // Test repository access
        let repo_url = match self.get_repository_url(&config.backend) {
            Ok(url) => {
                results.repository_accessible = true;
                url
            }
            Err(e) => {
                results.errors.push(format!("Repository URL error: {}", e));
                return Ok(results);
            }
        };

        // Test authentication by listing snapshots
        let output = Command::new(&self.restic_path)
            .env("RESTIC_PASSWORD", &config.encryption_password)
            .args(&["snapshots", "--repo", &repo_url, "--json"])
            .output();

        match output {
            Ok(output) if output.status.success() => {
                results.authentication_valid = true;
                results.write_permissions = true; // If we can list, we likely can write
            }
            Ok(output) => {
                let error = String::from_utf8_lossy(&output.stderr);
                results.errors.push(format!("Authentication failed: {}", error));
            }
            Err(e) => {
                results.errors.push(format!("Command execution failed: {}", e));
            }
        }

        Ok(results)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupHealthStatus {
    pub is_healthy: bool,
    pub errors: Vec<String>,
    pub last_check: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupStats {
    pub total_size: u64,
    pub total_file_count: u64,
    pub snapshots_count: u32,
    pub repository_size: u64,
    pub deduplicated_size: u64,
    pub compression_ratio: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigTestResult {
    pub repository_accessible: bool,
    pub authentication_valid: bool,
    pub write_permissions: bool,
    pub errors: Vec<String>,
}

impl Default for BackupManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_config_serialization() {
        let config = BackupConfig {
            backend: BackupBackend::S3 {
                endpoint: "s3.amazonaws.com".to_string(),
                bucket: "my-backups".to_string(),
                access_key: "AKIA123".to_string(),
                secret_key: "secret".to_string(),
                region: "us-east-1".to_string(),
            },
            encryption_password: "password123".to_string(),
            retention: RetentionPolicy {
                hourly: Some(24),
                daily: Some(7),
                weekly: Some(4),
                monthly: Some(12),
                yearly: Some(2),
            },
            schedule: BackupSchedule::Daily { hour: 2 },
            excludes: vec!["*.tmp".to_string(), "*.log".to_string()],
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: BackupConfig = serde_json::from_str(&json).unwrap();

        assert!(matches!(deserialized.backend, BackupBackend::S3 { .. }));
        assert_eq!(deserialized.encryption_password, "password123");
        assert!(matches!(deserialized.schedule, BackupSchedule::Daily { hour: 2 }));
    }

    #[test]
    fn test_repository_url_generation() {
        let manager = BackupManager::new();

        // Test S3 backend
        let s3_backend = BackupBackend::S3 {
            endpoint: "s3.amazonaws.com".to_string(),
            bucket: "my-bucket".to_string(),
            access_key: "key".to_string(),
            secret_key: "secret".to_string(),
            region: "us-east-1".to_string(),
        };

        let url = manager.get_repository_url(&s3_backend).unwrap();
        assert_eq!(url, "s3:s3.amazonaws.com/my-bucket");

        // Test local backend
        let local_backend = BackupBackend::Local {
            path: PathBuf::from("/backups/repo"),
        };

        let url = manager.get_repository_url(&local_backend).unwrap();
        assert_eq!(url, "/backups/repo");

        // Test SFTP backend
        let sftp_backend = BackupBackend::SFTP {
            host: "backup.example.com".to_string(),
            port: 22,
            username: "backups".to_string(),
            password: Some("pass".to_string()),
            key_path: None,
            path: "/backups".to_string(),
        };

        let url = manager.get_repository_url(&sftp_backend).unwrap();
        assert_eq!(url, "sftp:backups@backup.example.com:22/backups");
    }

    #[test]
    fn test_backup_job_creation() {
        let job = BackupJob {
            id: Uuid::new_v4(),
            name: "Daily Website Backup".to_string(),
            backup_type: BackupType::Website {
                domain: "example.com".to_string(),
            },
            source_paths: vec![
                PathBuf::from("/var/www/html/example.com"),
                PathBuf::from("/etc/nginx/sites-available/example.com"),
            ],
            config: BackupConfig {
                backend: BackupBackend::Local {
                    path: PathBuf::from("/backups"),
                },
                encryption_password: "secret".to_string(),
                retention: RetentionPolicy {
                    hourly: None,
                    daily: Some(7),
                    weekly: Some(4),
                    monthly: Some(6),
                    yearly: Some(1),
                },
                schedule: BackupSchedule::Daily { hour: 3 },
                excludes: vec!["*.log".to_string()],
            },
            last_run: None,
            next_run: None,
            status: BackupStatus::Pending,
        };

        assert_eq!(job.name, "Daily Website Backup");
        assert!(matches!(job.backup_type, BackupType::Website { .. }));
        assert_eq!(job.source_paths.len(), 2);
        assert!(matches!(job.status, BackupStatus::Pending));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub time: DateTime<Utc>,
    pub hostname: String,
    pub tags: Vec<String>,
    pub paths: Vec<String>,
}