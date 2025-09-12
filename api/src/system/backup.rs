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

        Command::new("crontab")
            .arg("-")
            .arg(&crontab)
            .output()?;

        Ok(())
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