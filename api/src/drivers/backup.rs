use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("Backup API error: {0}")]
    ApiError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Compression error: {0}")]
    CompressionError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupJob {
    pub name: String,
    pub include_paths: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub include_databases: Vec<String>,
    pub compression: CompressionType,
    pub encryption_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionType {
    None,
    Gzip,
    Zstd,
}

#[async_trait]
pub trait BackupProvider: Send + Sync {
    fn provider_name(&self) -> &'static str;
    
    async fn create_backup(&self, job: &BackupJob) -> Result<String, BackupError>;
    
    async fn restore_backup(&self, backup_id: &str, destination: &str) -> Result<(), BackupError>;
    
    async fn delete_backup(&self, backup_id: &str) -> Result<(), BackupError>;
    
    async fn list_backups(&self) -> Result<Vec<String>, BackupError>;
}

// TODO: Implement S3, MinIO, local filesystem providers