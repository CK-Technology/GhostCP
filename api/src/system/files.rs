// Basic file manager for web hosting
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManager {
    pub base_path: PathBuf,
    pub allowed_extensions: Vec<String>,
    pub max_file_size: usize, // in bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub file_type: FileType,
    pub permissions: String,
    pub owner: String,
    pub group: String,
    pub modified: DateTime<Utc>,
    pub is_readable: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileType {
    File,
    Directory,
    Symlink,
}

impl FileManager {
    pub fn new(base_path: PathBuf) -> Self {
        Self {
            base_path,
            allowed_extensions: vec![
                // Web files
                "html".to_string(), "htm".to_string(), "php".to_string(),
                "css".to_string(), "js".to_string(), "json".to_string(),
                
                // Text files  
                "txt".to_string(), "md".to_string(), "xml".to_string(),
                
                // Config files
                "conf".to_string(), "cfg".to_string(), "ini".to_string(),
                "yaml".to_string(), "yml".to_string(), "env".to_string(),
                
                // Images
                "jpg".to_string(), "jpeg".to_string(), "png".to_string(),
                "gif".to_string(), "svg".to_string(), "webp".to_string(),
                
                // Archives
                "zip".to_string(), "tar".to_string(), "gz".to_string(),
            ],
            max_file_size: 100 * 1024 * 1024, // 100MB
        }
    }

    // List directory contents
    pub async fn list_directory(&self, path: &str) -> Result<Vec<FileInfo>> {
        let full_path = self.resolve_path(path)?;
        
        if !full_path.exists() {
            return Err(anyhow!("Directory does not exist"));
        }
        
        if !full_path.is_dir() {
            return Err(anyhow!("Path is not a directory"));
        }

        let mut files = Vec::new();
        let mut entries = fs::read_dir(&full_path)?;
        
        while let Some(entry) = entries.next().transpose()? {
            let metadata = entry.metadata()?;
            let file_name = entry.file_name().to_string_lossy().to_string();
            
            // Skip hidden files starting with .
            if file_name.starts_with('.') && file_name != ".htaccess" {
                continue;
            }
            
            let file_type = if metadata.is_dir() {
                FileType::Directory
            } else if metadata.file_type().is_symlink() {
                FileType::Symlink
            } else {
                FileType::File
            };
            
            let modified = metadata.modified()
                .map(|time| DateTime::from(time))
                .unwrap_or_else(|_| Utc::now());
            
            // Get permissions (Unix-like systems)
            #[cfg(unix)]
            let permissions = {
                use std::os::unix::fs::MetadataExt;
                format!("{:o}", metadata.mode() & 0o777)
            };
            
            #[cfg(not(unix))]
            let permissions = "644".to_string();
            
            // Get owner info (Unix-like systems)
            #[cfg(unix)]
            let (owner, group) = {
                use std::os::unix::fs::MetadataExt;
                let uid = metadata.uid();
                let gid = metadata.gid();
                
                // In a real implementation, you'd convert UID/GID to names
                (uid.to_string(), gid.to_string())
            };
            
            #[cfg(not(unix))]
            let (owner, group) = ("user".to_string(), "user".to_string());
            
            files.push(FileInfo {
                name: file_name,
                path: entry.path().to_string_lossy().to_string(),
                size: metadata.len(),
                file_type,
                permissions,
                owner,
                group,
                modified,
                is_readable: true, // Simplified
                is_writable: !metadata.permissions().readonly(),
            });
        }
        
        // Sort: directories first, then files alphabetically
        files.sort_by(|a, b| {
            match (&a.file_type, &b.file_type) {
                (FileType::Directory, FileType::File) => std::cmp::Ordering::Less,
                (FileType::File, FileType::Directory) => std::cmp::Ordering::Greater,
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            }
        });
        
        Ok(files)
    }

    // Read file content
    pub async fn read_file(&self, path: &str) -> Result<String> {
        let full_path = self.resolve_path(path)?;
        
        if !full_path.exists() {
            return Err(anyhow!("File does not exist"));
        }
        
        if !full_path.is_file() {
            return Err(anyhow!("Path is not a file"));
        }
        
        // Check file size
        let metadata = fs::metadata(&full_path)?;
        if metadata.len() > self.max_file_size as u64 {
            return Err(anyhow!("File too large to read"));
        }
        
        // Check if file is text-based
        if !self.is_text_file(&full_path)? {
            return Err(anyhow!("File is not readable (binary file)"));
        }
        
        let content = fs::read_to_string(&full_path)?;
        Ok(content)
    }

    // Write file content
    pub async fn write_file(&self, path: &str, content: &str) -> Result<()> {
        let full_path = self.resolve_path(path)?;
        
        // Check if parent directory exists
        if let Some(parent) = full_path.parent() {
            if !parent.exists() {
                return Err(anyhow!("Parent directory does not exist"));
            }
        }
        
        // Check file extension
        if let Some(extension) = full_path.extension() {
            let ext = extension.to_string_lossy().to_lowercase();
            if !self.allowed_extensions.contains(&ext) {
                return Err(anyhow!("File extension not allowed"));
            }
        }
        
        // Check content size
        if content.len() > self.max_file_size {
            return Err(anyhow!("File content too large"));
        }
        
        // Create backup if file exists
        if full_path.exists() {
            let backup_path = format!("{}.backup", full_path.display());
            fs::copy(&full_path, backup_path)?;
        }
        
        fs::write(&full_path, content)?;
        Ok(())
    }

    // Create directory
    pub async fn create_directory(&self, path: &str) -> Result<()> {
        let full_path = self.resolve_path(path)?;
        
        if full_path.exists() {
            return Err(anyhow!("Directory already exists"));
        }
        
        fs::create_dir_all(&full_path)?;
        Ok(())
    }

    // Delete file or directory
    pub async fn delete(&self, path: &str) -> Result<()> {
        let full_path = self.resolve_path(path)?;
        
        if !full_path.exists() {
            return Err(anyhow!("Path does not exist"));
        }
        
        // Protect important files
        let protected_files = [".htaccess", "index.php", "wp-config.php"];
        if let Some(file_name) = full_path.file_name() {
            if protected_files.contains(&file_name.to_string_lossy().as_ref()) {
                return Err(anyhow!("Cannot delete protected file"));
            }
        }
        
        if full_path.is_dir() {
            fs::remove_dir_all(&full_path)?;
        } else {
            fs::remove_file(&full_path)?;
        }
        
        Ok(())
    }

    // Move/rename file
    pub async fn move_file(&self, from: &str, to: &str) -> Result<()> {
        let from_path = self.resolve_path(from)?;
        let to_path = self.resolve_path(to)?;
        
        if !from_path.exists() {
            return Err(anyhow!("Source file does not exist"));
        }
        
        if to_path.exists() {
            return Err(anyhow!("Destination already exists"));
        }
        
        fs::rename(&from_path, &to_path)?;
        Ok(())
    }

    // Copy file
    pub async fn copy_file(&self, from: &str, to: &str) -> Result<()> {
        let from_path = self.resolve_path(from)?;
        let to_path = self.resolve_path(to)?;
        
        if !from_path.exists() {
            return Err(anyhow!("Source file does not exist"));
        }
        
        if to_path.exists() {
            return Err(anyhow!("Destination already exists"));
        }
        
        if from_path.is_dir() {
            self.copy_dir_recursive(&from_path, &to_path)?;
        } else {
            fs::copy(&from_path, &to_path)?;
        }
        
        Ok(())
    }

    // Upload file
    pub async fn upload_file(&self, path: &str, content: Vec<u8>) -> Result<()> {
        let full_path = self.resolve_path(path)?;
        
        // Check file size
        if content.len() > self.max_file_size {
            return Err(anyhow!("File too large"));
        }
        
        // Check file extension
        if let Some(extension) = full_path.extension() {
            let ext = extension.to_string_lossy().to_lowercase();
            if !self.allowed_extensions.contains(&ext) {
                return Err(anyhow!("File extension not allowed"));
            }
        }
        
        fs::write(&full_path, content)?;
        Ok(())
    }

    // Extract archive
    pub async fn extract_archive(&self, archive_path: &str, extract_to: &str) -> Result<()> {
        let archive_full_path = self.resolve_path(archive_path)?;
        let extract_full_path = self.resolve_path(extract_to)?;
        
        if !archive_full_path.exists() {
            return Err(anyhow!("Archive file does not exist"));
        }
        
        // Create extraction directory
        fs::create_dir_all(&extract_full_path)?;
        
        // Check archive type and extract
        if let Some(extension) = archive_full_path.extension() {
            match extension.to_string_lossy().to_lowercase().as_str() {
                "zip" => {
                    std::process::Command::new("unzip")
                        .args(&[
                            "-q", 
                            archive_full_path.to_str().unwrap(),
                            "-d",
                            extract_full_path.to_str().unwrap()
                        ])
                        .output()?;
                },
                "tar" | "gz" => {
                    std::process::Command::new("tar")
                        .args(&[
                            "-xzf",
                            archive_full_path.to_str().unwrap(),
                            "-C",
                            extract_full_path.to_str().unwrap()
                        ])
                        .output()?;
                },
                _ => return Err(anyhow!("Unsupported archive format")),
            }
        }
        
        Ok(())
    }

    // Get file permissions
    pub async fn get_permissions(&self, path: &str) -> Result<String> {
        let full_path = self.resolve_path(path)?;
        
        if !full_path.exists() {
            return Err(anyhow!("File does not exist"));
        }
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::metadata(&full_path)?;
            Ok(format!("{:o}", metadata.mode() & 0o777))
        }
        
        #[cfg(not(unix))]
        Ok("644".to_string())
    }

    // Set file permissions
    pub async fn set_permissions(&self, path: &str, permissions: &str) -> Result<()> {
        let full_path = self.resolve_path(path)?;
        
        if !full_path.exists() {
            return Err(anyhow!("File does not exist"));
        }
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = u32::from_str_radix(permissions, 8)?;
            let perms = std::fs::Permissions::from_mode(mode);
            fs::set_permissions(&full_path, perms)?;
        }
        
        Ok(())
    }

    // Helper methods
    fn resolve_path(&self, path: &str) -> Result<PathBuf> {
        let path = path.trim_start_matches('/');
        let full_path = self.base_path.join(path);
        
        // Ensure the path is within base_path (security check)
        let canonical = full_path.canonicalize().unwrap_or(full_path.clone());
        if !canonical.starts_with(&self.base_path) {
            return Err(anyhow!("Access denied: path outside allowed directory"));
        }
        
        Ok(canonical)
    }

    fn is_text_file(&self, path: &Path) -> Result<bool> {
        // Check by extension first
        if let Some(extension) = path.extension() {
            let ext = extension.to_string_lossy().to_lowercase();
            let text_extensions = [
                "txt", "html", "htm", "php", "css", "js", "json", "xml",
                "md", "conf", "cfg", "ini", "yaml", "yml", "env", "log",
                "sql", "py", "rb", "pl", "sh", "bash",
            ];
            
            if text_extensions.contains(&ext.as_str()) {
                return Ok(true);
            }
        }
        
        // Check content (simple heuristic)
        let mut file = std::fs::File::open(path)?;
        let mut buffer = [0; 1024];
        let bytes_read = std::io::Read::read(&mut file, &mut buffer)?;
        
        // Check if content is mostly ASCII/UTF-8
        let text_ratio = buffer[..bytes_read].iter()
            .filter(|&&byte| byte >= 32 && byte <= 126 || byte == 9 || byte == 10 || byte == 13)
            .count() as f64 / bytes_read as f64;
            
        Ok(text_ratio > 0.8)
    }

    fn copy_dir_recursive(&self, from: &Path, to: &Path) -> Result<()> {
        fs::create_dir_all(to)?;
        
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            let from_path = entry.path();
            let to_path = to.join(entry.file_name());
            
            if from_path.is_dir() {
                self.copy_dir_recursive(&from_path, &to_path)?;
            } else {
                fs::copy(&from_path, &to_path)?;
            }
        }
        
        Ok(())
    }
}