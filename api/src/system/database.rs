// Database management system for MySQL/PostgreSQL/MariaDB
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::process::Command;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sqlx::{Row, mysql::MySqlPool, postgres::PgPool};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseManager {
    pub mysql_enabled: bool,
    pub postgresql_enabled: bool,
    pub mariadb_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub db_type: DatabaseType,
    pub host: String,
    pub port: u16,
    pub charset: String,
    pub collation: String,
    pub size_mb: Option<i64>,
    pub max_connections: Option<u32>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseUser {
    pub id: Uuid,
    pub database_id: Uuid,
    pub username: String,
    pub host: String,
    pub privileges: Vec<DatabasePrivilege>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    MariaDB,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatabasePrivilege {
    Select,
    Insert, 
    Update,
    Delete,
    Create,
    Drop,
    Index,
    Alter,
    Grant,
    All,
}

impl DatabaseManager {
    pub fn new() -> Self {
        Self {
            mysql_enabled: true,
            postgresql_enabled: true,
            mariadb_enabled: false,
        }
    }

    // Create database
    pub async fn create_database(
        &self,
        db_type: &DatabaseType,
        name: &str,
        charset: Option<&str>,
        collation: Option<&str>,
    ) -> Result<()> {
        match db_type {
            DatabaseType::MySQL | DatabaseType::MariaDB => {
                self.create_mysql_database(name, charset, collation).await
            },
            DatabaseType::PostgreSQL => {
                self.create_postgresql_database(name).await
            },
        }
    }

    async fn create_mysql_database(
        &self,
        name: &str,
        charset: Option<&str>,
        collation: Option<&str>,
    ) -> Result<()> {
        let charset = charset.unwrap_or("utf8mb4");
        let collation = collation.unwrap_or("utf8mb4_unicode_ci");
        
        let query = format!(
            "CREATE DATABASE `{}` CHARACTER SET {} COLLATE {}",
            name, charset, collation
        );

        let output = Command::new("mysql")
            .args(&["-e", &query])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to create MySQL database: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        Ok(())
    }

    async fn create_postgresql_database(&self, name: &str) -> Result<()> {
        let output = Command::new("createdb")
            .arg(name)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to create PostgreSQL database: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        Ok(())
    }

    // Create database user
    pub async fn create_user(
        &self,
        db_type: &DatabaseType,
        username: &str,
        password: &str,
        database: &str,
        host: Option<&str>,
    ) -> Result<()> {
        match db_type {
            DatabaseType::MySQL | DatabaseType::MariaDB => {
                self.create_mysql_user(username, password, database, host).await
            },
            DatabaseType::PostgreSQL => {
                self.create_postgresql_user(username, password, database).await
            },
        }
    }

    async fn create_mysql_user(
        &self,
        username: &str,
        password: &str,
        database: &str,
        host: Option<&str>,
    ) -> Result<()> {
        let host = host.unwrap_or("localhost");
        
        // Create user
        let create_query = format!(
            "CREATE USER '{}'@'{}' IDENTIFIED BY '{}'",
            username, host, password
        );

        let output = Command::new("mysql")
            .args(&["-e", &create_query])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to create MySQL user"));
        }

        // Grant privileges
        let grant_query = format!(
            "GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'{}'",
            database, username, host
        );

        let output = Command::new("mysql")
            .args(&["-e", &grant_query])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to grant privileges"));
        }

        // Flush privileges
        Command::new("mysql")
            .args(&["-e", "FLUSH PRIVILEGES"])
            .output()?;

        Ok(())
    }

    async fn create_postgresql_user(
        &self,
        username: &str,
        password: &str,
        database: &str,
    ) -> Result<()> {
        // Create user
        let output = Command::new("createuser")
            .args(&[username, "--no-createdb", "--no-createrole", "--no-superuser"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to create PostgreSQL user"));
        }

        // Set password
        let password_query = format!("ALTER USER {} PASSWORD '{}'", username, password);
        let output = Command::new("psql")
            .args(&["-c", &password_query])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to set password"));
        }

        // Grant database access
        let grant_query = format!("GRANT ALL PRIVILEGES ON DATABASE {} TO {}", database, username);
        Command::new("psql")
            .args(&["-c", &grant_query])
            .output()?;

        Ok(())
    }

    // Delete database
    pub async fn delete_database(&self, db_type: &DatabaseType, name: &str) -> Result<()> {
        match db_type {
            DatabaseType::MySQL | DatabaseType::MariaDB => {
                let query = format!("DROP DATABASE IF EXISTS `{}`", name);
                let output = Command::new("mysql")
                    .args(&["-e", &query])
                    .output()?;

                if !output.status.success() {
                    return Err(anyhow!("Failed to delete MySQL database"));
                }
            },
            DatabaseType::PostgreSQL => {
                let output = Command::new("dropdb")
                    .arg(name)
                    .output()?;

                if !output.status.success() {
                    return Err(anyhow!("Failed to delete PostgreSQL database"));
                }
            },
        }

        Ok(())
    }

    // Delete user
    pub async fn delete_user(
        &self,
        db_type: &DatabaseType,
        username: &str,
        host: Option<&str>,
    ) -> Result<()> {
        match db_type {
            DatabaseType::MySQL | DatabaseType::MariaDB => {
                let host = host.unwrap_or("localhost");
                let query = format!("DROP USER IF EXISTS '{}'@'{}'", username, host);
                let output = Command::new("mysql")
                    .args(&["-e", &query])
                    .output()?;

                if !output.status.success() {
                    return Err(anyhow!("Failed to delete MySQL user"));
                }
            },
            DatabaseType::PostgreSQL => {
                let output = Command::new("dropuser")
                    .arg(username)
                    .output()?;

                if !output.status.success() {
                    return Err(anyhow!("Failed to delete PostgreSQL user"));
                }
            },
        }

        Ok(())
    }

    // List databases
    pub async fn list_databases(&self, db_type: &DatabaseType) -> Result<Vec<String>> {
        match db_type {
            DatabaseType::MySQL | DatabaseType::MariaDB => {
                let output = Command::new("mysql")
                    .args(&["-e", "SHOW DATABASES"])
                    .output()?;

                if !output.status.success() {
                    return Err(anyhow!("Failed to list MySQL databases"));
                }

                let output_str = String::from_utf8_lossy(&output.stdout);
                let databases: Vec<String> = output_str
                    .lines()
                    .skip(1) // Skip header
                    .filter(|line| {
                        // Filter out system databases
                        !["information_schema", "mysql", "performance_schema", "sys"].contains(line)
                    })
                    .map(|line| line.to_string())
                    .collect();

                Ok(databases)
            },
            DatabaseType::PostgreSQL => {
                let output = Command::new("psql")
                    .args(&["-l", "-t"])
                    .output()?;

                if !output.status.success() {
                    return Err(anyhow!("Failed to list PostgreSQL databases"));
                }

                let output_str = String::from_utf8_lossy(&output.stdout);
                let databases: Vec<String> = output_str
                    .lines()
                    .filter_map(|line| {
                        let parts: Vec<&str> = line.split('|').collect();
                        if parts.len() > 0 {
                            let name = parts[0].trim();
                            // Filter out system databases
                            if !["postgres", "template0", "template1"].contains(&name) {
                                Some(name.to_string())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect();

                Ok(databases)
            },
        }
    }

    // Get database size
    pub async fn get_database_size(&self, db_type: &DatabaseType, name: &str) -> Result<i64> {
        match db_type {
            DatabaseType::MySQL | DatabaseType::MariaDB => {
                let query = format!(
                    "SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'DB Size in MB' FROM information_schema.tables WHERE table_schema='{}'",
                    name
                );

                let output = Command::new("mysql")
                    .args(&["-e", &query, "-s"])
                    .output()?;

                if !output.status.success() {
                    return Ok(0);
                }

                let size_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                Ok(size_str.parse().unwrap_or(0))
            },
            DatabaseType::PostgreSQL => {
                let query = format!("SELECT pg_database_size('{}')", name);
                let output = Command::new("psql")
                    .args(&["-c", &query, "-t"])
                    .output()?;

                if !output.status.success() {
                    return Ok(0);
                }

                let size_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let bytes: i64 = size_str.parse().unwrap_or(0);
                Ok(bytes / 1024 / 1024) // Convert to MB
            },
        }
    }

    // Backup database
    pub async fn backup_database(
        &self,
        db_type: &DatabaseType,
        name: &str,
        output_path: &str,
    ) -> Result<()> {
        match db_type {
            DatabaseType::MySQL | DatabaseType::MariaDB => {
                let output = Command::new("mysqldump")
                    .args(&[
                        "--single-transaction",
                        "--routines",
                        "--triggers",
                        name,
                        "--result-file",
                        output_path,
                    ])
                    .output()?;

                if !output.status.success() {
                    return Err(anyhow!("Failed to backup MySQL database"));
                }
            },
            DatabaseType::PostgreSQL => {
                let output = Command::new("pg_dump")
                    .args(&[
                        "-d", name,
                        "-f", output_path,
                        "--clean",
                        "--if-exists",
                        "--no-owner",
                        "--no-privileges",
                    ])
                    .output()?;

                if !output.status.success() {
                    return Err(anyhow!("Failed to backup PostgreSQL database"));
                }
            },
        }

        Ok(())
    }

    // Restore database
    pub async fn restore_database(
        &self,
        db_type: &DatabaseType,
        name: &str,
        backup_path: &str,
    ) -> Result<()> {
        match db_type {
            DatabaseType::MySQL | DatabaseType::MariaDB => {
                let output = Command::new("mysql")
                    .arg(name)
                    .stdin(std::fs::File::open(backup_path)?)
                    .output()?;

                if !output.status.success() {
                    return Err(anyhow!("Failed to restore MySQL database"));
                }
            },
            DatabaseType::PostgreSQL => {
                let output = Command::new("psql")
                    .args(&["-d", name, "-f", backup_path])
                    .output()?;

                if !output.status.success() {
                    return Err(anyhow!("Failed to restore PostgreSQL database"));
                }
            },
        }

        Ok(())
    }

    // Get database status
    pub async fn get_status(&self) -> Result<DatabaseStatus> {
        let mysql_running = self.is_service_running("mysql").await?;
        let postgresql_running = self.is_service_running("postgresql").await?;
        
        Ok(DatabaseStatus {
            mysql_running,
            postgresql_running,
            mysql_version: if mysql_running {
                self.get_mysql_version().await?
            } else {
                None
            },
            postgresql_version: if postgresql_running {
                self.get_postgresql_version().await?
            } else {
                None
            },
        })
    }

    async fn is_service_running(&self, service: &str) -> Result<bool> {
        let output = Command::new("systemctl")
            .args(&["is-active", service])
            .output()?;

        Ok(output.status.success())
    }

    async fn get_mysql_version(&self) -> Result<Option<String>> {
        let output = Command::new("mysql")
            .args(&["-e", "SELECT VERSION()", "-s"])
            .output()?;

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(Some(version))
        } else {
            Ok(None)
        }
    }

    async fn get_postgresql_version(&self) -> Result<Option<String>> {
        let output = Command::new("psql")
            .args(&["-c", "SELECT version()", "-t"])
            .output()?;

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(Some(version))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStatus {
    pub mysql_running: bool,
    pub postgresql_running: bool,
    pub mysql_version: Option<String>,
    pub postgresql_version: Option<String>,
}