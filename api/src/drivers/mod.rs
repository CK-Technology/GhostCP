pub mod dns;
pub mod acme;
pub mod backup;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// Re-export main traits
pub use dns::{DnsProvider, DnsError, DnsRecord, DnsZone};
pub use acme::{AcmeProvider, AcmeError, CertificateRequest};
pub use backup::{BackupProvider, BackupError, BackupJob};