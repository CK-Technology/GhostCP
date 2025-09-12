use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

// TODO: Implement full models - these are stubs
#[derive(Debug, Serialize)]
pub struct PlaceholderModel {
    pub id: Uuid,
}
