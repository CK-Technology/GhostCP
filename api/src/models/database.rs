use serde::Serialize;
use uuid::Uuid;

// TODO: Implement full models - these are stubs
#[derive(Debug, Serialize)]
pub struct PlaceholderModel {
    pub id: Uuid,
}
