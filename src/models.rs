use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct Entry {
    pub site: String,
    pub username: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
}

impl Entry {
    pub fn new(site: &str, username: &str, password: &str) -> Self {
        Entry {
            site: site.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            created_at: Utc::now(),
        }
    }
}
