use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct Entry {
    pub site: String,
    pub username: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
}

impl Entry {
    pub fn new(site: String, username: String, password: String) -> Self {
        Entry {
            site: site,
            username: username,
            password: password,
            created_at: Utc::now(),
        }
    }
}
