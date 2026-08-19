use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use rust_decimal::Decimal;

#[derive(Debug, Deserialize, Serialize, Clone, Copy, sqlx::Type, PartialEq)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
}

impl UserRole {
    pub fn as_str(&self) -> &str {
        match self {
            UserRole::Admin => "admin",
            UserRole::User => "user",
        }
    }
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, sqlx::Type, Clone)]
pub struct User {
    pub id: uuid::Uuid,
    pub name: String,
    pub email: String,
    pub password: String,
    pub role: UserRole,
    pub verified: bool,
    pub verification_token: Option<String>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub failed_login_attempts: Option<i32>,
    pub locked_until: Option<DateTime<Utc>>,
    pub two_factor_enabled: Option<bool>,
    pub two_factor_secret: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,
}

// Insurance Platform Models

#[derive(Debug, Deserialize, Serialize, Clone, sqlx::FromRow)]
pub struct Client {
    pub user_id: uuid::Uuid,
    pub advisor_id: Option<uuid::Uuid>,
    pub date_of_birth: Option<chrono::NaiveDate>,
    pub phone: Option<String>,
    pub address: Option<String>,
    pub city: Option<String>,
    pub province: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub emergency_contact_name: Option<String>,
    pub emergency_contact_phone: Option<String>,
    pub emergency_contact_relationship: Option<String>,
    pub beneficiaries: Option<serde_json::Value>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, Clone, sqlx::FromRow)]
pub struct Quote {
    pub id: uuid::Uuid,
    pub user_id: Option<uuid::Uuid>,
    pub advisor_id: Option<uuid::Uuid>,
    pub service_type: String,
    pub coverage_amount: Option<Decimal>,
    pub coverage_term: Option<i32>,
    pub status: String,
    pub personal_info: Option<serde_json::Value>,
    pub health_info: Option<serde_json::Value>,
    pub additional_info: Option<serde_json::Value>,
    pub notes: Option<String>,
    pub estimated_premium: Option<Decimal>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub reviewed_by: Option<uuid::Uuid>,
}

#[derive(Debug, Deserialize, Serialize, Clone, sqlx::FromRow)]
pub struct Policy {
    pub id: uuid::Uuid,
    pub client_id: uuid::Uuid,
    pub quote_id: Option<uuid::Uuid>,
    pub advisor_id: Option<uuid::Uuid>,
    pub policy_number: String,
    pub r#type: String,
    pub coverage_amount: Decimal,
    pub premium_amount: Decimal,
    pub premium_frequency: String,
    pub start_date: chrono::NaiveDate,
    pub end_date: Option<chrono::NaiveDate>,
    pub status: String,
    pub payment_method: Option<String>,
    pub next_payment_date: Option<chrono::NaiveDate>,
    pub documents: Option<serde_json::Value>,
    pub terms: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, Clone, sqlx::FromRow)]
pub struct Appointment {
    pub id: uuid::Uuid,
    pub client_id: uuid::Uuid,
    pub advisor_id: uuid::Uuid,
    pub quote_id: Option<uuid::Uuid>,
    pub appointment_date: DateTime<Utc>,
    pub duration_minutes: i32,
    pub r#type: String,
    pub status: String,
    pub meeting_link: Option<String>,
    pub location: Option<String>,
    pub notes: Option<String>,
    pub reminder_sent: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, Clone, sqlx::FromRow)]
pub struct Document {
    pub id: uuid::Uuid,
    pub policy_id: Option<uuid::Uuid>,
    pub client_id: uuid::Uuid,
    pub quote_id: Option<uuid::Uuid>,
    pub r#type: String,
    pub name: String,
    pub file_path: String,
    pub file_size: Option<i64>,
    pub mime_type: Option<String>,
    pub uploaded_by: Option<uuid::Uuid>,
    pub version: i32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, Clone, sqlx::FromRow)]
pub struct Payment {
    pub id: uuid::Uuid,
    pub policy_id: uuid::Uuid,
    pub client_id: uuid::Uuid,
    pub amount: Decimal,
    pub payment_date: chrono::NaiveDate,
    pub due_date: chrono::NaiveDate,
    pub method: String,
    pub status: String,
    pub transaction_id: Option<String>,
    pub receipt_url: Option<String>,
    pub failure_reason: Option<String>,
    pub processed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, Clone, sqlx::FromRow)]
pub struct Claim {
    pub id: uuid::Uuid,
    pub policy_id: uuid::Uuid,
    pub client_id: uuid::Uuid,
    pub r#type: String,
    pub claim_amount: Option<Decimal>,
    pub submitted_amount: Decimal,
    pub status: String,
    pub description: String,
    pub incident_date: Option<chrono::NaiveDate>,
    pub documents: Option<serde_json::Value>,
    pub reviewed_by: Option<uuid::Uuid>,
    pub review_notes: Option<String>,
    pub submitted_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub processed_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}
