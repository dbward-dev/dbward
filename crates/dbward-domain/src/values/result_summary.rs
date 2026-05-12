use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultSummary {
    pub execution_id: String,
    pub success: bool,
    pub rows_affected: Option<u64>,
    pub truncated: bool,
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_data: Option<String>,
}
