use redis::{aio::ConnectionManager, AsyncCommands};
use relayer_core::utils::ThreadSafe;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use tracing::{debug, error};

#[derive(Clone)]
pub struct CostCache {
    conn: ConnectionManager,
}

impl CostCache {
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn }
    }
}

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait CostCacheTrait: ThreadSafe {
    async fn get_cost_by_message_id(
        &self,
        message_id: String,
        transaction_type: TransactionType,
    ) -> Result<u64, anyhow::Error>;
}

// Type alias for Arc-wrapped trait objects to make them cloneable
pub type CostCacheRef = Arc<dyn CostCacheTrait>;

#[async_trait::async_trait]
impl CostCacheTrait for CostCache {
    async fn get_cost_by_message_id(
        &self,
        message_id: String,
        transaction_type: TransactionType,
    ) -> Result<u64, anyhow::Error> {
        let key = format!("cost:{}:{}", transaction_type, message_id);
        let mut conn = self.conn.clone();
        match conn.get::<_, Option<String>>(&key).await {
            Ok(Some(serialized)) => {
                if let Ok(cost) = serialized.parse::<u64>() {
                    debug!("Cost for message_id {} is {}", message_id, cost);
                    return Ok(cost);
                } else {
                    error!(
                        "Failed to parse cost for message_id {}: {}",
                        message_id, serialized
                    );
                    return Err(anyhow::anyhow!(
                        "Failed to parse cost for message_id {}: {}",
                        message_id,
                        serialized
                    ));
                }
            }
            Ok(None) => {
                error!(
                    "Failed to get cost for message_id {}: Key not found in Redis",
                    message_id
                );
                return Err(anyhow::anyhow!(
                    "Failed to get cost for message_id {}: Key not found in Redis",
                    message_id
                ));
            }
            Err(e) => {
                error!(
                    "Failed to get context from Redis for message_id {}: {}",
                    message_id, e
                );
                return Err(anyhow::anyhow!(
                    "Failed to get cost for message_id {}: {}",
                    message_id,
                    e
                ));
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionType {
    #[serde(rename = "execute")]
    Execute,
    #[serde(rename = "approve")]
    Approve,
}

impl Display for TransactionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TransactionType::Execute => "execute",
            TransactionType::Approve => "approve",
        };
        write!(f, "{}", s)
    }
}
