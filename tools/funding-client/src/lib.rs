//! Flashnet regtest funding client.
//!
//! This is a Flashnet-built client used as a faucet to request regtest funds on Spark.

mod config;
use reqwest::Client;
use serde::{Deserialize, Serialize};

pub struct FundingClient {
    client: Client,
}

#[derive(Serialize)]
pub struct FundingTask {
    pub amount_sats: u64,
    pub recipient: String,
}

#[derive(Serialize)]
struct FundingRequest {
    funding_requests: Vec<FundingTask>,
}

#[derive(Debug, Deserialize)]
pub struct FundingResult {
    pub recipient: String,
    pub amount_sent: u64,
    pub txids: Vec<String>,
    pub amm_operation_id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
struct FundingResponse {
    results: Vec<FundingResult>,
}

impl FundingClient {
    pub async fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    pub async fn request_funds(
        &self,
        funding_requests: Vec<FundingTask>,
    ) -> reqwest::Result<Vec<FundingResult>> {
        let response = self
            .client
            .post(format!("{}/api/fund", config::FUNDING_URL))
            .json(&FundingRequest { funding_requests })
            .send()
            .await?
            .error_for_status()?
            .json::<FundingResponse>()
            .await?;

        Ok(response.results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_request_funds() {
        let recipient = "sparkrt1pgssyahw2s9hhzcu3uw3yyq9vfhgwf6fc9l7ahrywngzvngpmst4h2fdcgnktj";
        let amount_sats = 1;

        let tasks = vec![FundingTask {
            amount_sats,
            recipient: recipient.to_string(),
        }];

        let client = FundingClient::new().await;
        let results = client.request_funds(tasks).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].recipient, recipient);
        assert_eq!(results[0].amount_sent, amount_sats);
        assert_eq!(results[0].txids.len(), 1);
        assert!(!results[0].amm_operation_id.is_empty());
        assert!(results[0].status == "PENDING");
    }
}
