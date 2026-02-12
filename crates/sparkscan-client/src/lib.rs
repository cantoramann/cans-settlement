// //! Functional utilities for interacting with the Sparkscan API

// use bitcoin::Network;
// use reqwest::StatusCode;
// use serde::Deserialize;
// use spark_transfer_id::SparkTransferId;
// use tracing::{debug, error};

// const DEFAULT_BASE_URL: &str = "https://api.sparkscan.io/v1";

// /// Network to query Sparkscan for
// #[derive(Debug, Clone)]
// pub enum SparkscanQueryNetwork {
//     /// Mainnet
//     Mainnet,
//     /// Regtest
//     Regtest,
// }

// impl SparkscanQueryNetwork {
//     /// Convert the network to a Bitcoin network
//     pub fn to_bitcoin_network(&self) -> Network {
//         match self {
//             SparkscanQueryNetwork::Mainnet => Network::Bitcoin,
//             SparkscanQueryNetwork::Regtest => Network::Regtest,
//         }
//     }
// }

// impl ToString for SparkscanQueryNetwork {
//     fn to_string(&self) -> String {
//         match self {
//             SparkscanQueryNetwork::Mainnet => "MAINNET".to_string(),
//             SparkscanQueryNetwork::Regtest => "REGTEST".to_string(),
//         }
//     }
// }

// impl From<Network> for SparkscanQueryNetwork {
//     fn from(network: Network) -> Self {
//         match network {
//             Network::Bitcoin => SparkscanQueryNetwork::Mainnet,
//             Network::Regtest => SparkscanQueryNetwork::Regtest,
//             _ => SparkscanQueryNetwork::Regtest,
//         }
//     }
// }

// /// Fetch the transfer data from Sparkscan
// #[cfg_attr(feature = "instrumentation", tracing::instrument(skip_all,
//     fields(
//         transfer_id = %spark_transfer_id,
//         network = %network.to_string(),
//     )))]
// pub async fn fetch_transfer_from_sparkscan(
//     spark_transfer_id: SparkTransferId,
//     network: SparkscanQueryNetwork,
//     base_url: Option<&str>,
//     api_key: Option<&str>,
// ) -> Result<SparkscanGetTransferResponse, SparkscanError> {
//     let base_url = base_url.unwrap_or(DEFAULT_BASE_URL);
//     let url: String = format!(
//         "{}/tx/{}?network={}",
//         base_url,
//         spark_transfer_id,
//         network.to_string()
//     );

//     let client = reqwest::Client::new();

//     debug!(
//         url = %url,
//         network = %network.to_string(),
//         "sparkscan_fetch_start"
//     );

//     let mut request_builder = client.get(url);

//     // Add Authorization header if API key is provided
//     if let Some(key) = api_key {
//         request_builder = request_builder.header("Authorization", format!("Bearer {}", key));
//     }

//     let response = request_builder.send().await.map_err(|e| {
//         error!(error = %e, "sparkscan_http_send_error");
//         SparkscanError::ApiError {
//             status: e.status(),
//             body: e.to_string(),
//         }
//     })?;

//     if !response.status().is_success() {
//         let status = response.status();
//         let body = response.text().await.unwrap_or_default();
//         error!(
//             status = %status,
//             body = %body,
//             "Sparkscan API error: fetch {} is not successful",
//             spark_transfer_id
//         );
//         return Err(SparkscanError::ApiError {
//             status: Some(status),
//             body,
//         });
//     }

//     let status = response.status();
//     let response_body = response
//         .json::<SparkscanGetTransferResponse>()
//         .await
//         .map_err(|e| {
//             error!(status = %status, error = %e, "sparkscan_json_parse_error");
//             SparkscanError::ParseError {
//                 status,
//                 body: e.to_string(),
//             }
//         })?;

//     Ok(response_body)
// }

// #[derive(Debug, Deserialize)]
// #[allow(missing_docs)]
// pub struct SparkscanGetTransferResponse {
//     pub id: String,
//     #[serde(rename = "type")]
//     pub transfer_type: String,
//     pub status: String,
//     #[serde(rename = "createdAt")]
//     pub created_at: String,
//     #[serde(rename = "updatedAt")]
//     pub updated_at: String,
//     pub from: Option<SparkscanParty>,
//     pub to: Option<SparkscanParty>,
//     pub amount: Option<u128>,
//     #[serde(rename = "amountSats")]
//     pub amount_sats: Option<u128>,
//     #[serde(rename = "valueUsd")]
//     pub value_usd: Option<f64>,
//     #[serde(rename = "tokenMetadata")]
//     pub token_metadata: Option<SparkscanTokenMetadata>,
//     #[serde(rename = "multiIoDetails")]
//     pub multi_io_details: Option<SparkscanMultiIoDetails>,
// }

// #[derive(Debug, Deserialize)]
// #[allow(missing_docs)]
// pub struct SparkscanParty {
//     #[serde(rename = "type")]
//     pub party_type: String,
//     pub identifier: String,
//     pub pubkey: String,
// }

// #[derive(Debug, Deserialize)]
// #[allow(missing_docs)]
// pub struct SparkscanIo {
//     pub address: String,
//     pub pubkey: String,
//     pub amount: u128,
// }

// #[derive(Debug, Deserialize)]
// #[allow(missing_docs)]
// pub struct SparkscanMultiIoDetails {
//     pub inputs: Vec<SparkscanIo>,
//     pub outputs: Vec<SparkscanIo>,
//     #[serde(rename = "totalInputAmount")]
//     pub total_input_amount: u128,
//     #[serde(rename = "totalOutputAmount")]
//     pub total_output_amount: u128,
// }

// #[derive(Debug, Deserialize)]
// #[allow(missing_docs)]
// pub struct SparkscanTokenMetadata {
//     #[serde(rename = "tokenIdentifier")]
//     pub token_identifier: String,
//     #[serde(rename = "tokenAddress")]
//     pub token_address: String,
//     pub name: String,
//     pub ticker: String,
//     pub decimals: u8,
//     #[serde(rename = "issuerPublicKey")]
//     pub issuer_public_key: String,
//     #[serde(rename = "maxSupply")]
//     pub max_supply: u128,
//     #[serde(rename = "isFreezable")]
//     pub is_freezable: bool,
// }

// /// Errors that can occur when interacting with the Sparkscan API
// #[derive(Debug, thiserror::Error)]
// pub enum SparkscanError {
//     /// An error occurred while interacting with the Sparkscan API
//     #[error("Sparkscan API error: status={:?} body={}", status, body)]
//     ApiError {
//         /// The status code of the response
//         status: Option<StatusCode>,
//         /// The body of the response
//         body: String,
//     },

//     /// Unauthorized access to the Sparkscan API
//     #[error("Unauthorized access to the Sparkscan API")]
//     Unauthorized,

//     /// An error occurred while parsing the response from the Sparkscan API
//     #[error("Sparkscan API error: status={} body={}", status, body)]
//     ParseError {
//         /// The status code of the response
//         status: StatusCode,
//         /// The body of the response
//         body: String,
//     },
// }

// #[cfg(test)]
// mod tests {

//     use std::str::FromStr;

//     use futures::future::join_all;

//     use super::*;

//     const TOKEN_TRANSFER_MAINNET: &str =
//         "696d419cac75150c46a3466c304e1a45588538a00e657a1a0e2415ee99987112";
//     const TOKEN_TRANSFER_REGTEST: &str =
//         "1c2784446e3741b9b8105f52b4b432f84295fd92f84c9e2277b65f898f2757db";
//     const SATS_TRANSFER_MAINNET: &str = "0198b60e-d0a2-7019-8e3a-8b29b321a5bb";
//     const SATS_TRANSFER_REGTEST: &str = "0198b5f2-6b72-71e6-8d90-bdfd5bd64c5b";

//     #[tokio::test]
//     async fn test_sparkscan_txid_queries_sequential() {
//         // let token = &std::env::var("SPARKSCAN_TOKEN").expect("SPARKSCAN_TOKEN is not set");

//         // fetch token transfer on mainnet
//         let mainnet_token_transfer_id = SparkTransferId::from_str(TOKEN_TRANSFER_MAINNET).unwrap();

//         let mainnet_token_transfer = fetch_transfer_from_sparkscan(
//             mainnet_token_transfer_id,
//             SparkscanQueryNetwork::Mainnet,
//             None,
//             None,
//         )
//         .await;

//         // fetch token transfer on regtest
//         let regtest_token_transfer_id = SparkTransferId::from_str(TOKEN_TRANSFER_REGTEST).unwrap();
//         let regtest_token_transfer = fetch_transfer_from_sparkscan(
//             regtest_token_transfer_id,
//             SparkscanQueryNetwork::Regtest,
//             None,
//             None,
//         )
//         .await;

//         // fetch sats transfer on mainnet
//         let mainnet_sats_transfer_id = SparkTransferId::from_str(SATS_TRANSFER_MAINNET).unwrap();
//         let mainnet_sats_transfer = fetch_transfer_from_sparkscan(
//             mainnet_sats_transfer_id,
//             SparkscanQueryNetwork::Mainnet,
//             None,
//             None,
//         )
//         .await;

//         // fetch sats transfer on regtest
//         let regtest_sats_transfer_id = SparkTransferId::from_str(SATS_TRANSFER_REGTEST).unwrap();
//         let regtest_sats_transfer = fetch_transfer_from_sparkscan(
//             regtest_sats_transfer_id,
//             SparkscanQueryNetwork::Regtest,
//             None,
//             None,
//         )
//         .await;

//         println!("{:?}", mainnet_token_transfer);
//         println!("{:?}", regtest_token_transfer);

//         println!("{:?}", mainnet_sats_transfer);
//         println!("{:?}", regtest_sats_transfer);
//     }

//     #[tokio::test]
//     async fn test_sparkscan_txid_queries_parallel() {
//         let mainnet_token_transfer_id = SparkTransferId::from_str(TOKEN_TRANSFER_MAINNET).unwrap();
//         let regtest_token_transfer_id = SparkTransferId::from_str(TOKEN_TRANSFER_REGTEST).unwrap();

//         let mainnet_sats_transfer_id = SparkTransferId::from_str(SATS_TRANSFER_MAINNET).unwrap();
//         let regtest_sats_transfer_id = SparkTransferId::from_str(SATS_TRANSFER_REGTEST).unwrap();

//         let mainnet_token_transfer = fetch_transfer_from_sparkscan(
//             mainnet_token_transfer_id,
//             SparkscanQueryNetwork::Mainnet,
//             None,
//             None,
//         );
//         let regtest_token_transfer = fetch_transfer_from_sparkscan(
//             regtest_token_transfer_id,
//             SparkscanQueryNetwork::Regtest,
//             None,
//             None,
//         );

//         let mainnet_sats_transfer = fetch_transfer_from_sparkscan(
//             mainnet_sats_transfer_id,
//             SparkscanQueryNetwork::Mainnet,
//             None,
//             None,
//         );
//         let regtest_sats_transfer = fetch_transfer_from_sparkscan(
//             regtest_sats_transfer_id,
//             SparkscanQueryNetwork::Regtest,
//             None,
//             None,
//         );

//         let _ = join_all(vec![
//             mainnet_token_transfer,
//             regtest_token_transfer,
//             mainnet_sats_transfer,
//             regtest_sats_transfer,
//         ]);
//     }
// }
