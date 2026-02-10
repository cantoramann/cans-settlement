//! Spark Service Provider (SSP) configuration.
//!
//! The SSP provides additional services on top of the Spark protocol:
//! - Lightning Network integration (send/receive)
//! - Cooperative exits (on-chain withdrawals)
//! - Static deposit claims
//! - Leaf swaps for optimization
//!
//! All configurations are compile-time constants (`&'static str` fields).
//! Zero heap allocations.
//!
//! # Security
//!
//! SSP endpoints handle financial operations. Production deployments must:
//! - Verify the SSP identity public key against official documentation
//! - Use TLS for all API communication
//! - Implement request signing for authentication
//!
//! # Warning
//!
//! The [`SspConfig::REGTEST`] configuration includes **hardcoded test credentials**
//! that are publicly known. These credentials are **NOT** suitable for production use
//! and should only be used for local development and testing.

/// Configuration for a Spark Service Provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SspConfig {
    /// Base URL for the SSP GraphQL API.
    pub base_url: &'static str,

    /// GraphQL schema endpoint path.
    pub schema_endpoint: &'static str,

    /// Identity public key of the SSP (33-byte compressed, hex-encoded).
    pub identity_public_key: &'static str,

    /// Electrs/Esplora API URL for chain data.
    pub electrs_url: &'static str,

    /// Optional authentication credentials for Electrs.
    pub electrs_auth: Option<ElectrsAuth>,
}

/// Basic authentication credentials for Electrs API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElectrsAuth {
    pub username: &'static str,
    pub password: &'static str,
}

impl SspConfig {
    /// Mainnet SSP configuration (Lightspark).
    pub const MAINNET: Self = Self {
        base_url: "https://api.lightspark.com",
        schema_endpoint: "graphql/spark/2025-03-19",
        identity_public_key: "023e33e2920326f64ea31058d44777442d97d7d5cbfcf54e3060bc1695e5261c93",
        electrs_url: "https://mempool.space/api",
        electrs_auth: None,
    };

    /// Regtest SSP configuration.
    pub const REGTEST: Self = Self {
        base_url: "https://api.lightspark.com",
        schema_endpoint: "graphql/spark/rc",
        identity_public_key: "022bf283544b16c0622daecb79422007d167eca6ce9f0c98c0c49833b1f7170bfe",
        electrs_url: "https://regtest-mempool.us-west-2.sparkinfra.net/api",
        electrs_auth: Some(ElectrsAuth {
            username: "spark-sdk",
            password: "mCMk1JqlBNtetUNy",
        }),
    };

    /// Local development SSP configuration.
    pub const LOCAL: Self = Self {
        base_url: "http://127.0.0.1:5000",
        schema_endpoint: "graphql/spark/rc",
        identity_public_key: "028c094a432d46a0ac95349d792c2e3730bd60c29188db716f56a99e39b95338b4",
        electrs_url: "http://127.0.0.1:30000",
        electrs_auth: None,
    };

    /// Dev regtest SSP configuration (remote dev environment).
    ///
    /// Connects to the Spark dev environment at `sparkinfra.net`.
    /// Use for integration testing against real operators.
    pub const DEV_REGTEST: Self = Self {
        base_url: "https://api.dev.dev.sparkinfra.net",
        schema_endpoint: "graphql/spark/rc",
        identity_public_key: "028c094a432d46a0ac95349d792c2e3730bd60c29188db716f56a99e39b95338b4",
        electrs_url: "https://regtest-mempool.dev.dev.sparkinfra.net/api",
        electrs_auth: Some(ElectrsAuth {
            username: "spark-sdk",
            password: "mCMk1JqlBNtetUNy",
        }),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_ssp_uses_https() {
        assert!(SspConfig::MAINNET.base_url.starts_with("https://"));
        assert!(SspConfig::MAINNET.electrs_auth.is_none());
    }

    #[test]
    fn regtest_ssp_has_auth() {
        assert!(SspConfig::REGTEST.electrs_auth.is_some());
    }

    #[test]
    fn ssp_configs_are_copy() {
        let a = SspConfig::MAINNET;
        let b = a; // Copy
        assert_eq!(a, b);
    }
}
