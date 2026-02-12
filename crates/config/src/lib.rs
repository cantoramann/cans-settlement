//! Spark network configuration.
//!
//! This crate provides static, per-network configuration for the Spark SDK:
//!
//! - [`NetworkConfig`] -- operators, SSP, and FROST threshold for a given network
//! - [`OperatorInfo`] -- information about a single signing operator
//! - [`SspConfig`] -- Spark Service Provider endpoints and credentials
//! - [`constants`] -- protocol-level parameters (timelocks, sequence flags, timeouts)
//!
//! All data is compile-time constant (`&'static str`, `&'static [OperatorInfo]`).
//! Zero heap allocations. Types are `Copy`.
//!
//! `config` depends only on [`sdk_core::Network`]. It does **not** depend on
//! transport, crypto, or any runtime crate, so it can be used freely as a
//! leaf dependency.

pub mod constants;
pub mod operators;
pub mod ssp;

pub use operators::OperatorInfo;
pub use ssp::{ElectrsAuth, SspConfig};

use operators::{INTERNAL_DEV_OPERATORS, MAINNET_OPERATORS, REGTEST_OPERATORS};
use sdk_core::Network;

// ---------------------------------------------------------------------------
// NetworkConfig
// ---------------------------------------------------------------------------

/// Network-specific configuration containing operators and SSP info.
///
/// This is `Copy` -- just pointers to static data and a few scalars.
/// The coordinator is identified by index into the operators slice,
/// guaranteeing exactly one coordinator at the type level.
#[derive(Debug, Clone, Copy)]
pub struct NetworkConfig {
    /// The network this configuration is for.
    pub network: Network,

    /// Signing operators for this network.
    operators: &'static [OperatorInfo],

    /// Index into `operators` identifying the coordinator.
    coordinator_index: usize,

    /// Spark Service Provider configuration.
    pub ssp: SspConfig,

    /// FROST signing threshold (t of n).
    pub threshold: usize,

    /// Optional Sparkscan API base URL for transfer validation.
    ///
    /// When set (and the `sparkscan-validation` feature is enabled in the
    /// SDK), the SDK can cross-check transfer data against the Sparkscan
    /// block explorer before claiming.
    ///
    /// Defaults to `None` (validation disabled). Set to
    /// `Some("https://api.sparkscan.io/v1")` to enable.
    pub sparkscan_url: Option<&'static str>,
}

impl NetworkConfig {
    /// Get the configuration for a specific network.
    pub const fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::MAINNET,
            Network::Regtest => Self::REGTEST,
        }
    }

    /// Returns the list of operators.
    pub const fn operators(&self) -> &'static [OperatorInfo] {
        self.operators
    }

    /// Returns the number of operators.
    pub const fn num_operators(&self) -> usize {
        self.operators.len()
    }

    /// Returns the coordinator operator. O(1) index lookup.
    pub const fn coordinator(&self) -> &'static OperatorInfo {
        &self.operators[self.coordinator_index]
    }

    /// Returns the Sparkscan API base URL, if configured.
    pub const fn sparkscan_url(&self) -> Option<&'static str> {
        self.sparkscan_url
    }

    // -----------------------------------------------------------------------
    // Built-in network configurations
    // -----------------------------------------------------------------------

    /// Production mainnet configuration.
    pub const MAINNET: Self = Self {
        network: Network::Mainnet,
        operators: &MAINNET_OPERATORS,
        coordinator_index: 0,
        ssp: SspConfig::MAINNET,
        threshold: 2,
        sparkscan_url: None,
    };

    /// Local regtest configuration.
    pub const REGTEST: Self = Self {
        network: Network::Regtest,
        operators: &REGTEST_OPERATORS,
        coordinator_index: 0,
        ssp: SspConfig::REGTEST,
        threshold: 3,
        sparkscan_url: None,
    };

    /// Public regtest configuration.
    ///
    /// Connects to the same operators as mainnet but uses `Network::Regtest`
    /// in queries. Matches the official JS SDK configuration.
    pub const DEV_REGTEST: Self = Self {
        network: Network::Regtest,
        operators: &MAINNET_OPERATORS,
        coordinator_index: 0,
        ssp: SspConfig::REGTEST,
        threshold: 2,
        sparkscan_url: None,
    };

    /// Internal dev regtest configuration (sparkinfra.net).
    ///
    /// Connects to the internal Spark dev environment.
    /// Use for integration testing only -- not compatible with the public Spark app.
    pub const INTERNAL_DEV_REGTEST: Self = Self {
        network: Network::Regtest,
        operators: &INTERNAL_DEV_OPERATORS,
        coordinator_index: 0,
        ssp: SspConfig::DEV_REGTEST,
        threshold: 2,
        sparkscan_url: None,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_config() {
        let config = NetworkConfig::for_network(Network::Mainnet);
        assert_eq!(config.num_operators(), 3);
        assert_eq!(config.threshold, 2);
        assert_eq!(
            config.coordinator().address,
            "https://0.spark.lightspark.com"
        );
    }

    #[test]
    fn regtest_config() {
        let config = NetworkConfig::for_network(Network::Regtest);
        assert_eq!(config.num_operators(), 5);
        assert_eq!(config.threshold, 3);
    }

    #[test]
    fn coordinator_is_in_operators_slice() {
        for config in [NetworkConfig::MAINNET, NetworkConfig::REGTEST] {
            let coord = config.coordinator();
            assert!(
                config.operators().contains(coord),
                "{:?} coordinator must be in operators slice",
                config.network
            );
        }
    }

    #[test]
    fn operator_addresses_are_https() {
        for network in [Network::Mainnet, Network::Regtest] {
            let config = NetworkConfig::for_network(network);
            for op in config.operators() {
                assert!(
                    op.address.starts_with("https://"),
                    "operator {} should use HTTPS",
                    op.id
                );
            }
        }
    }

    #[test]
    fn dev_regtest_uses_mainnet_operators() {
        let config = NetworkConfig::DEV_REGTEST;
        assert_eq!(config.num_operators(), 3);
        assert_eq!(config.threshold, 2);
        assert_eq!(config.network, Network::Regtest);
        assert_eq!(
            config.coordinator().address,
            "https://0.spark.lightspark.com"
        );
    }

    #[test]
    fn internal_dev_regtest() {
        let config = NetworkConfig::INTERNAL_DEV_REGTEST;
        assert_eq!(config.num_operators(), 3);
        assert_eq!(config.threshold, 2);
        assert!(
            config.coordinator().address.contains("sparkinfra.net"),
            "internal dev should point to sparkinfra.net"
        );
    }

    #[test]
    fn configs_are_copy() {
        let a = NetworkConfig::MAINNET;
        let b = a;
        assert_eq!(a.num_operators(), b.num_operators());
    }

    #[test]
    fn const_fn_works_at_compile_time() {
        const CONFIG: NetworkConfig = NetworkConfig::for_network(Network::Mainnet);
        assert_eq!(CONFIG.num_operators(), 3);
    }
}
