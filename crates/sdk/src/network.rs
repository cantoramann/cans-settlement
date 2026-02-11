//! Network helpers: map SDK network to proto and Bitcoin network.
//!
//! Shared by claim, transfer, and other operations that need to pass
//! a network identifier to the transport or build Bitcoin transactions.

use sdk_core::Network;

/// Map `sdk_core::Network` to the proto `Network` enum value.
#[inline]
pub fn spark_network_proto(network: Network) -> i32 {
    match network {
        Network::Mainnet => 1,
        Network::Regtest => 2,
    }
}

/// Map `sdk_core::Network` to `bitcoin::Network`.
#[inline]
pub fn bitcoin_network(network: Network) -> bitcoin::Network {
    match network {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Regtest => bitcoin::Network::Regtest,
    }
}
