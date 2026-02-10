//! Spark operator definitions and static per-network tables.
//!
//! Operators are the signing entities in the Spark network. Each operator
//! holds a share of the threshold signing key and participates in
//! multi-party signing for transactions.
//!
//! All data is compile-time constant. Zero heap allocations.

// ---------------------------------------------------------------------------
// OperatorInfo
// ---------------------------------------------------------------------------

/// Information about a single Spark signing operator.
///
/// All fields are `&'static str` -- no heap allocations.
/// Whether an operator is the coordinator is a network-level property,
/// not an operator-level one -- see [`crate::NetworkConfig::coordinator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorInfo {
    /// Numeric index of the operator (0-based).
    pub index: u32,

    /// Unique identifier (64-char hex string, 32 bytes).
    pub id: &'static str,

    /// gRPC endpoint URL (e.g. `https://0.spark.lightspark.com`).
    pub address: &'static str,

    /// Identity public key (33-byte compressed, hex-encoded).
    pub identity_public_key: &'static str,
}

// ---------------------------------------------------------------------------
// Operator tables (compile-time constants in .rodata)
// ---------------------------------------------------------------------------

pub(crate) const MAINNET_OPERATORS: [OperatorInfo; 3] = [
    OperatorInfo {
        index: 0,
        id: "0000000000000000000000000000000000000000000000000000000000000001",
        address: "https://0.spark.lightspark.com",
        identity_public_key: "03dfbdff4b6332c220f8fa2ba8ed496c698ceada563fa01b67d9983bfc5c95e763",
    },
    OperatorInfo {
        index: 1,
        id: "0000000000000000000000000000000000000000000000000000000000000002",
        address: "https://1.spark.lightspark.com",
        identity_public_key: "03e625e9768651c9be268e287245cc33f96a68ce9141b0b4769205db027ee8ed77",
    },
    OperatorInfo {
        index: 2,
        id: "0000000000000000000000000000000000000000000000000000000000000003",
        address: "https://2.spark.flashnet.xyz",
        identity_public_key: "022eda13465a59205413086130a65dc0ed1b8f8e51937043161f8be0c369b1a410",
    },
];

pub(crate) const REGTEST_OPERATORS: [OperatorInfo; 5] = [
    OperatorInfo {
        index: 0,
        id: "0000000000000000000000000000000000000000000000000000000000000001",
        address: "https://localhost:8535",
        identity_public_key: "0322ca18fc489ae25418a0e768273c2c61cabb823edfb14feb891e9bec62016510",
    },
    OperatorInfo {
        index: 1,
        id: "0000000000000000000000000000000000000000000000000000000000000002",
        address: "https://localhost:8536",
        identity_public_key: "0341727a6c41b168f07eb50865ab8c397a53c7eef628ac1020956b705e43b6cb27",
    },
    OperatorInfo {
        index: 2,
        id: "0000000000000000000000000000000000000000000000000000000000000003",
        address: "https://localhost:8537",
        identity_public_key: "0305ab8d485cc752394de4981f8a5ae004f2becfea6f432c9a59d5022d8764f0a6",
    },
    OperatorInfo {
        index: 3,
        id: "0000000000000000000000000000000000000000000000000000000000000004",
        address: "https://localhost:8538",
        identity_public_key: "0352aef4d49439dedd798ac4aef1e7ebef95f569545b647a25338398c1247ffdea",
    },
    OperatorInfo {
        index: 4,
        id: "0000000000000000000000000000000000000000000000000000000000000005",
        address: "https://localhost:8539",
        identity_public_key: "02c05c88cc8fc181b1ba30006df6a4b0597de6490e24514fbdd0266d2b9cd3d0ba",
    },
];

pub(crate) const INTERNAL_DEV_OPERATORS: [OperatorInfo; 3] = [
    OperatorInfo {
        index: 0,
        id: "0000000000000000000000000000000000000000000000000000000000000001",
        address: "https://0.spark.dev.dev.sparkinfra.net",
        identity_public_key: "03acd9a5a88db102730ff83dee69d69088cc4c9d93bbee893e90fd5051b7da9651",
    },
    OperatorInfo {
        index: 1,
        id: "0000000000000000000000000000000000000000000000000000000000000002",
        address: "https://1.spark.dev.dev.sparkinfra.net",
        identity_public_key: "02d2d103cacb1d6355efeab27637c74484e2a7459e49110c3fe885210369782e23",
    },
    OperatorInfo {
        index: 2,
        id: "0000000000000000000000000000000000000000000000000000000000000003",
        address: "https://2.spark.dev.dev.sparkinfra.net",
        identity_public_key: "0350f07ffc21bfd59d31e0a7a600e2995273938444447cb9bc4c75b8a895dbb853",
    },
];
