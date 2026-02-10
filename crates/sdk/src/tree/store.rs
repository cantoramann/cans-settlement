//! Tree store trait and domain types.

use crate::SdkError;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Unique identifier for a leaf reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReservationId(pub u64);

/// A Spark tree node (leaf) representing a BTC UTXO.
///
/// Fields match the Spark protocol's `TreeNode` message. Byte arrays
/// are used instead of proto-generated types to keep the SDK independent
/// of the transport layer's generated code.
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Unique node identifier (UUID bytes or string).
    pub id: String,

    /// Tree identifier.
    pub tree_id: String,

    /// Value in satoshis.
    pub value: u64,

    /// Serialized node transaction (raw Bitcoin tx).
    pub node_tx: Vec<u8>,

    /// Serialized refund transaction.
    pub refund_tx: Option<Vec<u8>>,

    /// The group's aggregate verifying public key (33 bytes, compressed).
    pub verifying_public_key: [u8; 33],

    /// Owner's identity public key (33 bytes, compressed).
    pub owner_identity_public_key: [u8; 33],

    /// Signing keyshare information for this leaf.
    pub signing_keyshare: SigningKeyshare,

    /// Output index in the node transaction.
    pub vout: u32,
}

/// Signing keyshare for a tree node.
#[derive(Debug, Clone)]
pub struct SigningKeyshare {
    /// The operator's public key share for this leaf (33 bytes, compressed).
    pub operator_public_key: [u8; 33],

    /// The owner's signing public key for this leaf (33 bytes, compressed).
    pub owner_public_key: [u8; 33],
}

/// A set of reserved leaves with their reservation ID.
#[derive(Debug)]
pub struct LeafReservation {
    /// Reservation identifier (used to finalize or cancel).
    pub id: ReservationId,

    /// The reserved leaves.
    pub leaves: Vec<TreeNode>,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Storage for BTC leaf tree nodes.
///
/// Implementations manage the lifecycle of leaves: insertion when received
/// or claimed, reservation during transfers, and removal when spent.
pub trait TreeStore: Send + Sync {
    /// Insert new leaves (e.g., after claiming a transfer or deposit).
    fn insert_leaves(&self, leaves: &[TreeNode]) -> Result<(), SdkError>;

    /// Remove leaves by ID (e.g., after spending).
    fn remove_leaves(&self, leaf_ids: &[&str]) -> Result<(), SdkError>;

    /// Get all available (non-reserved) leaves.
    fn get_available_leaves(&self) -> Result<Vec<TreeNode>, SdkError>;

    /// Reserve a set of leaves by ID for an operation.
    ///
    /// Reserved leaves are excluded from balance and selection until
    /// the reservation is finalized or cancelled.
    fn reserve_leaves(&self, leaf_ids: &[&str]) -> Result<LeafReservation, SdkError>;

    /// Finalize a reservation: remove the reserved leaves and optionally
    /// insert replacement leaves (e.g., change outputs).
    fn finalize_reservation(
        &self,
        id: ReservationId,
        new_leaves: Option<&[TreeNode]>,
    ) -> Result<(), SdkError>;

    /// Cancel a reservation, returning leaves to available state.
    fn cancel_reservation(&self, id: ReservationId) -> Result<(), SdkError>;

    /// Total value of available (non-reserved) leaves in satoshis.
    fn available_balance(&self) -> Result<u64, SdkError>;
}
