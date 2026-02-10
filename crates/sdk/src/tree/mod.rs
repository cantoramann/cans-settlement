//! BTC leaf tree management.
//!
//! Manages the set of Spark tree nodes (leaves) that represent Bitcoin
//! UTXOs controlled by threshold FROST keys shared with operators.

mod memory;
mod selection;
mod store;

pub use memory::InMemoryTreeStore;
pub use selection::select_leaves_greedy;
pub use store::{LeafReservation, ReservationId, SigningKeyshare, TreeNode, TreeStore};
