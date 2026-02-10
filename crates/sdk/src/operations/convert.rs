//! Shared proto-to-SDK type conversions.
//!
//! Centralizes conversion from transport-layer protobuf types to the
//! SDK's domain types, avoiding duplication across operation modules.

use transport::spark;

use crate::tree::{SigningKeyshare, TreeNode};

/// Converts a proto `TreeNode` to the SDK's `TreeNode`.
///
/// Returns `None` if required fields (verifying key or owner key) are
/// missing or not exactly 33 bytes.
pub fn proto_to_tree_node(node: &spark::TreeNode) -> Option<TreeNode> {
    let verifying_public_key: [u8; 33] = node.verifying_public_key.as_ref().try_into().ok()?;
    let owner_identity_public_key: [u8; 33] =
        node.owner_identity_public_key.as_ref().try_into().ok()?;

    // Extract the operator's public key from the proto SigningKeyshare.
    // The `public_key` field is the aggregate group key (33 bytes compressed).
    let operator_public_key = node
        .signing_keyshare
        .as_ref()
        .and_then(|ks| ks.public_key.as_ref().try_into().ok())
        .unwrap_or([0u8; 33]);

    Some(TreeNode {
        id: node.id.clone(),
        tree_id: node.tree_id.clone(),
        value: node.value,
        node_tx: node.node_tx.to_vec(),
        refund_tx: if node.refund_tx.is_empty() {
            None
        } else {
            Some(node.refund_tx.to_vec())
        },
        verifying_public_key,
        owner_identity_public_key,
        signing_keyshare: SigningKeyshare {
            operator_public_key,
            owner_public_key: owner_identity_public_key,
        },
        vout: node.vout,
    })
}
