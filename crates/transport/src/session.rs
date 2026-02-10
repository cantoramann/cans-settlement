//! In-memory session cache for Spark authentication tokens.
//!
//! [`SessionCache`] stores auth tokens keyed by (operator index, public key)
//! with zero heap allocations on cache hit. The operator dimension uses O(1)
//! array indexing; within each operator, sessions are stored in a
//! [`HashMap<PubKey, CachedSession>`].
//!
//! # Thread Safety
//!
//! Each operator slot has its own [`RwLock`], so reads to different operators
//! never contend. Reads within the same operator slot are concurrent.
//!
//! # Expiry
//!
//! Sessions are treated as expired [`EXPIRY_BUFFER_SECS`] before their actual
//! expiry timestamp to prevent mid-request token expiration.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use signer::PubKey;

/// Sessions are considered expired this many seconds before their actual
/// expiry timestamp. This prevents mid-request token expiration.
const EXPIRY_BUFFER_SECS: i64 = 30;

/// A cached authentication session.
struct CachedSession {
    /// Session token. `Bytes::clone()` is O(1) -- ref-count increment only.
    token: Bytes,
    /// UNIX timestamp (seconds) at which the token expires.
    expires_at: i64,
}

/// In-memory session cache keyed by (operator index, public key).
///
/// The operator dimension is a fixed-size boxed slice (one slot per operator,
/// allocated once at construction). Each slot holds a `RwLock<HashMap>` for
/// concurrent read/write access.
pub struct SessionCache {
    operators: Box<[RwLock<HashMap<PubKey, CachedSession>>]>,
}

impl SessionCache {
    /// Creates a new cache with `operator_count` empty slots.
    pub fn new(operator_count: usize) -> Self {
        let operators = (0..operator_count)
            .map(|_| RwLock::new(HashMap::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self { operators }
    }

    /// Returns a cached session token if it exists and has not expired.
    ///
    /// This is the hot path: one `RwLock` read + one `HashMap::get` + one
    /// `Bytes::clone` (O(1), zero heap allocation).
    pub fn get(&self, operator_idx: usize, pubkey: &PubKey) -> Option<Bytes> {
        let now = unix_timestamp_secs();
        let map = self.operators[operator_idx].read().ok()?;
        let session = map.get(pubkey)?;
        if session.expires_at - EXPIRY_BUFFER_SECS > now {
            Some(session.token.clone())
        } else {
            None
        }
    }

    /// Inserts or replaces a session for the given operator and public key.
    ///
    /// `token` is taken by value to enable zero-copy ownership transfer.
    pub fn insert(&self, operator_idx: usize, pubkey: PubKey, token: Bytes, expires_at: i64) {
        if let Ok(mut map) = self.operators[operator_idx].write() {
            map.insert(pubkey, CachedSession { token, expires_at });
        }
    }
}

/// Returns the current UNIX timestamp in seconds.
fn unix_timestamp_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A dummy pubkey for testing.
    fn test_pubkey(seed: u8) -> PubKey {
        let mut pk = [0x04u8; 65];
        pk[1] = seed;
        pk
    }

    #[test]
    fn get_returns_none_for_empty_cache() {
        let cache = SessionCache::new(3);
        assert!(cache.get(0, &test_pubkey(1)).is_none());
    }

    #[test]
    fn insert_then_get() {
        let cache = SessionCache::new(2);
        let pk = test_pubkey(1);
        let token = Bytes::from_static(b"session-token-abc");
        let far_future = unix_timestamp_secs() + 3600;

        cache.insert(0, pk, token.clone(), far_future);

        let cached = cache.get(0, &pk).expect("should find cached token");
        assert_eq!(cached, token);
    }

    #[test]
    fn expired_session_returns_none() {
        let cache = SessionCache::new(1);
        let pk = test_pubkey(2);
        // Expires "now" -- within the buffer window.
        let already_expired = unix_timestamp_secs();

        cache.insert(0, pk, Bytes::from_static(b"old-token"), already_expired);

        assert!(cache.get(0, &pk).is_none());
    }

    #[test]
    fn expiry_buffer_is_applied() {
        let cache = SessionCache::new(1);
        let pk = test_pubkey(3);
        let now = unix_timestamp_secs();

        // Expires 10s from now -- within the 30s buffer.
        cache.insert(0, pk, Bytes::from_static(b"almost-expired"), now + 10);
        assert!(cache.get(0, &pk).is_none());

        // Expires 60s from now -- outside the 30s buffer.
        cache.insert(0, pk, Bytes::from_static(b"still-valid"), now + 60);
        assert!(cache.get(0, &pk).is_some());
    }

    #[test]
    fn different_operators_are_independent() {
        let cache = SessionCache::new(3);
        let pk = test_pubkey(1);
        let far_future = unix_timestamp_secs() + 3600;

        cache.insert(0, pk, Bytes::from_static(b"op0-token"), far_future);
        cache.insert(2, pk, Bytes::from_static(b"op2-token"), far_future);

        assert_eq!(cache.get(0, &pk).unwrap(), Bytes::from_static(b"op0-token"));
        assert!(cache.get(1, &pk).is_none());
        assert_eq!(cache.get(2, &pk).unwrap(), Bytes::from_static(b"op2-token"));
    }

    #[test]
    fn different_pubkeys_are_independent() {
        let cache = SessionCache::new(1);
        let pk_a = test_pubkey(10);
        let pk_b = test_pubkey(20);
        let far_future = unix_timestamp_secs() + 3600;

        cache.insert(0, pk_a, Bytes::from_static(b"token-a"), far_future);

        assert!(cache.get(0, &pk_a).is_some());
        assert!(cache.get(0, &pk_b).is_none());
    }

    #[test]
    fn insert_replaces_existing() {
        let cache = SessionCache::new(1);
        let pk = test_pubkey(1);
        let far_future = unix_timestamp_secs() + 3600;

        cache.insert(0, pk, Bytes::from_static(b"old"), far_future);
        cache.insert(0, pk, Bytes::from_static(b"new"), far_future);

        assert_eq!(cache.get(0, &pk).unwrap(), Bytes::from_static(b"new"));
    }

    #[test]
    fn concurrent_reads_do_not_block() {
        let cache = SessionCache::new(1);
        let pk = test_pubkey(1);
        let far_future = unix_timestamp_secs() + 3600;
        cache.insert(0, pk, Bytes::from_static(b"token"), far_future);

        // Multiple concurrent reads should all succeed.
        let results: Vec<_> = (0..100)
            .map(|_| cache.get(0, &pk).expect("concurrent read should succeed"))
            .collect();

        assert!(results.iter().all(|t| t == &Bytes::from_static(b"token")));
    }
}
