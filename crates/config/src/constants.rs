//! Spark protocol constants.
//!
//! These constants define protocol parameters for timelocks, fees, and other
//! protocol-level configuration.

/// Initial timelock for new leaves (in blocks).
pub const INITIAL_TIMELOCK: u16 = 2000;

/// Timelock decrement interval (in blocks).
///
/// Each renewal reduces the timelock by this amount.
pub const TIMELOCK_INTERVAL: u16 = 100;

/// Offset for direct (non-CPFP) transaction timelocks.
pub const DIRECT_TIMELOCK_OFFSET: u16 = 50;

/// Offset for HTLC transaction timelocks.
pub const HTLC_TIMELOCK_OFFSET: u16 = 70;

/// Offset for direct HTLC transaction timelocks.
pub const DIRECT_HTLC_TIMELOCK_OFFSET: u16 = 85;

/// Spark sequence flag (bit 30).
///
/// This flag is set in transaction sequence numbers to identify
/// Spark protocol transactions.
pub const SPARK_SEQUENCE_FLAG: u32 = 1 << 30;

/// Mask for extracting the timelock value from a sequence number.
pub const TIMELOCK_MASK: u32 = 0x0000_FFFF;

/// Default connection timeout in milliseconds.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;

/// Default request timeout in milliseconds.
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;

/// Maximum message size for gRPC (50 MiB).
pub const MAX_GRPC_MESSAGE_SIZE: usize = 50 * 1024 * 1024;

/// Default expected withdraw bond in satoshis.
pub const DEFAULT_WITHDRAW_BOND_SATS: u64 = 10_000;

/// Default expected relative block locktime for withdrawals.
pub const DEFAULT_WITHDRAW_RELATIVE_LOCKTIME: u64 = 1_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timelock_math() {
        // Verify initial timelock can be decremented 20 times
        let mut timelock = INITIAL_TIMELOCK;
        for _ in 0..20 {
            timelock = timelock
                .checked_sub(TIMELOCK_INTERVAL)
                .expect("should not underflow");
        }
        assert_eq!(timelock, 0);
    }

    #[test]
    fn test_spark_sequence_flag() {
        // Verify the flag is in the upper bits
        assert_eq!(SPARK_SEQUENCE_FLAG, 0x4000_0000);
    }
}
