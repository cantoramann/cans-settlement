//! Operation tracking: structured observability for multi-step SDK operations.
//!
//! Every public SDK method creates an [`Operation`] record that captures:
//! - A unique [`OperationId`] for log correlation
//! - The [`OperationKind`] (claim, transfer, swap, etc.)
//! - A sequence of [`StepRecord`]s with timestamps, durations, and outcomes
//! - Final [`OperationStatus`]
//!
//! The [`OperationStore`] trait provides pluggable persistence. The default
//! [`InMemoryOperationStore`] is zero-cost when unused and `DashMap`-backed
//! when active.
//!
//! # Retry
//!
//! [`RetryPolicy`] configures automatic retries for transient errors
//! (gRPC failures, auth token expiry). Non-transient errors surface
//! immediately.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::SdkError;

// ---------------------------------------------------------------------------
// OperationId
// ---------------------------------------------------------------------------

/// Unique identifier for an in-flight operation.
///
/// Monotonically increasing u64 -- cheap to create, copy, and display.
/// Avoids a `uuid` dependency for internal tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationId(u64);

impl OperationId {
    /// Generate the next unique operation ID.
    pub(crate) fn next() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "op-{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// OperationKind
// ---------------------------------------------------------------------------

/// The type of SDK operation being tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperationKind {
    Claim,
    Transfer,
    Swap,
    PayInvoice,
    CreateInvoice,
    CooperativeExit,
    SendToken,
    CreateToken,
    MintToken,
    FreezeTokens,
    Sync,
}

impl fmt::Display for OperationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Claim => write!(f, "claim"),
            Self::Transfer => write!(f, "transfer"),
            Self::Swap => write!(f, "swap"),
            Self::PayInvoice => write!(f, "pay_invoice"),
            Self::CreateInvoice => write!(f, "create_invoice"),
            Self::CooperativeExit => write!(f, "cooperative_exit"),
            Self::SendToken => write!(f, "send_token"),
            Self::CreateToken => write!(f, "create_token"),
            Self::MintToken => write!(f, "mint_token"),
            Self::FreezeTokens => write!(f, "freeze_tokens"),
            Self::Sync => write!(f, "sync"),
        }
    }
}

// ---------------------------------------------------------------------------
// OperationStatus
// ---------------------------------------------------------------------------

/// Final status of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStatus {
    /// The operation is still running.
    InProgress,
    /// All steps succeeded.
    Succeeded,
    /// The operation failed.
    Failed,
    /// Some sub-operations succeeded, others failed (e.g. claim loop).
    PartiallyCompleted,
}

impl fmt::Display for OperationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InProgress => write!(f, "in_progress"),
            Self::Succeeded => write!(f, "succeeded"),
            Self::Failed => write!(f, "failed"),
            Self::PartiallyCompleted => write!(f, "partially_completed"),
        }
    }
}

// ---------------------------------------------------------------------------
// OperationStep
// ---------------------------------------------------------------------------

/// A logical step within an operation.
///
/// Generic steps (`Auth`, `LeafSelection`, etc.) are shared across all
/// operation types. Operation-specific sub-steps use nested variants.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperationStep {
    // -- generic steps --
    /// Operator authentication handshake.
    Auth,
    /// Leaf selection from the tree store.
    LeafSelection,
    /// SSP swap to produce exact-denomination leaves.
    SspSwap,
    /// Leaf reservation in the tree store.
    Reservation,
    /// Cryptographic signing (FROST, ECDSA, ECIES).
    Signing,
    /// gRPC transport call.
    Transport(String),
    /// Leaf/output finalization in the store.
    Finalization,

    // -- claim-specific --
    /// Pre-claim hook execution.
    PreClaimHook,
    /// A single transfer within a multi-transfer claim.
    ClaimSingleTransfer(String),

    // -- transfer-specific --
    /// Building and submitting the transfer package.
    TransferSubmit,

    // -- lightning-specific --
    /// HTLC construction and preimage swap.
    HtlcSubmit,
    /// Preimage share distribution to operators.
    PreimageDistribution,

    // -- token-specific --
    /// Token output acquisition from the store.
    TokenAcquire,
    /// Token transaction broadcast.
    TokenBroadcast,
}

impl fmt::Display for OperationStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth => write!(f, "auth"),
            Self::LeafSelection => write!(f, "leaf_selection"),
            Self::SspSwap => write!(f, "ssp_swap"),
            Self::Reservation => write!(f, "reservation"),
            Self::Signing => write!(f, "signing"),
            Self::Transport(desc) => write!(f, "transport({desc})"),
            Self::Finalization => write!(f, "finalization"),
            Self::PreClaimHook => write!(f, "pre_claim_hook"),
            Self::ClaimSingleTransfer(id) => write!(f, "claim_transfer({id})"),
            Self::TransferSubmit => write!(f, "transfer_submit"),
            Self::HtlcSubmit => write!(f, "htlc_submit"),
            Self::PreimageDistribution => write!(f, "preimage_distribution"),
            Self::TokenAcquire => write!(f, "token_acquire"),
            Self::TokenBroadcast => write!(f, "token_broadcast"),
        }
    }
}

// ---------------------------------------------------------------------------
// StepOutcome
// ---------------------------------------------------------------------------

/// Outcome of a single step execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// Step succeeded on first attempt.
    Ok,
    /// Step succeeded after `count` transient retries.
    Retried(u32),
    /// Step failed with the given error.
    Failed(SdkError),
    /// Step was skipped (e.g. no key tweak needed).
    Skipped,
}

impl fmt::Display for StepOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::Retried(n) => write!(f, "retried({n})"),
            Self::Failed(e) => write!(f, "failed({e})"),
            Self::Skipped => write!(f, "skipped"),
        }
    }
}

// ---------------------------------------------------------------------------
// StepRecord
// ---------------------------------------------------------------------------

/// A timestamped record of a step execution.
#[derive(Debug, Clone)]
pub struct StepRecord {
    /// Which step was executed.
    pub step: OperationStep,
    /// What happened.
    pub outcome: StepOutcome,
    /// When the step started.
    pub timestamp: Instant,
    /// How long it took (if completed).
    pub duration: Option<Duration>,
}

// ---------------------------------------------------------------------------
// Operation
// ---------------------------------------------------------------------------

/// Full record of an SDK operation.
#[derive(Debug, Clone)]
pub struct Operation {
    /// Unique identifier.
    pub id: OperationId,
    /// What kind of operation.
    pub kind: OperationKind,
    /// Current status.
    pub status: OperationStatus,
    /// Ordered list of step records.
    pub steps: Vec<StepRecord>,
    /// When the operation started.
    pub created_at: Instant,
    /// When the operation completed (success, failure, or partial).
    pub completed_at: Option<Instant>,
}

impl Operation {
    /// Create a new in-progress operation.
    pub(crate) fn new(kind: OperationKind) -> Self {
        Self {
            id: OperationId::next(),
            kind,
            status: OperationStatus::InProgress,
            steps: Vec::new(),
            created_at: Instant::now(),
            completed_at: None,
        }
    }

    /// Record a step that completed (with a pre-measured duration).
    pub(crate) fn record(&mut self, step: OperationStep, outcome: StepOutcome, duration: Duration) {
        self.steps.push(StepRecord {
            step,
            outcome,
            timestamp: Instant::now(),
            duration: Some(duration),
        });
    }

    /// Record a step that happened instantaneously or was skipped.
    #[allow(dead_code)]
    pub(crate) fn record_instant(&mut self, step: OperationStep, outcome: StepOutcome) {
        self.steps.push(StepRecord {
            step,
            outcome,
            timestamp: Instant::now(),
            duration: None,
        });
    }

    /// Mark the operation as completed with the given status.
    pub(crate) fn complete(&mut self, status: OperationStatus) {
        self.status = status;
        self.completed_at = Some(Instant::now());
    }

    /// Returns `true` if any step failed.
    pub fn has_failures(&self) -> bool {
        self.steps
            .iter()
            .any(|s| matches!(s.outcome, StepOutcome::Failed(_)))
    }

    /// Returns `true` if any step succeeded.
    pub fn has_successes(&self) -> bool {
        self.steps
            .iter()
            .any(|s| matches!(s.outcome, StepOutcome::Ok | StepOutcome::Retried(_)))
    }
}

// ---------------------------------------------------------------------------
// OperationError
// ---------------------------------------------------------------------------

/// Rich error returned by tracked SDK operations.
///
/// Wraps the base [`SdkError`] with the operation context: which operation
/// failed, at which step, and what had already completed.
#[derive(Debug, Clone)]
pub struct OperationError {
    /// The tracked operation ID.
    pub operation_id: OperationId,
    /// The base SDK error.
    pub error: SdkError,
    /// The step that failed.
    pub failed_step: OperationStep,
    /// Steps that completed before the failure.
    pub completed_steps: Vec<StepRecord>,
}

impl fmt::Display for OperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] operation failed at {}: {}",
            self.operation_id, self.failed_step, self.error
        )
    }
}

impl std::error::Error for OperationError {}

impl From<OperationError> for SdkError {
    fn from(e: OperationError) -> Self {
        e.error
    }
}

// ---------------------------------------------------------------------------
// RetryPolicy
// ---------------------------------------------------------------------------

/// Configuration for automatic retries of transient errors.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of attempts (including the first try).
    pub max_attempts: u32,
    /// Delay before the first retry.
    pub initial_backoff: Duration,
    /// Maximum delay between retries.
    pub max_backoff: Duration,
    /// Multiplier applied to the backoff after each retry.
    pub backoff_multiplier: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(10),
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryPolicy {
    /// A policy that never retries.
    pub const fn no_retry() -> Self {
        Self {
            max_attempts: 1,
            initial_backoff: Duration::from_millis(0),
            max_backoff: Duration::from_millis(0),
            backoff_multiplier: 1.0,
        }
    }

    /// Compute the backoff duration for the given attempt number (0-indexed).
    pub(crate) fn backoff_for(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return self.initial_backoff;
        }
        let factor = self.backoff_multiplier.powi(attempt as i32);
        let ms = (self.initial_backoff.as_millis() as f64 * factor) as u64;
        Duration::from_millis(ms).min(self.max_backoff)
    }
}

// ---------------------------------------------------------------------------
// SdkError::is_transient
// ---------------------------------------------------------------------------

impl SdkError {
    /// Returns `true` if this error is transient and may succeed on retry.
    ///
    /// Transient errors:
    /// - `TransportFailed` -- gRPC call failed (network blip)
    /// - `AuthFailed` -- session token expired, re-auth may fix it
    ///
    /// Everything else is considered persistent (signing bugs, insufficient
    /// balance, invalid responses, hook rejections, etc.).
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::TransportFailed | Self::AuthFailed)
    }
}

// ---------------------------------------------------------------------------
// OperationStore trait
// ---------------------------------------------------------------------------

/// Pluggable storage for operation tracking records.
///
/// The SDK calls into this store at operation start, after each step, and
/// at completion. Implementations may persist to a database for crash
/// recovery or stay in-memory for observability only.
pub trait OperationStore: Send + Sync {
    /// Record a new operation (status = InProgress).
    fn record(&self, op: &Operation);

    /// Retrieve an operation by ID.
    fn get(&self, id: OperationId) -> Option<Operation>;

    /// List all operations that are still in-progress.
    fn list_active(&self) -> Vec<Operation>;

    /// Append a step record to an existing operation.
    fn update_step(&self, id: OperationId, step: StepRecord);

    /// Mark an operation as complete with the given status.
    fn complete(&self, id: OperationId, status: OperationStatus);
}

// ---------------------------------------------------------------------------
// NoopOperationStore
// ---------------------------------------------------------------------------

/// A no-op store that discards all records.
///
/// Used as the default when no tracking is configured. All methods are
/// inlined no-ops, so the compiler can eliminate the overhead entirely.
pub struct NoopOperationStore;

impl OperationStore for NoopOperationStore {
    #[inline]
    fn record(&self, _op: &Operation) {}
    #[inline]
    fn get(&self, _id: OperationId) -> Option<Operation> {
        None
    }
    #[inline]
    fn list_active(&self) -> Vec<Operation> {
        Vec::new()
    }
    #[inline]
    fn update_step(&self, _id: OperationId, _step: StepRecord) {}
    #[inline]
    fn complete(&self, _id: OperationId, _status: OperationStatus) {}
}

// ---------------------------------------------------------------------------
// InMemoryOperationStore
// ---------------------------------------------------------------------------

/// Thread-safe in-memory operation store.
///
/// Uses `RwLock<HashMap>` for concurrent read access with exclusive writes.
/// Operations are lost on process restart.
pub struct InMemoryOperationStore {
    ops: RwLock<HashMap<OperationId, Operation>>,
}

impl InMemoryOperationStore {
    pub fn new() -> Self {
        Self {
            ops: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryOperationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationStore for InMemoryOperationStore {
    fn record(&self, op: &Operation) {
        self.ops.write().unwrap().insert(op.id, op.clone());
    }

    fn get(&self, id: OperationId) -> Option<Operation> {
        self.ops.read().unwrap().get(&id).cloned()
    }

    fn list_active(&self) -> Vec<Operation> {
        self.ops
            .read()
            .unwrap()
            .values()
            .filter(|op| op.status == OperationStatus::InProgress)
            .cloned()
            .collect()
    }

    fn update_step(&self, id: OperationId, step: StepRecord) {
        if let Some(op) = self.ops.write().unwrap().get_mut(&id) {
            op.steps.push(step);
        }
    }

    fn complete(&self, id: OperationId, status: OperationStatus) {
        if let Some(op) = self.ops.write().unwrap().get_mut(&id) {
            op.status = status;
            op.completed_at = Some(Instant::now());
        }
    }
}

// ---------------------------------------------------------------------------
// OperationTracker
// ---------------------------------------------------------------------------

/// Convenience wrapper around a store reference and a live operation.
///
/// Provides ergonomic methods for recording steps and completing an
/// operation. Used internally by SDK methods.
pub(crate) struct OperationTracker {
    store: Arc<dyn OperationStore>,
    pub op: Operation,
}

impl OperationTracker {
    /// Start tracking a new operation.
    pub fn start(store: Arc<dyn OperationStore>, kind: OperationKind) -> Self {
        let op = Operation::new(kind);
        store.record(&op);
        Self { store, op }
    }

    /// The operation ID.
    pub fn id(&self) -> OperationId {
        self.op.id
    }

    /// Record a successful step.
    pub fn step_ok(&mut self, step: OperationStep, duration: Duration) {
        self.op.record(step.clone(), StepOutcome::Ok, duration);
        let last = self.op.steps.last().unwrap().clone();
        self.store.update_step(self.op.id, last);
    }

    /// Record a step that succeeded after retries.
    pub fn step_retried(&mut self, step: OperationStep, retries: u32, duration: Duration) {
        self.op
            .record(step.clone(), StepOutcome::Retried(retries), duration);
        let last = self.op.steps.last().unwrap().clone();
        self.store.update_step(self.op.id, last);
    }

    /// Record a failed step.
    pub fn step_failed(&mut self, step: OperationStep, error: SdkError, duration: Duration) {
        self.op
            .record(step.clone(), StepOutcome::Failed(error), duration);
        let last = self.op.steps.last().unwrap().clone();
        self.store.update_step(self.op.id, last);
    }

    /// Record a skipped step.
    #[allow(dead_code)]
    pub fn step_skipped(&mut self, step: OperationStep) {
        self.op.record_instant(step, StepOutcome::Skipped);
        let last = self.op.steps.last().unwrap().clone();
        self.store.update_step(self.op.id, last);
    }

    /// Mark the operation as succeeded and persist.
    pub fn succeed(mut self) {
        self.op.complete(OperationStatus::Succeeded);
        self.store.complete(self.op.id, OperationStatus::Succeeded);
    }

    /// Mark as failed, returning an [`OperationError`].
    pub fn fail(mut self, failed_step: OperationStep, error: SdkError) -> OperationError {
        self.op.complete(OperationStatus::Failed);
        self.store.complete(self.op.id, OperationStatus::Failed);
        OperationError {
            operation_id: self.op.id,
            error,
            failed_step,
            completed_steps: self.op.steps,
        }
    }

    /// Mark as partially completed, returning an [`OperationError`].
    pub fn partial(mut self, failed_step: OperationStep, error: SdkError) -> OperationError {
        self.op.complete(OperationStatus::PartiallyCompleted);
        self.store
            .complete(self.op.id, OperationStatus::PartiallyCompleted);
        OperationError {
            operation_id: self.op.id,
            error,
            failed_step,
            completed_steps: self.op.steps,
        }
    }
}
