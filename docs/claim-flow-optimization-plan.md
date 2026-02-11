# Claim Flow: Optimization, Modularization, and Allocation Reduction Plan

This document outlines a planning-phase plan to optimize the claim flow, improve modularization, and minimize heap allocations. It is intended to be executed in a follow-up implementation phase.

---

## 1. Scope

- **Primary file**: `crates/sdk/src/operations/claim.rs`
- **Related**: `crates/sdk/src/frost_bridge.rs`, `crates/crypto/src/frost.rs` (only where API changes reduce allocations in claim)
- **Out of scope**: Behavior changes, protocol changes, or changes that would require new dependencies.

---

## 2. Modularization

### 2.1 Split claim into submodules (under `operations/claim/`)

Goal: One file per logical step, clearer boundaries, easier testing and reuse.

| Current location | Proposed module | Contents |
|------------------|-----------------|----------|
| `verify_and_decrypt_transfer` + `ClaimableLeaf` | `claim/verify_decrypt.rs` | Sender verification, ECIES decrypt, sequence extraction, `ClaimableLeaf` |
| `prepare_and_apply_key_tweaks` | `claim/key_tweaks.rs` | VSS split, per-operator tweak lists, `ClaimTransferTweakKeys` RPC loop |
| Refund tx construction + signing jobs + FROST sign/aggregate + finalize | `claim/sign_finalize.rs` | Build refund txs, build signing jobs, call `frost_sign_and_aggregate` per tx type, `FinalizeNodeSignatures`, tree store insert |
| `frost_sign_and_aggregate` + `LeafSigningContext` | `claim/frost.rs` (SDK-local) | FROST sign+aggregate for one refund tx; optionally shared with transfer flow later |
| Helpers | `claim/mod.rs` or `claim/helpers.rs` | `extract_sequence_from_tx_bytes`, `spark_network_proto`, `bitcoin_network` |

**Public surface**: Keep `claim_transfer` and `claim_single_transfer` on `Sdk` in `claim/mod.rs`; rest are `pub(crate)` or private to the claim module.

**Optional**: If you prefer to avoid a directory, keep a single `claim.rs` but add clear section comments and internal functions (e.g. `build_claimable_leaves`, `build_per_operator_tweaks`, `build_signing_jobs_and_contexts`) to mirror the same logical steps.

### 2.2 Shared network helpers

- `spark_network_proto` and `bitcoin_network` are used by claim (and likely transfer). Move to a small shared place, e.g. `crates/sdk-core/src/network.rs` or `crates/sdk/src/network.rs`, to avoid duplication and keep claim focused on protocol steps.

---

## 3. Heap Allocation Reduction

### 3.1 High-impact: avoid cloning per-leaf in key tweaks (prepare_and_apply_key_tweaks)

- **Issue**: For each leaf, `pubkey_shares_tweak` is a `HashMap<String, Bytes>` that is **cloned for every operator** (`pubkey_shares_tweak.clone()` inside the inner loop). So with L leaves and N operators we do L×N clones of the same map.
- **Change**: Build `pubkey_shares_tweak` once per leaf and pass it by reference. Options:
  - Build one shared map per leaf (e.g. in a small struct), then when building `per_operator_tweaks[i]`, store only the operator’s own share and a **reference** to the shared map — but proto uses `HashMap<String, Vec<u8>>`/Bytes, so “reference” means we need a single copy. So instead: build the map once per leaf, then when constructing each `ClaimLeafKeyTweak`, **move** the map into the first operator’s tweak and use `Arc<std::collections::HashMap<_,_>>` (or similar) for the rest so we don’t clone L×N times. Or: build `pubkey_shares_tweak` once per leaf and clone only when building the Nth operator’s entry (we still need N copies per leaf for the proto, but we can build them without the inner loop doing a clone per operator).
- **Simpler approach**: Pre-allocate `per_operator_tweaks` and fill it so that we build `pubkey_shares_tweak` once per leaf, then push the same reference (e.g. wrap in `Arc`) into each operator’s list. Proto typically wants owned Bytes; then we need one clone per (leaf, operator) for the field, but we can avoid building the whole map N times: build once, then iterate operators and clone only the map when building each `ClaimLeafKeyTweak`. So we go from “build map + clone full map N times” to “build map once + clone full map N times” — same number of copies but we avoid re-building the map content N times. If the proto allows sharing (e.g. Bytes is ref-counted), we could use `Bytes` from a single source and clone Bytes (cheap) instead of cloning the whole HashMap.
- **Recommended**: Store `pubkey_shares_tweak` in an `Arc<HashMap<..., Bytes>>` per leaf; when building each operator’s `ClaimLeafKeyTweak`, use `pubkey_shares_tweak: Arc::clone(&arc_map)` so we only clone the Arc, not the map. Protobuf/gRPC usually need owned data; then when building the request, we can convert Arc<HashMap> to HashMap by cloning once per request if the type requires it, or if the generated code accepts references we avoid even that. So: **per leaf, one HashMap; share via Arc when pushing to each operator’s list.** When building the gRPC request we need a `HashMap`; we can do one clone of the map per operator from the Arc (so L×N map clones still for the wire format) or, if the runtime accepts it, share. So the win is: we don’t build the map N times (we build once and clone N times). That’s already an improvement. If we can pass a reference into the proto builder and it stores a clone internally only when needed, we avoid even that — to be checked per crate.

### 3.2 Avoid cloning operator_ids to Strings

- **Issue**: `operator_ids: Vec<String> = self.inner.transport.operator_ids().iter().map(|s| s.to_string()).collect()`.
- **Change**: If `operator_ids()` can return `&[String]` or we can iterate without collecting, use that. Otherwise keep one allocation but ensure we don’t clone again in the loop; use `&operator_ids[i]` when calling `session_token` and `claim_transfer_tweak_keys`.

### 3.3 Per-operator request: avoid extra clone of tweaks

- **Issue**: `let tweaks = per_operator_tweaks[i].clone();` then pass to request. The vector of tweaks is per-operator and we need to pass it by value to the RPC.
- **Change**: Use `std::mem::take(&mut per_operator_tweaks[i])` so we move the vector into the request instead of cloning, then the next iteration uses a new (empty) vec if we ever reused the same index. So we only do this when we’re done with that operator’s list: when building the request for operator `i`, take ownership of `per_operator_tweaks[i]` and pass it into the request (no clone). This removes one Vec clone per operator.

### 3.4 Signing jobs and leaf_signing_data

- **Issue**: `pk_bytes.clone()` used for each of the three job types (CPFP, direct, direct-from-CPFP). We already use `pk_bytes` once without clone for the last job; we can do the same for the first two by building jobs in an order that consumes `pk_bytes` on the last use.
- **Change**: Build `direct_from_cpfp_job` last and pass `pk_bytes` by value there; for the other two use `pk_bytes.clone()`. So we go from 3 clones to 2. Or use `Bytes::clone` (ref-counted) so the cost is only the refcount bump, which is already the case — so no change unless we switch to a different type.

### 3.5 Direct refund path: avoid building a full LeafSigningContext override

- **Issue**: For the direct refund we build a full `LeafSigningContext` that duplicates most of `ctx` and only overrides `prev_out` (and conceptually the tx/nonce we’re signing). This causes many clones (leaf_id, all three nonce pairs, all three refund txs, prev_out, direct_prev_out).
- **Change**: Refactor `frost_sign_and_aggregate` to accept the sighash input as “prev_out for this signing” instead of baking it into `LeafSigningContext`. For example:
  - Add an overload or new helper: `frost_sign_and_aggregate_with_prev_out(ctx, refund_tx, nonce_pair, operator_result, verifying_key_bytes, prev_out_for_sighash)`.
  - Or pass `prev_out: &TxOut` explicitly and use it inside for sighash; `ctx` still provides key material and verifying key. Then for CPFP and direct-from-CPFP we pass `&ctx.prev_out`; for direct we pass `ctx.direct_prev_out.as_ref().unwrap()`. This removes the need to construct `direct_ctx_override` and all its clones.

### 3.6 FROST: avoid cloning all_commitments for sign_as_user

- **Issue**: In `frost_sign_and_aggregate` we call `sign_as_user(..., all_commitments.clone())`. The crypto crate’s `sign_as_user` takes `BTreeMap<Identifier, SigningCommitments>` by value and builds a `SigningPackage` from it; then we use the same `all_commitments` again for `aggregate_nested`. So we need the map twice.
- **Change**: In `spark_crypto::frost`, change `sign_as_user` and `aggregate_nested` to take `&BTreeMap<...>` (or a type that allows both to use the same map). Then in the crypto crate, build the signing package from a reference; if the FROST API requires ownership, the crate can clone internally only where needed. So the allocation reduction is in the SDK: we don’t clone the whole map before calling `sign_as_user`; we pass a reference. The crypto crate may still need to clone for `SigningPackage::new_with_participants_groups` if it takes ownership — then we reduce to one clone inside crypto instead of one in SDK and one in crypto.

### 3.7 verify_and_decrypt_transfer: payload buffer

- **Issue**: `let mut payload = Vec::new(); payload.extend_from_slice(...)` per leaf. Size is bounded (leaf_id + transfer_id + secret_cipher).
- **Change**: Reuse a single buffer: e.g. `let mut payload = Vec::with_capacity(estimate);` outside the loop, then `payload.clear(); payload.extend(...)` inside the loop. That avoids repeated small allocations per leaf.

### 3.8 ClaimableLeaf and proto buffers

- **Issue**: `leaf.node_tx.to_vec()`, `leaf.direct_tx.to_vec()` when building `ClaimableLeaf`. We need owned bytes for later use in refund construction.
- **Change**: If we only ever need to read these as slices, we could store `Bytes` (ref-counted) from the proto instead of `Vec<u8>`, so we don’t re-allocate. Check whether the proto gives us `Bytes` or `Vec<u8>` and whether refund construction can work with `&[u8]` (e.g. `parse_tx(&leaf.node_tx_raw)`). If the type is already `Bytes`, use it; if it’s `Vec<u8>`, we could request a Bytes-based API from the transport layer to avoid copying.

### 3.9 Finalize and tree store

- **Issue**: `let mut claimed_nodes = Vec::new();` then push only when `proto_to_tree_node` returns `Some`. Pre-size with capacity `finalize_resp.nodes.len()` to avoid reallocs.
- **Change**: `let mut claimed_nodes = Vec::with_capacity(finalize_resp.nodes.len());` and reserve exact capacity if we want to shrink later, or keep as is and only fix capacity.

---

## 4. Optimizations (non-allocation)

### 4.1 Lookup by index instead of by leaf_id

- **Issue**: In the loop over `sign_resp.signing_results`, we do `leaf_signing_data.iter().find(|c| c.leaf_id == signing_result.leaf_id)`. Order of results may match order of `leaf_signing_data` (same as signing_jobs).
- **Change**: If the coordinator returns results in the same order as the jobs we sent, match by index (e.g. same `i` for `signing_results[i]` and `leaf_signing_data[i]`) and add a debug assertion that `leaf_id` matches. That avoids a linear search per leaf.

### 4.2 Secp256k1 context

- **Issue**: `Secp256k1::new()` in `prepare_and_apply_key_tweaks` allocates a context per call.
- **Change**: Use `Secp256k1::verification_only()` if we only need verification, or reuse a single context (e.g. thread-local or passed in). For key derivation and public key from secret we need a full context; one per `prepare_and_apply_key_tweaks` call is acceptable unless we see this on a hot path. Low priority.

### 4.3 RNG

- **Issue**: `rand::thread_rng()` used in two places (key_tweaks and sign_finalize). No change needed unless we want to pass a single RNG for reproducibility; otherwise keep as is.

---

## 5. Suggested Implementation Order

1. **Allocation: direct refund context** (3.5) — refactor `frost_sign_and_aggregate` to take `prev_out` for sighash so we don’t build `direct_ctx_override`. High impact, localized change.
2. **Allocation: FROST commitments** (3.6) — have crypto take `&BTreeMap` where possible and clone only inside the crate if needed.
3. **Allocation: pubkey_shares_tweak** (3.1) — use `Arc<HashMap<...>>` per leaf when building per-operator tweaks to avoid building the same map N times.
4. **Optimization: match by index** (4.1) — assume coordinator order and match signing results to leaf context by index.
5. **Allocation: take instead of clone tweaks** (3.3) — move `per_operator_tweaks[i]` into the request.
6. **Allocation: payload buffer reuse** (3.7) — single buffer in verify_and_decrypt.
7. **Modularization** (2.1) — split into `claim/verify_decrypt.rs`, `claim/key_tweaks.rs`, `claim/sign_finalize.rs`, `claim/frost.rs`, and `claim/mod.rs` (and helpers). Keep public API in `mod.rs`.
8. **Shared network helpers** (2.2) — move to sdk-core or sdk network module.
9. **Minor**: capacity for `claimed_nodes` (3.9), `operator_ids` (3.2), and pk_bytes clones (3.4) as needed.

---

## 6. Testing and Validation

- Run existing claim E2E test(s) after each logical change.
- Run `cargo clippy` and `cargo test` for the sdk and spark-crypto crates.
- No behavior change to the protocol; only performance and structure.

---

## 7. Summary Table

| Item | Category | Impact | Effort |
|------|----------|--------|--------|
| Direct ctx override (prev_out param) | Allocation | High | Medium |
| FROST commitments by ref | Allocation | Medium | Low (if API allows) |
| Arc for pubkey_shares_tweak | Allocation | High (in loop) | Medium |
| Match by index | Perf | Low–Medium | Low |
| Take tweaks (move) | Allocation | Medium | Low |
| Payload buffer reuse | Allocation | Low | Low |
| Submodules under claim/ | Modularization | Clarity/maintainability | Medium |
| Network helpers | Modularization | DRY | Low |
| claimed_nodes capacity | Allocation | Low | Trivial |
| operator_ids / pk_bytes | Allocation | Low | Trivial |

This plan is ready for implementation in the order above, with tests and clippy checks after each step.
