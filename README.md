# FARD Math Primitives

Structural arithmetic kernel prototype for FARD, built in Rust first so the migration path into FARD is clean, measurable, and low-friction.

This repository is not trying to solve “all mathematics” at once.
It is the first executable layer of the arithmetic identity program:

- define canonical witnesses for exact numbers,
- separate machine acceleration from structural truth,
- run native arithmetic in parallel with structural checking,
- attach Merkleized arithmetic receipts to execution,
- prepare a shared future ABI between Rust/FARD/Lean.

---

## 1. Why this exists

FARD needs a math kernel that can eventually say:

> arithmetic is not merely represented by the runtime;
> arithmetic is the runtime’s semantic substrate.

Right now, most languages trust the host machine’s primitive number types.
That is fast, but it means the language inherits the hidden assumptions of the CPU, compiler, platform ABI, floating-point model, overflow behavior, and serialization rules.

This project starts the inversion.

The design principle is:

- **the witness is truth**
- **the machine value is a cache**

In other words, the integer `10` should not only be an `i64` in memory.
It should also be a canonical structural artifact with a byte-stable identity and a digest.

---

## 2. Core goal

The immediate goal is to build the exact-number lane:

- `NatWitness`
- `IntWitness`
- `RatWitness`
- `StructuralNumber`
- `ArithmeticStepReceipt`
- `ArithmeticBlock` with Merkle roots
- `shadow_add_int()` as the first shadow-mode checked primitive

This is the beginning of the path:

\[
\mathbb{N} \to \mathbb{Z} \to \mathbb{Q}
\]

Floats are intentionally excluded from the initial kernel.
They are not exact identity objects and would pollute the foundation.

---

## 3. Mental model

There are two layers in every arithmetic step.

### Native layer
Fast execution on host machine values.
Examples:

- `i64`
- future optimized bigint storage
- reduced rational cache

### Structural layer
Canonical witness over the math substrate.
Examples:

- natural number witness
- signed integer witness
- reduced rational witness
- canonical encoding
- digest

The runtime compares them in shadow mode.

If they agree, the step is certified.
If they disagree, the machine value is considered wrong.

---

## 4. Shadow Mode vs Strict Mode

### Shadow Mode
Native execution remains active, but every arithmetic step is interpreted structurally and checked in parallel.

This gives:

- real mismatch detection
- deterministic proof artifacts
- no evaluator freeze
- low-friction rollout

### Strict Mode
Structural computation becomes authoritative.
Native representation becomes an optimization layer only.

That means:

- no arithmetic step without witness semantics
- no equality by raw host representation alone
- no number without canonical encoding
- execution and proof begin to converge toward identity

This repository starts with Shadow Mode.

---

## 5. Repository structure

```text
FARD Math Primitives/
├── .vscode/
│   ├── extensions.json
│   ├── launch.json
│   ├── settings.json
│   └── tasks.json
├── examples/
│   └── demo.rs
├── src/
│   └── lib.rs
├── .gitignore
├── Cargo.toml
└── README.md
```

---

## 6. Data model

### `NatWitness`
Represents a natural number as a canonical exact witness.

Fields:

- `extent: u64` — compact executable magnitude
- `canon: Vec<u8>` — canonical bytes (`NAT\0 || n_be_bytes`)
- `digest: [u8; 32]` — SHA-256 of canonical bytes

Interpretation:

A natural is treated as the canonical witness of the iterate \(T^n(0)\), but in compressed runtime form.
The expanded orbit is conceptual and reconstructible, not stored by default.

### `IntWitness`
Represents an integer as sign + natural magnitude.

Fields:

- `sign: Sign`
- `magnitude: NatWitness`
- `canon`
- `digest`

### `RatWitness`
Represents a rational as reduced `(num, den)` with `gcd(num, den) = 1`.

Fields:

- `num: IntWitness`
- `den: NatWitness`
- `canon`
- `digest`

Normalization rule:

- denominator must be nonzero
- rational is always reduced
- zero normalizes to `0/1`

### `StructuralNumber`
This is the semantic carrier.

Fields:

- `repr` — host-side acceleration form
- `witness` — actual structural witness
- `canon` — byte-stable identity
- `mode` — native / shadow / strict
- `receipt_link` — digest of witness / construction path

This is the first runtime object that explicitly says:

> the number is structural first, representational second.

---

## 7. Receipts and Merkleization

Arithmetic proof data is not appended naïvely to the main trace.
That would explode trace volume.

Instead, the design is:

1. **Arithmetic step receipts** become Merkle leaves
2. **Arithmetic blocks** aggregate local step receipts into a Merkle root
3. The larger evaluator can later attach only the block root to semantic execution steps

### `ArithmeticStepReceipt`
Fields:

- `op`
- `lhs_digest`
- `rhs_digest`
- `out_digest`
- `native_summary`
- `verdict`
- `mode`
- `leaf_digest`

Leaf digest commits to the operation and its checked result.

### `ArithmeticBlock`
Fields:

- `block_id`
- `leaf_count`
- `merkle_root`
- `storage_policy`

This is the right shape for loop-heavy execution later.
Instead of storing every arithmetic detail inline forever, the runtime stores commitments and expands only where policy or failure demands it.

---

## 8. Canonical encodings

The current prototype uses simple stable encodings:

- `NAT\0 || u64::to_be_bytes(n)`
- `INT\0 || sign_byte || magnitude_be_bytes`
- `RAT\0 || i64::to_be_bytes(num) || u64::to_be_bytes(den)`

These are not yet the final FARD/Lean shared ABI.
They are the first stable executable contract.

The important property is not elegance.
It is determinism.

---

## 9. What is implemented right now

### Exact witnesses
- natural construction
- signed integer construction
- reduced rational construction

### Deterministic hashing
- SHA-256 digest for witnesses
- SHA-256 leaf digests for arithmetic receipts

### Merkleization
- deterministic Merkle root for arithmetic blocks
- duplicate-last strategy on odd leaf counts
- explicit empty-tree root

### First shadow primitive
- `shadow_add_int(lhs, rhs, mode)`

This function:

1. builds structural wrappers for inputs,
2. executes native checked addition,
3. derives structural result,
4. compares native and structural outputs,
5. emits arithmetic receipt.

In `Strict` mode, a mismatch raises an error.

---

## 10. What is not implemented yet

This is a prototype, not the completed arithmetic kernel.

Still missing:

- subtraction / multiplication / comparison primitives
- full strict-mode evaluation lane
- big integer support beyond `u64` / `i64`
- exact rational arithmetic operators
- witness-body persistence tiers
- Merkle proofs for receipt inclusion
- ABI lock with Lean-side definitions
- FARD-side mirror implementation
- evaluator-step correspondence proofs
- float policy
- spectral / Hilbert lift

---

## 11. Opening in VS Code

### Prerequisites

Install:

- Rust toolchain via `rustup`
- VS Code
- LLDB extension for Rust debugging
- rust-analyzer extension

### Open the project

1. Unzip the archive
2. Open the folder `FARD Math Primitives` in VS Code
3. Let rust-analyzer finish indexing
4. Run one of the built-in tasks:
   - `cargo build`
   - `cargo test`
   - `cargo run --example demo`

The repository already includes `.vscode` configuration for:

- recommended extensions
- format-on-save
- cargo tasks
- an example debug launch target

---

## 12. Build and test

From the project root:

```bash
cargo build
cargo test
cargo run --example demo
```

Expected outcome:

- crate builds successfully
- tests pass
- demo prints two arithmetic leaf digests and one arithmetic block root

---

## 13. Example execution flow

The demo performs two shadow-checked integer additions:

- `10 + 20`
- `30 + 12`

Each produces an `ArithmeticStepReceipt`.
Those receipts are then grouped into an `ArithmeticBlock`, which computes a Merkle root.

This is the exact pattern that will later attach arithmetic proof data to semantic evaluator steps.

---

## 14. Why Rust first is correct

Building this first in Rust is not a retreat from FARD.
It is the fastest path into FARD.

Rust gives:

- direct control over representation
- stable systems-level semantics
- fast iteration on canonical encoding rules
- clean access to hashing and serialization
- precise failure surfaces
- immediate test harnesses

The point is not to leave the kernel in Rust forever.
The point is to:

1. freeze the exact object model,
2. validate the shadow/strict semantics,
3. lock the canonical encodings,
4. then mirror the same kernel into FARD without ambiguity.

That makes the migration frictionless because the contracts already exist.

---

## 15. The migration path into FARD

The clean path is:

### Phase 1 — Rust kernel prototype
Freeze object model and arithmetic receipt shape.

### Phase 2 — ABI freeze
Document exact canonical bytes, operation names, normalization rules, and digest contracts.

### Phase 3 — FARD mirror
Rebuild the same witnesses and encodings inside FARD.

### Phase 4 — Cross-check harness
Run the same arithmetic cases through Rust and FARD.
Require identical canonical bytes and identical digests.

### Phase 5 — Evaluator integration
Attach arithmetic Merkle roots to FARD semantic trace segments.

### Phase 6 — Lean alignment
Make the exact same arithmetic ABI provable from the formal side.

That is how the Golden Spike lands.

---

## 16. Recommended next implementation steps

1. Add `shadow_sub_int()` and `shadow_mul_int()`
2. Add exact rational add / sub / mul / compare
3. Introduce storage policy enum instead of raw string
4. Add Merkle inclusion proof generation and verification
5. Add serialized artifact output for arithmetic blocks
6. Add property tests for normalization and digest stability
7. Replace `u64/i64` bounds with bigint-backed exact witnesses
8. Lock the first `ArithCore` spec document
9. Mirror the implementation in FARD
10. Prove Rust/FARD digest equality on shared cases

---

## 17. Design constraints to keep

Do not violate these:

- exact numbers before floats
- witness truth before machine representation
- canonical bytes before convenience formatting
- Merkle commitments before full witness expansion by default
- deterministic normalization before optimization
- Rust prototype only as contract freezer, not as philosophical endpoint

---

## 18. Long-term vision

When mature, this project is not “just a math library.”
It becomes the arithmetic identity layer beneath the FARD evaluator.

That means a future execution step is no longer:

> machine computed a value and logged it

but:

> structural arithmetic reduced a witnessed object, and the runtime cached that fact efficiently

At that point, execution trace and proof trace begin collapsing into the same artifact class.

---

## 19. License / status

Prototype status: early foundation.

Safe assumption:

- the architecture is correct,
- the encoding rules are still provisional,
- the object model is the important thing being frozen first.

---

## 20. Quick start summary

```bash
cargo build
cargo test
cargo run --example demo
```

Then inspect:

- witness types in `src/lib.rs`
- Merkle aggregation in `ArithmeticBlock`
- first shadow primitive in `shadow_add_int()`
- example flow in `examples/demo.rs`

This repository is the first executable step toward arithmetic identity for FARD.
