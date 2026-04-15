# FARD Math Primitives

Structural arithmetic kernel for FARD — Rust-first implementation of `ArithCore v0.1.1`.

---

## Status

**ArithCore v0.1.0** — complete  
**ArithCore v0.1.1** — complete (canonical decode enforcement)

15/15 tests passing. Run with:

    cargo test

---

## What this is

A minimal canonical arithmetic substrate shared by the runtime evaluator,
receipt engine, replay verifier, and any formal proof layer that must agree
with runtime arithmetic identity.

Design principle: **the witness is truth — the machine value is a cache**

---

## Implemented

### Value domains
- `NatWitness` — natural number as canonical structural witness
- `IntWitness` — signed integer as sign + magnitude over NatWitness
- `RatWitness` — exact reduced rational, gcd(|num|, den) = 1 enforced

### Canonical encodings
- `encode_nat` / `decode_nat` — [0x01, u32_be_len, mag_bytes...]
- `encode_int` / `decode_int` — [0x02, sign_byte, nat_canon...]
- `encode_rat` / `decode_rat` — [0x03, int_canon..., nat_canon...]

Byte-stable, unique, invertible, deterministic across machines.
decode(encode(x)) == x verified for full value range including boundary values.

### Operation contracts
- nat: eq, cmp, add, sub_checked, mul
- int: eq, cmp, add, sub, mul, neg
- rat: eq, cmp, add, sub, mul, div_checked, normalize

All ops return Result — overflow never silently alters semantics.

### Overflow policy
- Wrapping and saturating arithmetic forbidden as semantic truth
- All ops use checked_* — overflow surfaces as ArithmeticError::NativeOverflow
- i64::MIN negation handled via wrapping_neg() throughout

### Shadow / Strict execution
- ShadowChecked — native and structural execute in parallel, mismatch is hard error
- Strict — structural is authoritative, native is optional cache only
- execute_int_op — general mode-aware op infrastructure
- checked_int_add, checked_int_sub, checked_int_mul

### Receipts and Merkleization
- ArithmeticStepReceipt — deterministic leaf digest per arithmetic step
- ArithmeticBlock — Merkle aggregation of receipt leaves per semantic region
- Duplicate-last strategy on odd leaf counts

### Replay verification
- replay_verify — recomputes leaf digests and Merkle root from receipt sequence
- recompute_leaf_digest — mirrors ArithmeticStepReceipt::new exactly
- Failure kinds: LeafDigestMismatch, MerkleRootMismatch, PolicyMismatch
- Tamper detection verified in tests

### Canonical decode enforcement (v0.1.1)
- decode_nat — rejects wrong tag, non-minimal encoding, trailing bytes, length mismatch
- decode_int — rejects invalid sign byte, negative zero, zero with nonzero sign
- decode_rat — rejects unreduced fractions, alternate zero forms, zero denominator

---

## Error types

    ArithmeticError: NativeOverflow, NegativeNatResult, DivideByZero,
                     ZeroDenominator, ShadowMismatch

    DecodeError: WrongTag, UnexpectedEof, NonMinimalEncoding, InvalidSignByte,
                 NegativeZero, ZeroWithNonzeroSign, ZeroDenominator,
                 UnreducedRational, AlternateZeroRational, TrailingBytes,
                 LengthMismatch

---

## Test coverage

| Test                              | What it proves                              |
|-----------------------------------|---------------------------------------------|
| nat_canon_is_stable               | Encoding stability                          |
| nat_ops                           | All nat operation contracts                 |
| int_ops                           | All int operation contracts                 |
| rat_reduces                       | Rational normalization and gcd reduction    |
| rat_ops                           | All rat operation contracts                 |
| overflow_policy                   | All overflow boundaries -> NativeOverflow   |
| shadow_add_produces_receipt       | Receipt determinism                         |
| shadow_mismatch_detection         | Shadow mode catches divergence              |
| strict_mode_authority             | Strict mode structural authority            |
| merkle_root_is_deterministic      | Merkle stability                            |
| merkle_block_determinism          | Block aggregation determinism               |
| replay_verification               | Replay, tamper detection, policy mismatch   |
| decode_nat_roundtrip_and_rejection| Nat decode contracts                        |
| decode_int_roundtrip_and_rejection| Int decode contracts                        |
| decode_rat_roundtrip_and_rejection| Rat decode contracts                        |

---

## Build and run

    cargo build
    cargo test
    cargo run --example demo

---

## Repository structure

    FARD Math Primitives/
    ├── .cargo/
    │   └── config.toml        # cargo test command
    ├── .vscode/
    ├── examples/
    │   └── demo.rs
    ├── src/
    │   └── lib.rs             # entire kernel
    ├── Cargo.toml
    └── README.md

---

## Migration path into FARD

| Phase                              | Status     |
|------------------------------------|------------|
| 1 — Rust kernel prototype          | complete   |
| 1.1 — Canonical decode enforcement | complete   |
| 2 — Unbounded Nat/Int/Rat          | in progress |

### Phase 2 Progress
- ✅ NatWitness migrated to BigUint (unbounded naturals)
- ✅ Nat arithmetic no longer overflows
- ✅ IntWitness migrated to BigInt (unbounded integers)
- 🔄 RatWitness still u64/i64-backed (bridge mode)

Invariant:
Nat and Int layers are now structurally unbounded; Rat remains in compatibility mode until migration completes.
| 3 — Full exact op closure          | pending    |
| 4 — Stable ABI                     | pending    |
| 5 — Runtime integration            | pending    |
| 6 — Std rebase                     | pending    |
| 7 — Strict numeric lane            | pending    |
| 8 — Decimal/fixed-point            | pending    |
| 9 — ApproxCore                     | pending    |
| 10 — Compiler unification          | pending    |
| 11 — FARD self-hosting             | pending    |

---

## Not yet implemented

- Big integer support beyond u64/i64
- Receipt schema validation and deserialization enforcement
- Merkle inclusion proof generation
- Serialized artifact output for blocks
- Property-based tests for normalization stability
- Storage policy enum
- FARD mirror implementation
- Lean-side ABI alignment
- Float policy (intentionally excluded from kernel scope)

---

## Design invariants — do not violate

- Exact numbers before floats
- Witness truth before machine representation
- Canonical bytes before convenience formatting
- Merkle commitments before full witness expansion
- Deterministic normalization before optimization
- checked_* arithmetic everywhere — no silent overflow
- No negative zero
- No unreduced rationals as outputs
- Structural result always authoritative
