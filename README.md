# FARD Math Primitives

Structural arithmetic kernel for FARD — Rust-first implementation of `ArithCore v0.2.0`.

---

## Status

**ArithCore v0.1.0** — complete (canonical witnesses, receipts, Merkle, replay)
**ArithCore v0.1.1** — complete (canonical decode enforcement)
**ArithCore v0.2.0** — complete (first-principles unbounded arithmetic, no external bignum)

23/23 tests passing. Run with:

    cargo t

---

## What this is

A minimal canonical arithmetic substrate shared by the runtime evaluator,
receipt engine, replay verifier, and any formal proof layer that must agree
with runtime arithmetic identity.

Design principle: **the witness is truth — the machine value is a cache**

---

## Implemented

### First-principles bignum (src/bignum.rs)
- BigNat — unbounded natural, Vec<u32> limbs little-endian, u128 mul accumulator
- BigInt — sign + BigNat magnitude
- Operations: add, sub, mul, divrem, gcd, to/from be_bytes, cmp, Display
- No external bignum dependencies — built from scratch as part of the kernel

### Value domains
- NatWitness — natural number backed by BigNat, structurally unbounded
- IntWitness — signed integer backed by BigInt, structurally unbounded
- RatWitness — exact reduced rational backed by BigInt/BigNat, gcd enforced

### Canonical encodings
- encode_nat / decode_nat — [0x01, u32_be_len, mag_bytes...]
- encode_int / decode_int — [0x02, sign_byte, nat_canon...]
- encode_rat / decode_rat — [0x03, int_canon..., nat_canon...]

Byte-stable, unique, invertible, deterministic across machines.
decode(encode(x)) == x verified for full value range including beyond machine bounds.

### Operation contracts
- nat: eq, cmp, add, sub_checked, mul
- int: eq, cmp, add, sub, mul, neg
- rat: eq, cmp, add, sub, mul, div_checked, normalize

### Overflow policy (v0.2.0)
- Structural overflow is impossible — BigNat/BigInt are unbounded
- Machine width is not semantic authority — it is a cache hint only
- nat.add(u64::MAX, 1) = 18446744073709551616 — succeeds structurally
- int.add(i64::MAX, 1) = 9223372036854775808 — succeeds structurally
- NativeOverflow is retained only for the native shadow cache path

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

## Test coverage (23 tests)

| Test                               | What it proves                                    |
|------------------------------------|---------------------------------------------------|
| nat_canon_is_stable                | Encoding stability                                |
| nat_ops                            | All nat operation contracts                       |
| int_ops                            | All int operation contracts                       |
| rat_reduces                        | Rational normalization and gcd reduction          |
| rat_ops                            | All rat operation contracts                       |
| overflow_policy                    | Large values succeed beyond machine bounds        |
| shadow_add_produces_receipt        | Receipt determinism                               |
| shadow_mismatch_detection          | Shadow mode catches divergence                    |
| strict_mode_authority              | Strict mode structural authority                  |
| merkle_root_is_deterministic       | Merkle stability                                  |
| merkle_block_determinism           | Block aggregation determinism                     |
| replay_verification                | Replay, tamper detection, policy mismatch         |
| decode_nat_roundtrip_and_rejection | Nat decode contracts                              |
| decode_int_roundtrip_and_rejection | Int decode contracts                              |
| decode_rat_roundtrip_and_rejection | Rat decode contracts                              |
| bignat_basics                      | BigNat zero, from_u64, is_zero, to_u64            |
| bignat_add                         | BigNat addition including beyond u64              |
| bignat_sub                         | BigNat subtraction and zero result                |
| bignat_mul                         | BigNat multiplication including beyond u64        |
| bignat_divrem                      | BigNat division and remainder                     |
| bignat_gcd                         | BigNat gcd correctness                            |
| bignat_be_bytes_roundtrip          | BigNat byte encoding round-trips                  |
| bigint_arithmetic                  | BigInt add/sub/mul/neg/cmp beyond i64             |

---

## Build and run

    cargo build
    cargo t
    cargo run --example demo

---

## Repository structure

    FARD Math Primitives/
    ├── .cargo/
    │   └── config.toml        # cargo t alias
    ├── .vscode/
    ├── examples/
    │   └── demo.rs
    ├── src/
    │   ├── lib.rs             # kernel: witnesses, ops, receipts, replay, decode
    │   └── bignum.rs          # first-principles BigNat and BigInt
    ├── Cargo.toml
    └── README.md

---

## Migration path into FARD

| Phase                              | Status     |
|------------------------------------|------------|
| 1 — Rust kernel prototype          | complete   |
| 1.1 — Canonical decode enforcement | complete   |
| 2 — Unbounded Nat/Int/Rat          | complete   |
| 3 — Full exact op closure          | next       |
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

- nat.divrem, int.divrem, int.abs, int.signum
- rat.floor, rat.ceil, rat.trunc, rat.abs, rat.signum
- Exponentiation for Nat/Int/Rat
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
- Structural arithmetic is unbounded — machine width is cache only
- No negative zero
- No unreduced rationals as outputs
- Structural result always authoritative
- No external bignum dependencies in the kernel
