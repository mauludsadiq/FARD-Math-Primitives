# ARITH_CORE_SPEC.md

Status: DRAFT  
Version: 0.1.0  
Scope: FARD Math Primitives / Rust-first arithmetic kernel candidate  
Authority: This document defines the canonical arithmetic contract for Nat, Int, and Rat in Shadow and Strict modes.

---

## 1. Purpose

`ArithCore` is the minimal canonical arithmetic substrate shared by:

- the runtime evaluator,
- the receipt engine,
- replay verification,
- future FARD-native arithmetic execution,
- and any formal proof layer that must agree with runtime arithmetic identity.

The purpose of this specification is to eliminate arithmetic ambiguity by defining:

1. canonical encodings,
2. exact operation contracts,
3. normalization rules,
4. overflow behavior,
5. receipt generation,
6. Merkle aggregation,
7. mode semantics,
8. replay verification.

This document does **not** define floating-point arithmetic.  
Floats are explicitly outside the initial kernel.

Initial kernel scope:

\[
\mathbb{N}, \mathbb{Z}, \mathbb{Q}
\]

---

## 2. Core Design Principle

Arithmetic values are not machine primitives.

Arithmetic values are **structural witnesses** with optional native cached representations.

The semantic truth ordering is:

1. canonical witness
2. canonical encoding
3. structural operation result
4. optional host/native cached acceleration

If host/native execution disagrees with the structural result, the host/native result is wrong by definition.

---

## 3. Terminology

### 3.1 Witness
A witness is the structural identity-bearing form of a value.

### 3.2 Canonical Encoding
A canonical encoding is the unique byte-stable serialization of a witness.

### 3.3 Structural Result
The result obtained by applying the operation contract to witnesses under normalization rules.

### 3.4 Native Result
A host-language accelerated computation result used only as a cache or as a shadow-checked comparison target.

### 3.5 Shadow Mode
A mode where native execution may occur, but structural arithmetic is computed and compared against it.

### 3.6 Strict Mode
A mode where structural arithmetic is authoritative and native execution is optional acceleration only.

### 3.7 Arithmetic Receipt
A digest-anchored artifact representing one arithmetic operation.

### 3.8 Merkle Block
A Merkle aggregation of arithmetic receipt leaves within a semantic region.

---

## 4. Value Domains

---

### 4.1 Nat

A natural number witness represents:

\[
n = T^n(0)
\]

where `0` is the origin and `T` is successor.

#### Structural Form

```text
NatWitness:
  value: u128 or BigNat-compatible magnitude carrier
  canon: bytes
  digest: sha256(canon)
```

#### Semantic Meaning

A `NatWitness` is the unique canonical representative of a natural number.

#### Constraints

- `value >= 0`
- canonical encoding must be unique
- no negative zero exists
- no alternate equivalent encodings are permitted

---

### 4.2 Int

An integer is a signed magnitude over `NatWitness`.

#### Structural Form

```text
IntWitness:
  sign: -1 | 0 | +1
  magnitude: NatWitness
  canon: bytes
  digest: sha256(canon)
```

#### Constraints

- if `sign == 0`, then `magnitude = 0`
- if `magnitude = 0`, then `sign == 0`
- no negative zero
- canonical encoding must collapse all zero forms to one encoding

---

### 4.3 Rat

A rational is a reduced exact quotient.

#### Structural Form

```text
RatWitness:
  num: IntWitness
  den: NatWitness
  canon: bytes
  digest: sha256(canon)
```

#### Constraints

- denominator must be strictly positive and nonzero
- fraction must be reduced:
  \[
  \gcd(|num|, den) = 1
  \]
- sign must live in numerator only
- zero must be encoded as:
  \[
  0 / 1
  \]

---

## 5. Canonical Encodings for Nat / Int / Rat

All canonical encodings in this specification are byte-stable and deterministic.

Canonical encodings must be:

- unique,
- invertible,
- deterministic,
- stable across machines,
- stable across runtime implementations.

### 5.1 Encoding Rules Overview

Each encoding begins with a domain tag byte.

Recommended tags:

- `0x01` = Nat
- `0x02` = Int
- `0x03` = Rat

All multi-byte integer fields must be big-endian.

---

### 5.2 Nat Canonical Encoding

#### Encoding Form

```text
Nat =
  TAG_NAT
  LEN
  MAG_BYTES
```

Where:

- `TAG_NAT = 0x01`
- `LEN` is the byte length of `MAG_BYTES`, encoded as canonical unsigned varint or fixed u32 BE
- `MAG_BYTES` is the minimal big-endian unsigned magnitude encoding
- zero is encoded with zero-length magnitude or single zero byte according to implementation policy, but policy must be fixed globally

#### Required Minimality Rule

No leading zero bytes are permitted in nonzero magnitudes.

#### Canonical Example

```text
0   -> [0x01, LEN=0]
1   -> [0x01, LEN=1, 0x01]
10  -> [0x01, LEN=1, 0x0A]
256 -> [0x01, LEN=2, 0x01, 0x00]
```

#### Required Invariant

Two equal natural numbers must have identical canonical bytes.

---

### 5.3 Int Canonical Encoding

#### Encoding Form

```text
Int =
  TAG_INT
  SIGN
  NAT_MAG_CANON
```

Where:

- `TAG_INT = 0x02`
- `SIGN = 0x00 | 0x01 | 0x02`
  - `0x00` = zero
  - `0x01` = positive
  - `0x02` = negative
- `NAT_MAG_CANON` is canonical Nat encoding of magnitude

#### Canonical Zero Rule

Zero must be encoded exactly once:

```text
[0x02, 0x00, <Nat(0)>]
```

No alternative zero forms are legal.

#### Canonical Examples

```text
0   -> [0x02, 0x00, Nat(0)]
5   -> [0x02, 0x01, Nat(5)]
-5  -> [0x02, 0x02, Nat(5)]
```

---

### 5.4 Rat Canonical Encoding

#### Encoding Form

```text
Rat =
  TAG_RAT
  INT_NUM_CANON
  NAT_DEN_CANON
```

Where:

- `TAG_RAT = 0x03`
- numerator is canonical Int encoding
- denominator is canonical Nat encoding
- denominator must be positive and nonzero
- pair must already be reduced

#### Canonical Zero Rule

All zero rationals must normalize to:

```text
0 / 1
```

and encode only that form.

#### Canonical Examples

```text
1/2   -> [0x03, Int(+1), Nat(2)]
-3/4  -> [0x03, Int(-3), Nat(4)]
0     -> [0x03, Int(0), Nat(1)]
```

---

## 6. Operation Contracts

Operations are defined structurally, not by machine instruction behavior.

Every operation must produce:

1. a normalized structural result,
2. canonical encoding,
3. digest,
4. operation receipt payload.

Initial required operations:

- `nat.eq`
- `nat.cmp`
- `nat.add`
- `nat.sub_checked`
- `nat.mul`

- `int.eq`
- `int.cmp`
- `int.add`
- `int.sub`
- `int.mul`
- `int.neg`

- `rat.eq`
- `rat.cmp`
- `rat.add`
- `rat.sub`
- `rat.mul`
- `rat.div_checked`
- `rat.normalize`

---

### 6.1 nat.eq

#### Contract

\[
\text{nat.eq}(a,b) = (a = b)
\]

#### Output
Boolean.

#### Rule
Equality is equality of canonical magnitude, not pointer identity or host-word identity.

---

### 6.2 nat.cmp

#### Contract

\[
\text{nat.cmp}(a,b) \in \{-1,0,+1\}
\]

#### Rule
Comparison is numeric comparison on natural magnitudes.

---

### 6.3 nat.add

#### Contract

\[
\text{nat.add}(a,b) = a+b
\]

#### Output
Normalized `NatWitness`.

---

### 6.4 nat.sub_checked

#### Contract

\[
\text{nat.sub\_checked}(a,b)
\]

#### Rule

- if \(a \ge b\), return \(a-b\)
- else return domain error `NEGATIVE_NAT_RESULT`

Nat subtraction is checked, not wrapping.

---

### 6.5 nat.mul

#### Contract

\[
\text{nat.mul}(a,b) = a \cdot b
\]

#### Output
Normalized `NatWitness`.

---

### 6.6 int.eq

#### Contract

\[
\text{int.eq}(a,b) = (a = b)
\]

#### Rule
Equality is structural equality after canonical zero collapse.

---

### 6.7 int.cmp

#### Contract

\[
\text{int.cmp}(a,b) \in \{-1,0,+1\}
\]

#### Rule
Signed comparison with canonical zero handling.

---

### 6.8 int.add

#### Contract

\[
\text{int.add}(a,b) = a+b
\]

#### Rules

- same-sign magnitudes add
- opposite-sign magnitudes subtract by larger-minus-smaller
- zero collapses canonically

---

### 6.9 int.sub

#### Contract

\[
\text{int.sub}(a,b) = a + (-b)
\]

---

### 6.10 int.mul

#### Contract

\[
\text{int.mul}(a,b) = a \cdot b
\]

#### Rules

- sign is product of signs
- zero annihilates sign to canonical zero
- magnitude is `nat.mul(|a|, |b|)`

---

### 6.11 int.neg

#### Contract

\[
\text{int.neg}(a) = -a
\]

#### Rules

- `-0 = 0`
- sign flips for nonzero values

---

### 6.12 rat.eq

#### Contract

\[
\text{rat.eq}(a,b) = (a = b)
\]

#### Rule
Equality is equality of canonical reduced form, not cross-multiplication on unreduced values.

Because unreduced values are illegal inputs after normalization.

---

### 6.13 rat.cmp

#### Contract

\[
\text{rat.cmp}(a,b) \in \{-1,0,+1\}
\]

#### Rule

Compare:

\[
a_n \cdot b_d \quad \text{vs} \quad b_n \cdot a_d
\]

using exact integer arithmetic.

---

### 6.14 rat.add

#### Contract

\[
\frac{a}{b} + \frac{c}{d} = \frac{ad + cb}{bd}
\]

#### Output
Must be reduced to canonical rational form.

---

### 6.15 rat.sub

#### Contract

\[
\frac{a}{b} - \frac{c}{d} = \frac{ad - cb}{bd}
\]

#### Output
Must be reduced to canonical rational form.

---

### 6.16 rat.mul

#### Contract

\[
\frac{a}{b} \cdot \frac{c}{d} = \frac{ac}{bd}
\]

#### Output
Must be reduced to canonical rational form.

---

### 6.17 rat.div_checked

#### Contract

\[
\frac{a}{b} \div \frac{c}{d} = \frac{ad}{bc}
\]

#### Rule

- if numerator of divisor is zero, return `DIVIDE_BY_ZERO`
- otherwise normalize and reduce

---

### 6.18 rat.normalize

#### Contract

Normalize any valid rational candidate into canonical form.

#### Rules

For candidate `(num, den)`:

1. `den != 0`
2. move sign into numerator
3. make denominator positive
4. if numerator is zero, return `0/1`
5. divide numerator and denominator by `gcd(|num|, den)`

---

## 7. Overflow Policy

Overflow is not allowed to silently alter arithmetic meaning.

There are only two valid implementation policies:

1. **Unbounded structural arithmetic**
2. **Explicit bounded-native cache overflow with structural fallback**

The initial kernel authority is structural arithmetic.

### 7.1 Structural Truth Rule

Structural arithmetic must not overflow.

If native cached arithmetic overflows, one of the following must happen:

- fallback to structural/unbounded path, or
- mark native acceleration invalid for that step

The step remains valid if the structural result is valid.

### 7.2 Forbidden Policies

The following are forbidden in `ArithCore`:

- wrapping arithmetic as semantic truth
- saturating arithmetic as semantic truth
- implementation-defined overflow semantics
- platform-dependent overflow semantics

### 7.3 Native Cache Overflow Handling

If native representation is bounded, then on overflow:

```text
native_status = overflow
structural_status = authoritative
```

The operation still succeeds if structural arithmetic succeeds.

### 7.4 Strict Mode Overflow Rule

In strict mode, native overflow is irrelevant except as a performance event.

It must not alter result semantics.

### 7.5 Shadow Mode Overflow Rule

In shadow mode, native overflow must be recorded in the arithmetic receipt metadata.

---

## 8. Reduction / Normalization Rules

Normalization is mandatory after every arithmetic operation.

A witness is not complete until normalized.

---

### 8.1 Nat Normalization

Nat normalization rules:

- remove leading zero bytes from magnitude
- map all zero representations to canonical zero
- ensure unique encoding

---

### 8.2 Int Normalization

Int normalization rules:

- if magnitude is zero, sign becomes zero
- zero must canonicalize to unique zero form
- no negative zero allowed

---

### 8.3 Rat Normalization

Rat normalization rules:

- denominator must be positive
- sign moves to numerator
- zero must become `0/1`
- divide numerator and denominator by gcd
- result must be fully reduced

---

### 8.4 Post-Operation Requirement

Every arithmetic operation must return a normalized witness before:

- encoding,
- digesting,
- receipt generation,
- Merkle leaf creation.

---

## 9. Receipt Schema

Each arithmetic primitive produces an arithmetic receipt.

Receipts must be deterministic, serializable, replayable, and hash-stable.

### 9.1 Receipt Purpose

A receipt certifies that:

- a specific operation was invoked,
- on specific canonical operands,
- under a specified mode,
- producing a specific canonical result,
- with specific normalization policy,
- under a specified implementation version.

---

### 9.2 Receipt Logical Shape

```json
{
  "schema": "fard.arith.receipt.v1",
  "op": "int.add",
  "mode": "shadow",
  "lhs_domain": "int",
  "rhs_domain": "int",
  "out_domain": "int",
  "lhs_canon_hex": "...",
  "rhs_canon_hex": "...",
  "out_canon_hex": "...",
  "lhs_digest": "sha256:...",
  "rhs_digest": "sha256:...",
  "out_digest": "sha256:...",
  "native_summary": {
    "used": true,
    "status": "ok",
    "repr": "i64",
    "value_text": "42"
  },
  "structural_summary": {
    "status": "ok"
  },
  "normalization_policy": "arith_core_v0_1_0",
  "overflow_policy": "structural_authoritative_native_fallback",
  "impl_version": "0.1.0",
  "source_location": null,
  "leaf_digest": "sha256:..."
}
```

---

### 9.3 Required Receipt Fields

Required fields:

- `schema`
- `op`
- `mode`
- `lhs_domain`
- `rhs_domain` if binary
- `out_domain`
- `lhs_canon_hex`
- `rhs_canon_hex` if binary
- `out_canon_hex`
- `lhs_digest`
- `rhs_digest` if binary
- `out_digest`
- `normalization_policy`
- `overflow_policy`
- `impl_version`
- `leaf_digest`

Optional but recommended:

- `source_location`
- `native_summary`
- `structural_summary`
- `debug_payload_ref`

---

### 9.4 Leaf Digest Definition

The leaf digest is the SHA-256 of the canonical serialized receipt payload excluding `leaf_digest`.

Formally:

\[
\text{leaf\_digest} = H(\text{canon\_serialize}(\text{receipt\_payload\_without\_leaf\_digest}))
\]

Serialization must itself be canonical.

Recommended canonical serialization:

- sorted keys,
- UTF-8,
- no insignificant whitespace,
- fixed field ordering if not JSON-canonicalized.

---

## 10. Merkle Block Schema

Arithmetic receipts must aggregate into Merkle blocks for semantic regions.

### 10.1 Purpose

Merkle blocks prevent trace explosion while preserving cryptographic commitment to every arithmetic step.

### 10.2 Semantic Region Examples

A Merkle block may correspond to:

- one expression,
- one statement,
- one function invocation,
- one loop iteration,
- one basic block,
- one evaluator reduction region.

### 10.3 Merkle Block Shape

```json
{
  "schema": "fard.arith.block.v1",
  "block_id": "loop_iter_00042",
  "region_kind": "while_iteration",
  "leaf_count": 12,
  "leaf_digests": [
    "sha256:...",
    "sha256:..."
  ],
  "merkle_root": "sha256:...",
  "storage_policy": "commit_only",
  "impl_version": "0.1.0"
}
```

### 10.4 Required Fields

Required fields:

- `schema`
- `block_id`
- `region_kind`
- `leaf_count`
- `merkle_root`
- `storage_policy`
- `impl_version`

Optional fields:

- `leaf_digests`
- `debug_payload_refs`
- `source_location_range`

### 10.5 Merkle Construction Rule

Leaves are ordered by execution order within the semantic region.

If the number of leaves is odd, implementation must define one stable rule and use it globally:

- duplicate last leaf, or
- promote lone node unchanged.

Policy must be fixed and documented.

### 10.6 Empty Block Rule

If a semantic region contains zero arithmetic steps, either:

1. no block is emitted, or
2. a fixed empty-root sentinel is emitted.

Policy must be globally fixed.

---

## 11. Shadow vs Strict Execution Semantics

This section defines the exact authority ordering.

---

### 11.1 Shadow Mode

In shadow mode:

1. native arithmetic may execute first,
2. structural arithmetic must also execute,
3. structural result must be normalized,
4. native and structural meanings must be compared,
5. receipt must record verdict.

#### Shadow Success Rule

If native and structural results agree:

```text
verdict = ok
```

and the operation succeeds.

#### Shadow Failure Rule

If native and structural results disagree:

```text
verdict = mismatch
```

and the operation must fail hard unless an explicitly weaker debug policy is enabled.

#### Shadow Authority Rule

Even in shadow mode, structural arithmetic defines semantic correctness.

The native result is a comparison target, not ultimate truth.

#### Shadow Persistence Rule

At minimum, leaf commitments must persist.

Full witness bodies may be:

- omitted,
- sampled,
- region-persisted,
- or fully persisted,

according to storage policy.

---

### 11.2 Strict Mode

In strict mode:

1. structural arithmetic executes,
2. normalized structural result becomes authoritative,
3. canonical encoding is produced,
4. receipt is emitted,
5. native arithmetic is optional cache only.

#### Strict Success Rule

If structural arithmetic succeeds, the operation succeeds.

#### Strict Native Cache Rule

If a native cache exists:

- it may be populated from structural result,
- it may be checked against structural result,
- it may be omitted entirely.

#### Strict Mismatch Rule

If optional native cache disagrees with structural result, native cache is invalid and must be discarded or marked erroneous.

The structural result remains authoritative.

---

### 11.3 Mode Summary

| Property | Shadow | Strict |
|---|---|---|
| Native arithmetic allowed | Yes | Optional |
| Structural arithmetic required | Yes | Yes |
| Structural result authoritative | Yes | Yes |
| Native result may decide semantics | No | No |
| Mismatch allowed silently | No | No |
| Receipt leaf required | Yes | Yes |

---

## 12. Replay Verification Contract

Replay verification proves that the arithmetic history is reproducible.

### 12.1 Replay Goal

Given:

- operation sequence,
- canonical operands,
- mode semantics,
- normalization rules,
- overflow policy,
- implementation version,

replay must recompute the same:

- normalized outputs,
- receipt leaves,
- Merkle roots.

### 12.2 Replay Input Requirements

Replay verifier must have access to:

- receipt payloads or canonical re-derivable operation logs,
- canonical operand encodings,
- implementation version,
- normalization policy,
- overflow policy,
- Merkle aggregation policy.

### 12.3 Replay Output

Replay must return:

```json
{
  "schema": "fard.arith.replay.v1",
  "ok": true,
  "leaf_count": 12,
  "recomputed_merkle_root": "sha256:...",
  "expected_merkle_root": "sha256:...",
  "impl_version": "0.1.0"
}
```

or a failure object:

```json
{
  "schema": "fard.arith.replay.v1",
  "ok": false,
  "failure_kind": "leaf_digest_mismatch",
  "index": 7,
  "expected": "sha256:...",
  "actual": "sha256:...",
  "impl_version": "0.1.0"
}
```

### 12.4 Replay Success Condition

Replay succeeds iff:

1. every operation re-normalizes to the same canonical result,
2. every leaf digest recomputes identically,
3. every Merkle block recomputes identically.

### 12.5 Replay Failure Kinds

Minimum required failure kinds:

- `operand_decode_failure`
- `normalization_failure`
- `divide_by_zero`
- `native_shadow_mismatch`
- `leaf_digest_mismatch`
- `merkle_root_mismatch`
- `policy_mismatch`
- `impl_version_mismatch`

### 12.6 Replay Determinism Requirement

Replay must not depend on:

- host pointer layout,
- CPU architecture arithmetic quirks,
- thread interleaving,
- map/dictionary iteration nondeterminism,
- non-canonical serialization.

---

## 13. Recommended Rust Type Surface

This section is informative but intended to align implementation.

```rust
pub enum ArithMode {
    Shadow,
    Strict,
}

pub struct NatWitness {
    pub canon: Vec<u8>,
}

pub struct IntWitness {
    pub canon: Vec<u8>,
}

pub struct RatWitness {
    pub canon: Vec<u8>,
}

pub enum StructuralNumber {
    Nat(NatWitness),
    Int(IntWitness),
    Rat(RatWitness),
}
```

Recommended runtime augmentation:

```rust
pub struct NativeCache {
    pub repr_kind: &'static str,
    pub value_text: String,
    pub valid: bool,
}

pub struct StructuralCarrier<T> {
    pub witness: T,
    pub digest_hex: String,
    pub native_cache: Option<NativeCache>,
}
```

---

## 14. Required Invariants

The implementation must preserve all of the following.

### 14.1 Canonical Identity Invariant

Equal structural values must have identical canonical encodings.

### 14.2 Digest Stability Invariant

Equal canonical encodings must produce identical digests.

### 14.3 Zero Uniqueness Invariant

There is exactly one zero for Nat, one zero for Int, and one zero rational form `0/1`.

### 14.4 Rational Reduction Invariant

All rational outputs are reduced.

### 14.5 Semantic Authority Invariant

Structural result is always semantically authoritative.

### 14.6 Receipt Determinism Invariant

Equivalent arithmetic steps under same policy and version produce identical leaf digests.

### 14.7 Merkle Determinism Invariant

Equivalent leaf sequences under same Merkle policy produce identical roots.

---

## 15. Initial Non-Goals

This version does not define:

- floating-point arithmetic,
- transcendental functions,
- real analysis objects,
- interval arithmetic,
- spectral arithmetic,
- Hilbert-space operators,
- symbolic algebra beyond exact Nat/Int/Rat,
- proof-term embedding format.

Those may be added later above this kernel.

---

## 16. Acceptance Criteria for v0.1.0

`ArithCore v0.1.0` is considered implemented when all of the following are true:

1. Nat, Int, and Rat have unique canonical encodings.
2. Nat/Int/Rat normalization rules are implemented.
3. Required operations are implemented.
4. Overflow never silently changes arithmetic semantics.
5. Arithmetic receipts are emitted deterministically.
6. Merkle blocks are emitted deterministically.
7. Shadow mode mismatch detection works.
8. Strict mode structural authority works.
9. Replay recomputes leaf digests and Merkle roots exactly.
10. Tests prove encoding stability, reduction correctness, receipt determinism, and replay reproducibility.

---

## 17. Final Statement

The purpose of `ArithCore` is to establish arithmetic identity as a structural fact rather than a host-language assumption.

In this system:

- a number is a witness,
- a result is a normalized structural artifact,
- a receipt is a cryptographic commitment to that arithmetic fact,
- and replay is the proof that the same arithmetic history occurred.

That is the arithmetic contract beneath the future FARD kernel.
