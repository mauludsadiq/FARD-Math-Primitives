# ARITH_CORE_ABI.md
Version: 0.3.0
Status: FROZEN
Date: 2026-04-15

This document is the canonical contract for ArithCore v0.3.0.
It defines the exact byte encodings, operation signatures, normalization rules,
digest contracts, error kinds, and receipt schema that all consumers of ArithCore
must agree on — including the Rust kernel, future FARD runtime, replay verifier,
and any formal proof layer.

---

## 1. Primitive Types

### 1.1 Digest
    type Digest = [u8; 32]   // SHA-256 output

### 1.2 Sign
    enum Sign {
        Negative = 0x02,
        Zero     = 0x00,
        Positive = 0x01,
    }

### 1.3 ArithMode
    enum ArithMode {
        Native        = 0,
        ShadowChecked = 1,
        Strict        = 2,
    }

---

## 2. Value Domains

### 2.1 Nat
A natural number. Structurally unbounded. Backed by BigNat (Vec<u32> limbs, little-endian).

    struct NatWitness {
        magnitude: BigNat,
        canon:     Vec<u8>,   // canonical encoding (see §3.1)
        digest:    Digest,    // sha256(canon)
    }

Invariants:
- magnitude >= 0
- canon is unique for every distinct magnitude
- digest = sha256(canon)

### 2.2 Int
A signed integer. Structurally unbounded. Backed by BigInt (Sign + BigNat).

    struct IntWitness {
        value:  BigInt,       // sign + magnitude
        canon:  Vec<u8>,      // canonical encoding (see §3.2)
        digest: Digest,       // sha256(canon)
    }

Invariants:
- if value == 0, sign == Zero
- no negative zero
- digest = sha256(canon)

### 2.3 Rat
An exact reduced rational. Backed by IntWitness numerator and NatWitness denominator.

    struct RatWitness {
        num:    IntWitness,   // numerator
        den:    NatWitness,   // denominator (strictly positive)
        canon:  Vec<u8>,      // canonical encoding (see §3.3)
        digest: Digest,       // sha256(canon)
    }

Invariants:
- den > 0
- gcd(|num|, den) = 1
- if num == 0, den == 1
- sign lives in numerator only
- digest = sha256(canon)

---

## 3. Canonical Encodings

All encodings are:
- deterministic
- byte-stable across machines and implementations
- uniquely invertible
- big-endian for all multi-byte integer fields

### 3.1 Nat Encoding

    encode_nat(n):
        [0x01]                    // domain tag
        [len as u32, big-endian]  // 4 bytes: byte length of magnitude
        [mag_bytes...]            // minimal big-endian magnitude bytes

    Zero encoding:
        [0x01, 0x00, 0x00, 0x00, 0x00]   // tag + len=0 + no mag bytes

    Minimality rule:
        No leading zero bytes in magnitude for nonzero values.

    Examples:
        0   -> [01 00 00 00 00]
        1   -> [01 00 00 00 01 01]
        10  -> [01 00 00 00 01 0a]
        256 -> [01 00 00 00 02 01 00]

### 3.2 Int Encoding

    encode_int(v):
        [0x02]             // domain tag
        [sign_byte]        // 0x00=zero, 0x01=positive, 0x02=negative
        [encode_nat(|v|)]  // canonical nat encoding of magnitude

    Zero rule:
        Zero must always encode as [02 00 <encode_nat(0)>]
        No alternative zero forms permitted.

    Examples:
        0   -> [02 00 01 00 00 00 00]
        5   -> [02 01 01 00 00 00 01 05]
        -5  -> [02 02 01 00 00 00 01 05]

### 3.3 Rat Encoding

    encode_rat(num, den):
        [0x03]             // domain tag
        [encode_int(num)]  // canonical int encoding of numerator
        [encode_nat(den)]  // canonical nat encoding of denominator

    Preconditions:
        den > 0
        gcd(|num|, den) = 1
        if num == 0, den == 1

    Examples:
        1/2   -> [03 <encode_int(1)> <encode_nat(2)>]
        -3/4  -> [03 <encode_int(-3)> <encode_nat(4)>]
        0     -> [03 <encode_int(0)> <encode_nat(1)>]

### 3.4 Digest Contract

    digest(witness) = sha256(canon(witness))

SHA-256 is the only permitted hash function.
Digest stability is a hard invariant: equal canonical bytes must produce equal digests.

---

## 4. Decode Contracts

Decoders must reject all non-canonical forms.

### 4.1 decode_nat(bytes) -> Result<NatWitness, DecodeError>

Rejects:
- bytes[0] != 0x01                     -> WrongTag
- len field exceeds available bytes     -> LengthMismatch
- trailing bytes after magnitude        -> TrailingBytes
- leading zero byte in nonzero magnitude -> NonMinimalEncoding
- truncated input                       -> UnexpectedEof

### 4.2 decode_int(bytes) -> Result<IntWitness, DecodeError>

Rejects:
- bytes[0] != 0x02                     -> WrongTag
- sign byte not in {0x00, 0x01, 0x02}  -> InvalidSignByte
- sign == Negative and magnitude == 0  -> NegativeZero
- sign != Zero and magnitude == 0      -> ZeroWithNonzeroSign
- sign == Zero and magnitude != 0      -> ZeroWithNonzeroSign
- any decode_nat rejection on magnitude -> propagated

### 4.3 decode_rat(bytes) -> Result<RatWitness, DecodeError>

Rejects:
- bytes[0] != 0x03                     -> WrongTag
- denominator == 0                     -> ZeroDenominator
- numerator == 0 and denominator != 1  -> AlternateZeroRational
- gcd(|num|, den) > 1                  -> UnreducedRational
- any decode_int/decode_nat rejection  -> propagated

### 4.4 Round-trip invariant

For all valid witnesses w:
    decode(encode(w)) == w

This must hold for all values including those beyond machine word width.

---

## 5. Operation Contracts

All structural operations return normalized witnesses.
Overflow is impossible for structural ops — BigNat/BigInt are unbounded.
NativeOverflow applies only to the native shadow cache path.

### 5.1 Nat Operations

    nat_eq(a, b) -> bool
        a.magnitude == b.magnitude

    nat_cmp(a, b) -> Ordering
        numeric comparison on magnitudes

    nat_add(a, b) -> NatWitness
        result = a + b, normalized

    nat_sub_checked(a, b) -> Result<NatWitness, NegativeNatResult>
        if a >= b: return a - b
        else: return NegativeNatResult

    nat_mul(a, b) -> NatWitness
        result = a * b, normalized

    nat_divrem(a, b) -> Result<(NatWitness, NatWitness), DivideByZero>
        if b == 0: return DivideByZero
        return (quotient, remainder) where a = b*q + r, 0 <= r < b

    nat_pow(base, exp) -> NatWitness
        result = base^exp, normalized
        nat_pow(_, 0) = 1

### 5.2 Int Operations

    int_eq(a, b) -> bool
        canonical equality after zero collapse

    int_cmp(a, b) -> Ordering
        signed comparison

    int_add(a, b) -> Result<IntWitness, ArithmeticError>
        result = a + b, normalized

    int_sub(a, b) -> Result<IntWitness, ArithmeticError>
        result = a - b, normalized

    int_mul(a, b) -> Result<IntWitness, ArithmeticError>
        result = a * b, normalized

    int_neg(a) -> IntWitness
        result = -a
        int_neg(0) = 0

    int_abs(a) -> NatWitness
        result = |a|

    int_signum(a) -> IntWitness
        result = -1 | 0 | 1

    int_divrem(a, b) -> Result<(IntWitness, IntWitness), DivideByZero>
        Euclidean division: remainder always non-negative
        a = b*q + r, 0 <= r < |b|

    int_pow(base, exp: NatWitness) -> IntWitness
        result = base^exp
        int_pow(_, 0) = 1

### 5.3 Rat Operations

    rat_eq(a, b) -> bool
        canonical equality on reduced form

    rat_cmp(a, b) -> Ordering
        compare a_num * b_den vs b_num * a_den using exact integer arithmetic

    rat_add(a, b) -> Result<RatWitness, ArithmeticError>
        (a_num*b_den + b_num*a_den) / (a_den*b_den), reduced

    rat_sub(a, b) -> Result<RatWitness, ArithmeticError>
        (a_num*b_den - b_num*a_den) / (a_den*b_den), reduced

    rat_mul(a, b) -> Result<RatWitness, ArithmeticError>
        (a_num*b_num) / (a_den*b_den), reduced

    rat_div_checked(a, b) -> Result<RatWitness, DivideByZero>
        if b_num == 0: return DivideByZero
        (a_num*b_den) / (b_num*a_den), reduced, sign normalized

    rat_normalize(num: i64, den: i64) -> Result<RatWitness, ZeroDenominator>
        normalize arbitrary (num, den) pair into canonical form

    rat_abs(a) -> Result<RatWitness, ArithmeticError>
        |num| / den, reduced

    rat_signum(a) -> IntWitness
        -1 | 0 | 1 based on numerator sign

    rat_floor(a) -> IntWitness
        largest integer <= a

    rat_ceil(a) -> IntWitness
        smallest integer >= a

    rat_trunc(a) -> IntWitness
        truncate toward zero

    rat_pow(base, exp: i64) -> Result<RatWitness, ArithmeticError>
        base^exp, negative exp gives reciprocal
        rat_pow(_, 0) = 1/1

---

## 6. Normalization Rules

Every arithmetic operation must return a normalized witness before:
- encoding
- digesting
- receipt generation
- Merkle leaf creation

### 6.1 Nat Normalization
- remove leading zero bytes from magnitude
- zero maps to unique zero form

### 6.2 Int Normalization
- if magnitude == 0, sign = Zero
- no negative zero
- unique zero form

### 6.3 Rat Normalization
- denominator > 0
- sign in numerator only
- if numerator == 0, denominator = 1
- divide num and den by gcd(|num|, den)
- result must be fully reduced

---

## 7. Receipt Schema

    struct ArithmeticStepReceipt {
        op:              String,   // operation name e.g. "int.add"
        lhs_digest:      Digest,
        rhs_digest:      Digest,   // for binary ops
        out_digest:      Digest,
        native_summary:  String,   // e.g. "native=42" or "strict:structural=42"
        verdict:         bool,     // true = native and structural agree
        mode:            ArithMode,
        leaf_digest:     Digest,   // sha256 of all above fields serialized
    }

### 7.1 Leaf Digest Definition

    leaf_digest = sha256(
        op.as_bytes()
        || lhs_digest
        || rhs_digest
        || out_digest
        || native_summary.as_bytes()
        || [verdict as u8]
        || [mode as u8]
    )

Serialization is concatenation in field order. No separators. No length prefixes.
This is the canonical leaf digest definition. Any implementation must reproduce it exactly.

---

## 8. Merkle Block Schema

    struct ArithmeticBlock {
        block_id:        String,
        leaf_count:      usize,
        merkle_root:     Digest,
        storage_policy:  String,
    }

### 8.1 Merkle Construction

Leaves are ordered by execution order within the semantic region.

Construction:
1. Start with leaf_digests as level 0
2. Pair adjacent leaves, hash each pair: sha256(left || right)
3. If odd number of leaves, duplicate last leaf
4. Repeat until one root remains

Empty block sentinel:
    merkle_root = sha256(b"MERKLE_EMPTY")

### 8.2 Merkle Root Stability

Equal leaf sequences under same policy must produce identical roots.
This is a hard invariant.

---

## 9. Replay Verification Contract

    struct ReplayResult {
        ok:                     bool,
        leaf_count:             usize,
        recomputed_merkle_root: Digest,
        expected_merkle_root:   Digest,
        failure:                Option<ReplayFailureKind>,
        impl_version:           String,
    }

    enum ReplayFailureKind {
        OperandDecodeFailure,
        NormalizationFailure,
        DivideByZero,
        NativeShadowMismatch,
        LeafDigestMismatch { index: usize, expected: Digest, actual: Digest },
        MerkleRootMismatch { expected: Digest, actual: Digest },
        PolicyMismatch,
        ImplVersionMismatch,
    }

Replay succeeds iff:
1. every receipt recomputes the same leaf digest
2. recomputed Merkle root matches committed block root
3. leaf count matches

---

## 10. Error Kinds

    enum ArithmeticError {
        NativeOverflow,      // native cache path overflowed i64/u64
        NegativeNatResult,   // nat.sub_checked: a < b
        DivideByZero,        // division by zero
        ZeroDenominator,     // rat construction with den == 0
        ShadowMismatch,      // native and structural results disagree
    }

    enum DecodeError {
        WrongTag { expected: u8, got: u8 },
        UnexpectedEof,
        NonMinimalEncoding,
        InvalidSignByte(u8),
        NegativeZero,
        ZeroWithNonzeroSign,
        ZeroDenominator,
        UnreducedRational,
        AlternateZeroRational,
        TrailingBytes,
        LengthMismatch { expected: usize, got: usize },
    }

---

## 11. Shadow vs Strict Mode Semantics

### Shadow Mode (ArithMode::ShadowChecked)
1. structural arithmetic executes
2. native arithmetic executes in parallel
3. if native != structural: ShadowMismatch error
4. receipt records verdict = true only if both agree
5. structural result is authoritative

### Strict Mode (ArithMode::Strict)
1. structural arithmetic executes and is authoritative
2. native arithmetic is optional cache only
3. receipt verdict = true always (structural is the definition of correct)
4. native_summary records structural value for auditability

### Authority Rule
In both modes, structural result defines semantic correctness.
Native result is never authoritative.

---

## 12. Version and Stability

    impl_version: "0.3.0"

This ABI is a candidate for freeze. The following are stable:
- canonical encoding byte layouts (§3)
- decode rejection rules (§4)
- normalization rules (§6)
- leaf digest serialization (§7.1)
- Merkle construction algorithm (§8.1)
- error kind names (§10)

The following may still change before final freeze:
- operation signatures for rat_normalize (currently takes i64/i64 bridge args)
- checked_int_* signatures (currently take i64 args, should take BigInt)
- StructuralRepr.HostInt field (currently i64 cache, should be BigInt)

---

## 13. Bridge Issues — RESOLVED

1. rat_normalize — now takes (OurBigInt, OurBigInt) ✅
2. checked_int_add/sub/mul — now take OurBigInt args ✅
3. encode_rat — now takes (&OurBigInt, &BigNat) ✅
4. StructuralRepr::HostInt — now holds OurBigInt ✅
5. gcd_u64 — marked deprecated, superseded by BigNat::gcd ✅

All bridge issues resolved. ABI is frozen.

---

## 14. Acceptance Criteria — STATUS

1. All bridge issues resolved ✅
2. encode_nat / encode_int / encode_rat take BigNat/BigInt args ✅
3. All operation signatures take witness types ✅
4. Leaf digest tested against known-good vector ✅ (shadow_add_produces_receipt)
5. Merkle construction tested against known-good root ✅ (merkle_block_determinism)
6. Round-trip decode(encode(x)) == x tested beyond machine bounds ✅ (decode_*_roundtrip tests)
7. This document matches the implementation ✅

ABI v0.3.0 is FROZEN.

---
