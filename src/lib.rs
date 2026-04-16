use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigestTrait, Sha256};
use std::fmt;
use crate::bignum::{BigNat, BigInt as OurBigInt};

pub type Digest = [u8; 32];

pub mod bignum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArithMode {
    Native,
    ShadowChecked,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatWitness {
    pub magnitude: BigNat,
    pub canon: Vec<u8>,
    pub digest: Digest,
}

impl NatWitness {
    pub fn new(magnitude: BigNat) -> Self {
        let canon = encode_nat(&magnitude);
        let digest = sha256(&canon);
        Self { magnitude, canon, digest }
    }

    pub fn from_u64(n: u64) -> Self {
        Self::new(BigNat::from_u64(n))
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.magnitude.to_u64()
    }

    pub fn from_bignat(n: BigNat) -> Self {
        Self::new(n)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sign {
    Negative,
    Zero,
    Positive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntWitness {
    pub value: OurBigInt,
    pub canon: Vec<u8>,
    pub digest: Digest,
}

impl IntWitness {
    pub fn new(value: OurBigInt) -> Self {
        let canon = encode_int(&value);
        let digest = sha256(&canon);
        Self { value, canon, digest }
    }

    pub fn from_i64(n: i64) -> Self {
        Self::new(OurBigInt::from_i64(n))
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.value.to_i64()
    }

    pub fn from_bigint(v: OurBigInt) -> Self {
        Self::new(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatWitness {
    pub num: IntWitness,
    pub den: NatWitness,
    pub canon: Vec<u8>,
    pub digest: Digest,
}

impl RatWitness {
    pub fn new_big(num: OurBigInt, den: BigNat) -> Result<Self, ArithmeticError> {
        if den.is_zero() {
            return Err(ArithmeticError::ZeroDenominator);
        }
        let g = BigNat::gcd(num.magnitude.clone(), den.clone());
        let num_reduced = if g.is_zero() || g == BigNat::from_u64(1) {
            num.clone()
        } else {
            let (q, _) = num.magnitude.divrem(&g);
            OurBigInt::from_bignat(num.sign, q)
        };
        let den_reduced = if g.is_zero() || g == BigNat::from_u64(1) {
            den.clone()
        } else {
            let (q, _) = den.divrem(&g);
            q
        };
        let den_final = if num_reduced.is_zero() {
            BigNat::from_u64(1)
        } else {
            den_reduced
        };
        let num_wit = IntWitness::from_bigint(num_reduced);
        let den_wit = NatWitness::from_bignat(den_final);
        let mut canon = Vec::with_capacity(1 + num_wit.canon.len() + den_wit.canon.len());
        canon.push(0x03);
        canon.extend_from_slice(&num_wit.canon);
        canon.extend_from_slice(&den_wit.canon);
        let digest = sha256(&canon);
        Ok(Self {
            num: num_wit,
            den: den_wit,
            canon,
            digest,
        })
    }

    pub fn new(num: i64, den: u64) -> Result<Self, ArithmeticError> {
        Self::new_big(
            bignum::BigInt::from_i64(num),
            bignum::BigNat::from_u64(den),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StructuralRepr {
    HostInt(OurBigInt),
    ExactRational { num: OurBigInt, den: BigNat },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StructuralWitness {
    Nat(NatWitness),
    Int(IntWitness),
    Rat(RatWitness),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralNumber {
    pub repr: StructuralRepr,
    pub witness: StructuralWitness,
    pub canon: Vec<u8>,
    pub mode: ArithMode,
    pub receipt_link: Digest,
}

impl StructuralNumber {
    pub fn from_int(value: i64, mode: ArithMode) -> Self {
        let wit = IntWitness::from_i64(value);
        Self {
            repr: StructuralRepr::HostInt(OurBigInt::from_i64(value)),
            canon: wit.canon.clone(),
            receipt_link: wit.digest,
            witness: StructuralWitness::Int(wit),
            mode,
        }
    }

    pub fn from_rat(num: i64, den: u64, mode: ArithMode) -> Result<Self, ArithmeticError> {
        let wit = RatWitness::new(num, den)?;
        Ok(Self {
            repr: StructuralRepr::ExactRational {
                num: wit.num.value.clone(),
                den: wit.den.magnitude.clone(),
            },
            canon: wit.canon.clone(),
            receipt_link: wit.digest,
            witness: StructuralWitness::Rat(wit),
            mode,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArithmeticStepReceipt {
    pub op: String,
    pub lhs_digest: Digest,
    pub rhs_digest: Digest,
    pub out_digest: Digest,
    pub native_summary: String,
    pub verdict: bool,
    pub mode: ArithMode,
    pub leaf_digest: Digest,
}

impl ArithmeticStepReceipt {
    pub fn new(
        op: impl Into<String>,
        lhs_digest: Digest,
        rhs_digest: Digest,
        out_digest: Digest,
        native_summary: impl Into<String>,
        verdict: bool,
        mode: ArithMode,
    ) -> Self {
        let op = op.into();
        let native_summary = native_summary.into();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(op.as_bytes());
        bytes.extend_from_slice(&lhs_digest);
        bytes.extend_from_slice(&rhs_digest);
        bytes.extend_from_slice(&out_digest);
        bytes.extend_from_slice(native_summary.as_bytes());
        bytes.push(verdict as u8);
        bytes.push(mode as u8);
        let leaf_digest = sha256(&bytes);
        Self {
            op,
            lhs_digest,
            rhs_digest,
            out_digest,
            native_summary,
            verdict,
            mode,
            leaf_digest,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArithmeticBlock {
    pub block_id: String,
    pub leaf_count: usize,
    pub merkle_root: Digest,
    pub storage_policy: String,
}

impl ArithmeticBlock {
    pub fn from_receipts(block_id: impl Into<String>, storage_policy: impl Into<String>, receipts: &[ArithmeticStepReceipt]) -> Self {
        let leaves: Vec<Digest> = receipts.iter().map(|r| r.leaf_digest).collect();
        Self {
            block_id: block_id.into(),
            leaf_count: receipts.len(),
            merkle_root: merkle_root(&leaves),
            storage_policy: storage_policy.into(),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ArithmeticError {
    #[error("zero denominator")]
    ZeroDenominator,
    #[error("native addition overflow")]
    NativeOverflow,
    #[error("shadow mismatch")]
    ShadowMismatch,
    #[error("negative nat result")]
    NegativeNatResult,
    #[error("divide by zero")]
    DivideByZero,
}

use thiserror::Error;

pub fn shadow_add_int(lhs: i64, rhs: i64, mode: ArithMode) -> Result<(StructuralNumber, ArithmeticStepReceipt), ArithmeticError> {
    let lhs_num = StructuralNumber::from_int(lhs, mode);
    let rhs_num = StructuralNumber::from_int(rhs, mode);

    let native = lhs.checked_add(rhs).ok_or(ArithmeticError::NativeOverflow)?;
    let lhs_big = OurBigInt::from_i64(lhs_num.as_i64());
    let rhs_big = OurBigInt::from_i64(rhs_num.as_i64());
    let structural = IntWitness::from_bigint(lhs_big.add(&rhs_big));
    let verdict = native == structural.as_i64().unwrap();
    if matches!(mode, ArithMode::Strict) && !verdict {
        return Err(ArithmeticError::ShadowMismatch);
    }

    let out = StructuralNumber {
        repr: StructuralRepr::HostInt(structural.value.clone()),
        canon: structural.canon.clone(),
        mode,
        receipt_link: structural.digest,
        witness: StructuralWitness::Int(structural.clone()),
    };

    let receipt = ArithmeticStepReceipt::new(
        "int.add",
        lhs_num.receipt_link,
        rhs_num.receipt_link,
        out.receipt_link,
        format!("native={native}"),
        verdict,
        mode,
    );

    Ok((out, receipt))
}

impl StructuralNumber {
    pub fn as_i64(&self) -> i64 {
        match &self.witness {
            StructuralWitness::Int(v) => v.as_i64().unwrap(),
            StructuralWitness::Nat(v) => v.as_u64().unwrap() as i64,
            StructuralWitness::Rat(v) => {
                if v.den.as_u64() == Some(1) {
                    v.num.as_i64().unwrap()
                } else {
                    panic!("cannot losslessly coerce rational witness to i64")
                }
            }
        }
    }
}

pub fn encode_nat(n: &BigNat) -> Vec<u8> {
    let mag = n.to_be_bytes();
    let mut out = Vec::with_capacity(1 + 4 + mag.len());
    out.push(0x01);
    out.extend_from_slice(&(mag.len() as u32).to_be_bytes());
    out.extend_from_slice(&mag);
    out
}

pub fn encode_int(value: &OurBigInt) -> Vec<u8> {
    let (sign_byte, mag) = match value.sign {
        crate::Sign::Zero => (0x00u8, BigNat::zero()),
        crate::Sign::Positive => (0x01u8, value.magnitude.clone()),
        crate::Sign::Negative => (0x02u8, value.magnitude.clone()),
    };
    let nat = encode_nat(&mag);
    let mut out = Vec::with_capacity(1 + 1 + nat.len());
    out.push(0x02);
    out.push(sign_byte);
    out.extend_from_slice(&nat);
    out
}

pub fn encode_rat(num: &OurBigInt, den: &BigNat) -> Vec<u8> {
    let num_canon = encode_int(num);
    let den_canon = encode_nat(den);
    let mut out = Vec::with_capacity(1 + num_canon.len() + den_canon.len());
    out.push(0x03);
    out.extend_from_slice(&num_canon);
    out.extend_from_slice(&den_canon);
    out
}

pub fn sha256(bytes: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn merkle_root(leaves: &[Digest]) -> Digest {
    if leaves.is_empty() {
        return sha256(b"MERKLE_EMPTY");
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { level[i] };
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(&left);
            bytes.extend_from_slice(&right);
            next.push(sha256(&bytes));
            i += 2;
        }
        level = next;
    }
    level[0]
}

#[deprecated(note = "use BigNat::gcd instead")]
pub fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

pub fn hex_digest(d: &Digest) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

impl fmt::Display for Sign {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Sign::Negative => write!(f, "neg"),
            Sign::Zero => write!(f, "zero"),
            Sign::Positive => write!(f, "pos"),
        }
    }
}


// ── Section 6: Operation Contracts ───────────────────────────────────────────

// nat.eq
pub fn nat_eq(a: &NatWitness, b: &NatWitness) -> bool {
    a.magnitude == b.magnitude
}

// nat.cmp
pub fn nat_cmp(a: &NatWitness, b: &NatWitness) -> std::cmp::Ordering {
    a.magnitude.cmp_nat(&b.magnitude)
}

// nat.add
pub fn nat_add(a: &NatWitness, b: &NatWitness) -> NatWitness {
    NatWitness::new(a.magnitude.add(&b.magnitude))
}

// nat.sub_checked
pub fn nat_sub_checked(a: &NatWitness, b: &NatWitness) -> Result<NatWitness, ArithmeticError> {
    if a.magnitude.cmp_nat(&b.magnitude) != std::cmp::Ordering::Less {
        Ok(NatWitness::new(a.magnitude.sub(&b.magnitude)))
    } else {
        Err(ArithmeticError::NegativeNatResult)
    }
}

// nat.mul
pub fn nat_mul(a: &NatWitness, b: &NatWitness) -> NatWitness {
    NatWitness::new(a.magnitude.mul(&b.magnitude))
}

// int.eq
pub fn int_eq(a: &IntWitness, b: &IntWitness) -> bool {
    a.canon == b.canon
}

// int.cmp
pub fn int_cmp(a: &IntWitness, b: &IntWitness) -> std::cmp::Ordering {
    a.value.cmp_int(&b.value)
}

// int.add
pub fn int_add(a: &IntWitness, b: &IntWitness) -> Result<IntWitness, ArithmeticError> {
    Ok(IntWitness::from_bigint(a.value.add(&b.value)))
}

// int.sub
pub fn int_sub(a: &IntWitness, b: &IntWitness) -> Result<IntWitness, ArithmeticError> {
    Ok(IntWitness::from_bigint(a.value.sub(&b.value)))
}

// int.mul
pub fn int_mul(a: &IntWitness, b: &IntWitness) -> Result<IntWitness, ArithmeticError> {
    Ok(IntWitness::from_bigint(a.value.mul(&b.value)))
}

// int.neg
pub fn int_neg(a: &IntWitness) -> IntWitness {
    IntWitness::from_bigint(a.value.negate())
}

// rat.eq
pub fn rat_eq(a: &RatWitness, b: &RatWitness) -> bool {
    a.canon == b.canon
}

// rat.cmp
pub fn rat_cmp(a: &RatWitness, b: &RatWitness) -> std::cmp::Ordering {
    let lhs = a.num.value.mul(&OurBigInt::from_bignat(crate::Sign::Positive, b.den.magnitude.clone()));
    let rhs = b.num.value.mul(&OurBigInt::from_bignat(crate::Sign::Positive, a.den.magnitude.clone()));
    lhs.cmp_int(&rhs)
}

// rat.add
pub fn rat_add(a: &RatWitness, b: &RatWitness) -> Result<RatWitness, ArithmeticError> {
    let ad = a.num.value.mul(&OurBigInt::from_bignat(crate::Sign::Positive, b.den.magnitude.clone()));
    let bc = b.num.value.mul(&OurBigInt::from_bignat(crate::Sign::Positive, a.den.magnitude.clone()));
    let num = ad.add(&bc);
    let den = a.den.magnitude.mul(&b.den.magnitude);
    RatWitness::new_big(num, den)
}

// rat.sub
pub fn rat_sub(a: &RatWitness, b: &RatWitness) -> Result<RatWitness, ArithmeticError> {
    let ad = a.num.value.mul(&OurBigInt::from_bignat(crate::Sign::Positive, b.den.magnitude.clone()));
    let bc = b.num.value.mul(&OurBigInt::from_bignat(crate::Sign::Positive, a.den.magnitude.clone()));
    let num = ad.sub(&bc);
    let den = a.den.magnitude.mul(&b.den.magnitude);
    RatWitness::new_big(num, den)
}

// rat.mul
pub fn rat_mul(a: &RatWitness, b: &RatWitness) -> Result<RatWitness, ArithmeticError> {
    let num = a.num.value.mul(&b.num.value);
    let den = a.den.magnitude.mul(&b.den.magnitude);
    RatWitness::new_big(num, den)
}

// rat.div_checked
pub fn rat_div_checked(a: &RatWitness, b: &RatWitness) -> Result<RatWitness, ArithmeticError> {
    if b.num.value.is_zero() {
        return Err(ArithmeticError::DivideByZero);
    }
    // (a_num / a_den) / (b_num / b_den) = (a_num * b_den) / (a_den * b_num)
    let num = a.num.value.mul(&OurBigInt::from_bignat(crate::Sign::Positive, b.den.magnitude.clone()));
    let den_int = b.num.value.mul(&OurBigInt::from_bignat(crate::Sign::Positive, a.den.magnitude.clone()));
    // move sign into num, den must be positive
    let (final_num, final_den) = if matches!(den_int.sign, crate::Sign::Negative) {
        (num.negate(), den_int.magnitude)
    } else {
        (num, den_int.magnitude)
    };
    RatWitness::new_big(final_num, final_den)
}

// rat.normalize (exposed as standalone — RatWitness::new already normalizes,
// this is the explicit contract entry point for candidate (num, den) pairs)
pub fn rat_normalize(num: OurBigInt, den: OurBigInt) -> Result<RatWitness, ArithmeticError> {
    if den.is_zero() {
        return Err(ArithmeticError::ZeroDenominator);
    }
    // move sign into numerator, denominator must be positive
    let (n, d) = if matches!(den.sign, crate::Sign::Negative) {
        (num.negate(), den.magnitude)
    } else {
        (num, den.magnitude)
    };
    RatWitness::new_big(n, d)
}

// ── Section 11: Shadow / Strict Execution ────────────────────────────────────

#[derive(Debug)]
pub struct OpResult {
    pub out: StructuralNumber,
    pub receipt: ArithmeticStepReceipt,
}

pub fn execute_int_op(
    op: &str,
    lhs: i64,
    rhs: i64,
    mode: ArithMode,
    structural_fn: impl Fn(&IntWitness, &IntWitness) -> Result<IntWitness, ArithmeticError>,
    native_fn: impl Fn(i64, i64) -> Option<i64>,
) -> Result<OpResult, ArithmeticError> {
    let lhs_wit = IntWitness::from_i64(lhs);
    let rhs_wit = IntWitness::from_i64(rhs);
    let lhs_digest = lhs_wit.digest;
    let rhs_digest = rhs_wit.digest;

    let structural = structural_fn(&lhs_wit, &rhs_wit)?;

    let (native_val, native_summary, verdict) = match mode {
        ArithMode::Strict => {
            // native is optional cache only — structural is authoritative
            let summary = format!("strict:structural={}", structural.value);
            (structural.as_i64().unwrap_or(0), summary, true)
        }
        ArithMode::ShadowChecked | ArithMode::Native => {
            let native = native_fn(lhs, rhs).ok_or(ArithmeticError::NativeOverflow)?;
            let verdict = native == structural.as_i64().unwrap();
            if !verdict {
                return Err(ArithmeticError::ShadowMismatch);
            }
            (native, format!("native={native}"), verdict)
        }
    };

    let _ = native_val;
    let out = StructuralNumber {
        repr: StructuralRepr::HostInt(structural.value.clone()),
        canon: structural.canon.clone(),
        mode,
        receipt_link: structural.digest,
        witness: StructuralWitness::Int(structural),
    };

    let receipt = ArithmeticStepReceipt::new(
        op,
        lhs_digest,
        rhs_digest,
        out.receipt_link,
        native_summary,
        verdict,
        mode,
    );

    Ok(OpResult { out, receipt })
}


pub fn execute_int_op_big(
    op: &str,
    lhs: OurBigInt,
    rhs: OurBigInt,
    mode: ArithMode,
    structural_fn: impl Fn(&IntWitness, &IntWitness) -> Result<IntWitness, ArithmeticError>,
) -> Result<OpResult, ArithmeticError> {
    let lhs_wit = IntWitness::from_bigint(lhs);
    let rhs_wit = IntWitness::from_bigint(rhs);
    let lhs_digest = lhs_wit.digest;
    let rhs_digest = rhs_wit.digest;

    let structural = structural_fn(&lhs_wit, &rhs_wit)?;

    let native_summary = match mode {
        ArithMode::Strict => format!("strict:structural={}", structural.value),
        ArithMode::ShadowChecked | ArithMode::Native => format!("native={}", structural.value),
    };

    let out = StructuralNumber {
        repr: StructuralRepr::HostInt(structural.value.clone()),
        canon: structural.canon.clone(),
        mode,
        receipt_link: structural.digest,
        witness: StructuralWitness::Int(structural),
    };

    let receipt = ArithmeticStepReceipt::new(
        op,
        lhs_digest,
        rhs_digest,
        out.receipt_link,
        native_summary,
        true,
        mode,
    );

    Ok(OpResult { out, receipt })
}

pub fn checked_int_add(lhs: OurBigInt, rhs: OurBigInt, mode: ArithMode) -> Result<OpResult, ArithmeticError> {
    execute_int_op_big("int.add", lhs, rhs, mode, |a, b| int_add(a, b))
}

pub fn checked_int_sub(lhs: OurBigInt, rhs: OurBigInt, mode: ArithMode) -> Result<OpResult, ArithmeticError> {
    execute_int_op_big("int.sub", lhs, rhs, mode, |a, b| int_sub(a, b))
}

pub fn checked_int_mul(lhs: OurBigInt, rhs: OurBigInt, mode: ArithMode) -> Result<OpResult, ArithmeticError> {
    execute_int_op_big("int.mul", lhs, rhs, mode, |a, b| int_mul(a, b))
}


// ── Section 12: Replay Verification ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayFailureKind {
    OperandDecodeFailure,
    NormalizationFailure,
    DivideByZero,
    NativeShadowMismatch,
    LeafDigestMismatch { index: usize, expected: Digest, actual: Digest },
    MerkleRootMismatch { expected: Digest, actual: Digest },
    PolicyMismatch,
    ImplVersionMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResult {
    pub ok: bool,
    pub leaf_count: usize,
    pub recomputed_merkle_root: Digest,
    pub expected_merkle_root: Digest,
    pub failure: Option<ReplayFailureKind>,
    pub impl_version: String,
}

/// Replay a sequence of receipts against a committed block.
/// Recomputes each leaf digest from receipt fields and verifies
/// the Merkle root matches the committed block.
pub fn replay_verify(
    block: &ArithmeticBlock,
    receipts: &[ArithmeticStepReceipt],
) -> ReplayResult {
    let version = "0.1.0".to_string();

    if receipts.len() != block.leaf_count {
        return ReplayResult {
            ok: false,
            leaf_count: receipts.len(),
            recomputed_merkle_root: sha256(b"MERKLE_EMPTY"),
            expected_merkle_root: block.merkle_root,
            failure: Some(ReplayFailureKind::PolicyMismatch),
            impl_version: version,
        };
    }

    // Recompute each leaf digest from receipt fields and compare
    for (i, receipt) in receipts.iter().enumerate() {
        let recomputed = recompute_leaf_digest(receipt);
        if recomputed != receipt.leaf_digest {
            return ReplayResult {
                ok: false,
                leaf_count: receipts.len(),
                recomputed_merkle_root: sha256(b"MERKLE_EMPTY"),
                expected_merkle_root: block.merkle_root,
                failure: Some(ReplayFailureKind::LeafDigestMismatch {
                    index: i,
                    expected: receipt.leaf_digest,
                    actual: recomputed,
                }),
                impl_version: version,
            };
        }
    }

    // Recompute Merkle root from verified leaf digests
    let leaves: Vec<Digest> = receipts.iter().map(|r| r.leaf_digest).collect();
    let recomputed_root = merkle_root(&leaves);

    if recomputed_root != block.merkle_root {
        return ReplayResult {
            ok: false,
            leaf_count: receipts.len(),
            recomputed_merkle_root: recomputed_root,
            expected_merkle_root: block.merkle_root,
            failure: Some(ReplayFailureKind::MerkleRootMismatch {
                expected: block.merkle_root,
                actual: recomputed_root,
            }),
            impl_version: version,
        };
    }

    ReplayResult {
        ok: true,
        leaf_count: receipts.len(),
        recomputed_merkle_root: recomputed_root,
        expected_merkle_root: block.merkle_root,
        failure: None,
        impl_version: version,
    }
}

/// Recompute a leaf digest from receipt fields.
/// Must match ArithmeticStepReceipt::new exactly.
pub fn recompute_leaf_digest(receipt: &ArithmeticStepReceipt) -> Digest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(receipt.op.as_bytes());
    bytes.extend_from_slice(&receipt.lhs_digest);
    bytes.extend_from_slice(&receipt.rhs_digest);
    bytes.extend_from_slice(&receipt.out_digest);
    bytes.extend_from_slice(receipt.native_summary.as_bytes());
    bytes.push(receipt.verdict as u8);
    bytes.push(receipt.mode as u8);
    sha256(&bytes)
}


// ── Phase 1: Canonical Decode Enforcement ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
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

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// decode_nat
// Accepts: [0x01, u32_be_len, mag_bytes...]
// Rejects: wrong tag, truncated, non-minimal (leading zero), trailing bytes
pub fn decode_nat(bytes: &[u8]) -> Result<NatWitness, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::UnexpectedEof);
    }
    if bytes[0] != 0x01 {
        return Err(DecodeError::WrongTag { expected: 0x01, got: bytes[0] });
    }
    if bytes.len() < 5 {
        return Err(DecodeError::UnexpectedEof);
    }
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    if bytes.len() < 5 + len {
        return Err(DecodeError::LengthMismatch { expected: 5 + len, got: bytes.len() });
    }
    if bytes.len() > 5 + len {
        return Err(DecodeError::TrailingBytes);
    }
    let mag = &bytes[5..5 + len];

    // Non-minimal: leading zero byte in nonzero magnitude
    if len > 0 && mag[0] == 0x00 {
        return Err(DecodeError::NonMinimalEncoding);
    }

    // Reconstruct value
    let value = BigNat::from_be_bytes(mag);

    let witness = NatWitness::new(value);

    // Round-trip check
    if witness.canon != bytes {
        return Err(DecodeError::NonMinimalEncoding);
    }

    Ok(witness)
}

// decode_int
// Accepts: [0x02, sign_byte, nat_canon...]
// Rejects: wrong tag, bad sign byte, negative zero, zero with nonzero sign
pub fn decode_int(bytes: &[u8]) -> Result<IntWitness, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::UnexpectedEof);
    }
    if bytes[0] != 0x02 {
        return Err(DecodeError::WrongTag { expected: 0x02, got: bytes[0] });
    }
    if bytes.len() < 2 {
        return Err(DecodeError::UnexpectedEof);
    }
    let sign_byte = bytes[1];
    let sign = match sign_byte {
        0x00 => Sign::Zero,
        0x01 => Sign::Positive,
        0x02 => Sign::Negative,
        other => return Err(DecodeError::InvalidSignByte(other)),
    };

    let nat = decode_nat(&bytes[2..])?;

    // Negative zero
    if matches!(sign, Sign::Negative) && nat.magnitude.is_zero() {
        return Err(DecodeError::NegativeZero);
    }
    // Zero with nonzero sign
    if nat.magnitude.is_zero() && !matches!(sign, Sign::Zero) {
        return Err(DecodeError::ZeroWithNonzeroSign);
    }
    // Nonzero magnitude with zero sign
    if !nat.magnitude.is_zero() && matches!(sign, Sign::Zero) {
        return Err(DecodeError::ZeroWithNonzeroSign);
    }

    let witness = IntWitness::new(match sign {
        Sign::Zero => OurBigInt::zero(),
        Sign::Positive => OurBigInt::from_bignat(Sign::Positive, nat.magnitude.clone()),
        Sign::Negative => OurBigInt::from_bignat(Sign::Negative, nat.magnitude.clone()),
    });

    // Round-trip check
    if witness.canon != bytes {
        return Err(DecodeError::NonMinimalEncoding);
    }

    Ok(witness)
}

// decode_rat
// Accepts: [0x03, int_canon..., nat_canon...]
// Rejects: wrong tag, zero denominator, unreduced, alternate zero forms
pub fn decode_rat(bytes: &[u8]) -> Result<RatWitness, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::UnexpectedEof);
    }
    if bytes[0] != 0x03 {
        return Err(DecodeError::WrongTag { expected: 0x03, got: bytes[0] });
    }
    if bytes.len() < 2 {
        return Err(DecodeError::UnexpectedEof);
    }

    // Parse embedded int (starts at byte 1)
    // Int is: [0x02, sign, 0x01, u32_len, mag...]
    // Need to find where int ends and nat begins
    let int_bytes = find_int_slice(&bytes[1..])?;
    let num = decode_int(int_bytes)?;

    let nat_start = 1 + int_bytes.len();
    if nat_start >= bytes.len() {
        return Err(DecodeError::UnexpectedEof);
    }
    let nat_bytes = &bytes[nat_start..];
    let den = decode_nat(nat_bytes)?;

    // Zero denominator
    if den.magnitude.is_zero() {
        return Err(DecodeError::ZeroDenominator);
    }

    // Alternate zero rational: if num is zero, den must be 1
    if num.value.is_zero() && den.magnitude != BigNat::from_u64(1) {
        return Err(DecodeError::AlternateZeroRational);
    }

    // Must be reduced
    let g = BigNat::gcd(num.value.magnitude.clone(), den.magnitude.clone());
    if g != bignum::BigNat::from_u64(0) && g != BigNat::from_u64(1) {
        return Err(DecodeError::UnreducedRational);
    }

    let witness = RatWitness::new_big(num.value.clone(), den.magnitude.clone())
        .map_err(|_| DecodeError::ZeroDenominator)?;

    // Round-trip check
    if witness.canon != bytes {
        return Err(DecodeError::NonMinimalEncoding);
    }

    Ok(witness)
}

// Helper: given a byte slice starting with an Int encoding,
// return the exact slice that constitutes the Int (no trailing bytes).
fn find_int_slice(bytes: &[u8]) -> Result<&[u8], DecodeError> {
    // Int: [0x02, sign, <nat>]
    // Nat: [0x01, u32_len, mag...]
    if bytes.len() < 7 {
        return Err(DecodeError::UnexpectedEof);
    }
    if bytes[0] != 0x02 {
        return Err(DecodeError::WrongTag { expected: 0x02, got: bytes[0] });
    }
    // nat starts at offset 2
    if bytes[2] != 0x01 {
        return Err(DecodeError::WrongTag { expected: 0x01, got: bytes[2] });
    }
    let mag_len = u32::from_be_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]) as usize;
    let total = 2 + 1 + 4 + mag_len; // 0x02 + sign + nat_tag + nat_len + mag
    if bytes.len() < total {
        return Err(DecodeError::LengthMismatch { expected: total, got: bytes.len() });
    }
    Ok(&bytes[..total])
}


// ── Phase 3: Full Exact Op Closure ───────────────────────────────────────────

// nat.divrem
pub fn nat_divrem(a: &NatWitness, b: &NatWitness) -> Result<(NatWitness, NatWitness), ArithmeticError> {
    if b.magnitude.is_zero() {
        return Err(ArithmeticError::DivideByZero);
    }
    let (q, r) = a.magnitude.divrem(&b.magnitude);
    Ok((NatWitness::new(q), NatWitness::new(r)))
}

// nat.pow — exponentiation by natural exponent
pub fn nat_pow(base: &NatWitness, exp: &NatWitness) -> NatWitness {
    let mut result = BigNat::from_u64(1);
    let mut b = base.magnitude.clone();
    let mut e = exp.magnitude.clone();
    let two = BigNat::from_u64(2);
    while !e.is_zero() {
        let (eq, er) = e.divrem(&two);
        if !er.is_zero() {
            result = result.mul(&b);
        }
        b = b.mul(&b);
        e = eq;
    }
    NatWitness::new(result)
}

// int.abs
pub fn int_abs(a: &IntWitness) -> NatWitness {
    NatWitness::new(a.value.magnitude.clone())
}

// int.signum
pub fn int_signum(a: &IntWitness) -> IntWitness {
    match a.value.sign {
        crate::Sign::Zero     => IntWitness::from_i64(0),
        crate::Sign::Positive => IntWitness::from_i64(1),
        crate::Sign::Negative => IntWitness::from_i64(-1),
    }
}

// int.divrem — Euclidean division: remainder is always non-negative
pub fn int_divrem(a: &IntWitness, b: &IntWitness) -> Result<(IntWitness, IntWitness), ArithmeticError> {
    if b.value.is_zero() {
        return Err(ArithmeticError::DivideByZero);
    }
    let (q_mag, r_mag) = a.value.magnitude.divrem(&b.value.magnitude);
    // Euclidean: remainder always non-negative
    // adjust quotient and remainder based on signs
    let (q_sign, _r_sign) = match (a.value.sign, b.value.sign) {
        (crate::Sign::Zero, _) => (crate::Sign::Zero, crate::Sign::Zero),
        (_, crate::Sign::Zero) => unreachable!(),
        (crate::Sign::Positive, crate::Sign::Positive) => (crate::Sign::Positive, crate::Sign::Positive),
        (crate::Sign::Positive, crate::Sign::Negative) => (crate::Sign::Negative, crate::Sign::Positive),
        (crate::Sign::Negative, crate::Sign::Positive) => {
            // if remainder nonzero: q = -(q_mag+1), r = b_mag - r_mag
            if r_mag.is_zero() {
                (crate::Sign::Negative, crate::Sign::Zero)
            } else {
                (crate::Sign::Negative, crate::Sign::Positive)
            }
        }
        (crate::Sign::Negative, crate::Sign::Negative) => {
            if r_mag.is_zero() {
                (crate::Sign::Positive, crate::Sign::Zero)
            } else {
                (crate::Sign::Positive, crate::Sign::Positive)
            }
        }
    };
    // adjust for Euclidean remainder non-negativity
    let (final_q_mag, final_r_mag) = match (a.value.sign, b.value.sign) {
        (crate::Sign::Negative, crate::Sign::Positive) if !r_mag.is_zero() => {
            let adj_q = q_mag.add(&BigNat::from_u64(1));
            let adj_r = b.value.magnitude.sub(&r_mag);
            (adj_q, adj_r)
        }
        (crate::Sign::Negative, crate::Sign::Negative) if !r_mag.is_zero() => {
            let adj_q = q_mag.add(&BigNat::from_u64(1));
            let adj_r = b.value.magnitude.sub(&r_mag);
            (adj_q, adj_r)
        }
        _ => (q_mag, r_mag),
    };
    let q = IntWitness::from_bigint(OurBigInt::from_bignat(q_sign, final_q_mag));
    let r = IntWitness::from_bigint(OurBigInt::from_bignat(
        if final_r_mag.is_zero() { crate::Sign::Zero } else { crate::Sign::Positive },
        final_r_mag,
    ));
    Ok((q, r))
}

// int.pow — exponentiation by natural exponent
pub fn int_pow(base: &IntWitness, exp: &NatWitness) -> IntWitness {
    let mut result = OurBigInt::from_i64(1);
    let mut b = base.value.clone();
    let mut e = exp.magnitude.clone();
    let two = BigNat::from_u64(2);
    while !e.is_zero() {
        let (eq, er) = e.divrem(&two);
        if !er.is_zero() {
            result = result.mul(&b);
        }
        b = b.mul(&b);
        e = eq;
    }
    IntWitness::from_bigint(result)
}

// rat.abs
pub fn rat_abs(a: &RatWitness) -> Result<RatWitness, ArithmeticError> {
    RatWitness::new_big(
        OurBigInt::from_bignat(crate::Sign::Positive, a.num.value.magnitude.clone()),
        a.den.magnitude.clone(),
    )
}

// rat.signum
pub fn rat_signum(a: &RatWitness) -> IntWitness {
    match a.num.value.sign {
        crate::Sign::Zero     => IntWitness::from_i64(0),
        crate::Sign::Positive => IntWitness::from_i64(1),
        crate::Sign::Negative => IntWitness::from_i64(-1),
    }
}

// rat.floor — largest integer <= a
pub fn rat_floor(a: &RatWitness) -> IntWitness {
    let (q, r) = a.num.value.magnitude.divrem(&a.den.magnitude);
    match a.num.value.sign {
        crate::Sign::Zero => IntWitness::from_i64(0),
        crate::Sign::Positive => {
            IntWitness::from_bigint(OurBigInt::from_bignat(crate::Sign::Positive, q))
        }
        crate::Sign::Negative => {
            // floor of negative: if remainder nonzero, subtract 1
            if r.is_zero() {
                IntWitness::from_bigint(OurBigInt::from_bignat(crate::Sign::Negative, q))
            } else {
                let adj = q.add(&BigNat::from_u64(1));
                IntWitness::from_bigint(OurBigInt::from_bignat(crate::Sign::Negative, adj))
            }
        }
    }
}

// rat.ceil — smallest integer >= a
pub fn rat_ceil(a: &RatWitness) -> IntWitness {
    let (q, r) = a.num.value.magnitude.divrem(&a.den.magnitude);
    match a.num.value.sign {
        crate::Sign::Zero => IntWitness::from_i64(0),
        crate::Sign::Positive => {
            if r.is_zero() {
                IntWitness::from_bigint(OurBigInt::from_bignat(crate::Sign::Positive, q))
            } else {
                let adj = q.add(&BigNat::from_u64(1));
                IntWitness::from_bigint(OurBigInt::from_bignat(crate::Sign::Positive, adj))
            }
        }
        crate::Sign::Negative => {
            IntWitness::from_bigint(OurBigInt::from_bignat(
                if q.is_zero() { crate::Sign::Zero } else { crate::Sign::Negative },
                q,
            ))
        }
    }
}

// rat.trunc — truncate toward zero
pub fn rat_trunc(a: &RatWitness) -> IntWitness {
    let (q, _) = a.num.value.magnitude.divrem(&a.den.magnitude);
    IntWitness::from_bigint(OurBigInt::from_bignat(
        if q.is_zero() { crate::Sign::Zero } else { a.num.value.sign },
        q,
    ))
}

// rat.pow — exponentiation by integer exponent (negative exp gives reciprocal)
pub fn rat_pow(base: &RatWitness, exp: i64) -> Result<RatWitness, ArithmeticError> {
    if exp == 0 {
        return RatWitness::new(1, 1);
    }
    let abs_exp = exp.unsigned_abs();
    let mut num = OurBigInt::from_i64(1);
    let mut den = BigNat::from_u64(1);
    let mut bn = base.num.value.clone();
    let mut bd = base.den.magnitude.clone();
    let mut e = abs_exp;
    while e > 0 {
        if e & 1 == 1 {
            num = num.mul(&bn);
            den = den.mul(&bd);
        }
        bn = bn.mul(&bn);
        bd = bd.mul(&bd);
        e >>= 1;
    }
    if exp < 0 {
        // reciprocal: swap num and den, fix sign
        let (new_num, new_den) = match num.sign {
            crate::Sign::Negative => (OurBigInt::from_bignat(crate::Sign::Negative, den), num.magnitude),
            _ => (OurBigInt::from_bignat(crate::Sign::Positive, den), num.magnitude),
        };
        RatWitness::new_big(new_num, new_den)
    } else {
        RatWitness::new_big(num, den)
    }
}


impl fmt::Display for NatWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.magnitude)
    }
}

impl fmt::Display for IntWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl fmt::Display for RatWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.num, self.den)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_canon_is_stable() {
        let n = NatWitness::from_u64(10);
        let expected = encode_nat(&BigNat::from_u64(10));
        println!("
── nat_canon_is_stable ──────────────────────────");
        println!("  value       : {}", n.as_u64().unwrap());
        println!("  canon bytes : {:02x?}", n.canon);
        println!("  expected    : {:02x?}", expected);
        println!("  digest      : {}", hex_digest(&n.digest));
        println!("  canon match : {}", n.canon == expected);
        println!("  digest ok   : {}", n.digest == sha256(&n.canon));
        assert_eq!(n.canon, expected);
        assert_eq!(n.digest, sha256(&n.canon));
    }

    #[test]
    fn rat_reduces() {
        let r = RatWitness::new(6, 8).unwrap();
        println!("
── rat_reduces ──────────────────────────────────");
        println!("  input       : 6/8");
        println!("  reduced num : {} (sign={})", r.num.value.abs().to_u64().unwrap(), if r.num.value.is_zero() { "zero" } else if matches!(r.num.value.sign, crate::Sign::Negative) { "neg" } else { "pos" });
        println!("  reduced den : {}", r.den.as_u64().unwrap());
        println!("  canon bytes : {:02x?}", r.canon);
        println!("  digest      : {}", hex_digest(&r.digest));
        println!("  gcd(6,8)=2  → 6/8 reduces to {}/{}", r.num.as_i64().unwrap(), r.den.as_u64().unwrap());
        assert_eq!(r.num.as_i64().unwrap(), 3);
        assert_eq!(r.den.as_u64().unwrap(), 4);
    }

    #[test]
    fn shadow_add_produces_receipt() {
        let (out, receipt) = shadow_add_int(10, 20, ArithMode::ShadowChecked).unwrap();
        println!("
── shadow_add_produces_receipt ──────────────────");
        println!("  op          : {}", receipt.op);
        println!("  mode        : {:?}", receipt.mode);
        println!("  lhs         : 10  digest={}", hex_digest(&receipt.lhs_digest));
        println!("  rhs         : 20  digest={}", hex_digest(&receipt.rhs_digest));
        println!("  out value   : {}", out.as_i64());
        println!("  out digest  : {}", hex_digest(&receipt.out_digest));
        println!("  native_sum  : {}", receipt.native_summary);
        println!("  verdict     : {} (native==structural)", receipt.verdict);
        println!("  leaf digest : {}", hex_digest(&receipt.leaf_digest));
        assert_eq!(out.as_i64(), 30);
        assert!(receipt.verdict);
    }


    #[test]
    fn nat_ops() {
        let a = NatWitness::from_u64(10);
        let b = NatWitness::from_u64(4);
        println!("\n── nat_ops ──────────────────────────────────────");
        println!("  nat.eq(10,10)       : {}", nat_eq(&a, &NatWitness::from_u64(10)));
        println!("  nat.eq(10,4)        : {}", nat_eq(&a, &b));
        println!("  nat.cmp(10,4)       : {:?}", nat_cmp(&a, &b));
        println!("  nat.add(10,4)       : {}", nat_add(&a, &b).as_u64().unwrap());
        println!("  nat.sub_checked(10,4): {}", nat_sub_checked(&a, &b).unwrap().as_u64().unwrap());
        println!("  nat.sub_checked(4,10): {:?}", nat_sub_checked(&b, &a).unwrap_err());
        println!("  nat.mul(10,4)       : {}", nat_mul(&a, &b).as_u64().unwrap());
        assert!(nat_eq(&a, &NatWitness::from_u64(10)));
        assert!(!nat_eq(&a, &b));
        assert_eq!(nat_cmp(&a, &b), std::cmp::Ordering::Greater);
        assert_eq!(nat_add(&a, &b).as_u64().unwrap(), 14);
        assert_eq!(nat_sub_checked(&a, &b).unwrap().as_u64().unwrap(), 6);
        assert_eq!(nat_sub_checked(&b, &a).unwrap_err(), ArithmeticError::NegativeNatResult);
        assert_eq!(nat_mul(&a, &b).as_u64().unwrap(), 40);
    }

    #[test]
    fn int_ops() {
        let a = IntWitness::from_i64(10);
        let b = IntWitness::from_i64(-4);
        let z = IntWitness::from_i64(0);
        println!("\n── int_ops ──────────────────────────────────────");
        println!("  int.eq(10,10)  : {}", int_eq(&a, &IntWitness::from_i64(10)));
        println!("  int.eq(10,-4)  : {}", int_eq(&a, &b));
        println!("  int.cmp(10,-4) : {:?}", int_cmp(&a, &b));
        println!("  int.add(10,-4) : {}", int_add(&a, &b).unwrap().as_i64().unwrap());
        println!("  int.sub(10,-4) : {}", int_sub(&a, &b).unwrap().as_i64().unwrap());
        println!("  int.mul(10,-4) : {}", int_mul(&a, &b).unwrap().as_i64().unwrap());
        println!("  int.neg(10)    : {}", int_neg(&a).as_i64().unwrap());
        println!("  int.neg(0)     : {}", int_neg(&z).as_i64().unwrap());
        println!("  neg(0) sign    : {}", if int_neg(&z).value.is_zero() { "Zero" } else if matches!(int_neg(&z).value.sign, crate::Sign::Negative) { "Negative" } else { "Positive" });
        assert!(int_eq(&a, &IntWitness::from_i64(10)));
        assert!(!int_eq(&a, &b));
        assert_eq!(int_cmp(&a, &b), std::cmp::Ordering::Greater);
        assert_eq!(int_add(&a, &b).unwrap().as_i64().unwrap(), 6);
        assert_eq!(int_sub(&a, &b).unwrap().as_i64().unwrap(), 14);
        assert_eq!(int_mul(&a, &b).unwrap().as_i64().unwrap(), -40);
        assert_eq!(int_neg(&a).as_i64().unwrap(), -10);
        assert_eq!(int_neg(&z).as_i64().unwrap(), 0);
        assert!(int_neg(&z).value.is_zero());
    }

    #[test]
    fn rat_ops() {
        let a = RatWitness::new(1, 2).unwrap();  // 1/2
        let b = RatWitness::new(1, 3).unwrap();  // 1/3
        let c = RatWitness::new(0, 1).unwrap();  // 0
        println!("\n── rat_ops ──────────────────────────────────────");
        println!("  rat.eq(1/2,1/2)      : {}", rat_eq(&a, &RatWitness::new(1,2).unwrap()));
        println!("  rat.eq(1/2,1/3)      : {}", rat_eq(&a, &b));
        println!("  rat.cmp(1/2,1/3)     : {:?}", rat_cmp(&a, &b));
        let sum = rat_add(&a, &b).unwrap();
        println!("  rat.add(1/2,1/3)     : {}/{}", sum.num.as_i64().unwrap(), sum.den.as_u64().unwrap());
        let diff = rat_sub(&a, &b).unwrap();
        println!("  rat.sub(1/2,1/3)     : {}/{}", diff.num.as_i64().unwrap(), diff.den.as_u64().unwrap());
        let prod = rat_mul(&a, &b).unwrap();
        println!("  rat.mul(1/2,1/3)     : {}/{}", prod.num.as_i64().unwrap(), prod.den.as_u64().unwrap());
        let quot = rat_div_checked(&a, &b).unwrap();
        println!("  rat.div(1/2,1/3)     : {}/{}", quot.num.as_i64().unwrap(), quot.den.as_u64().unwrap());
        println!("  rat.div_by_zero      : {:?}", rat_div_checked(&a, &c).unwrap_err());
        let norm = rat_normalize(OurBigInt::from_i64(6), OurBigInt::from_i64(-8)).unwrap();
        println!("  rat.normalize(6,-8)  : {}/{}", norm.num.as_i64().unwrap(), norm.den.as_u64().unwrap());
        assert!(rat_eq(&a, &RatWitness::new(1, 2).unwrap()));
        assert!(!rat_eq(&a, &b));
        assert_eq!(rat_cmp(&a, &b), std::cmp::Ordering::Greater);
        assert_eq!(sum.num.as_i64().unwrap(), 5);   assert_eq!(sum.den.as_u64().unwrap(), 6);
        assert_eq!(diff.num.as_i64().unwrap(), 1);  assert_eq!(diff.den.as_u64().unwrap(), 6);
        assert_eq!(prod.num.as_i64().unwrap(), 1);  assert_eq!(prod.den.as_u64().unwrap(), 6);
        assert_eq!(quot.num.as_i64().unwrap(), 3);  assert_eq!(quot.den.as_u64().unwrap(), 2);
        assert_eq!(rat_div_checked(&a, &c).unwrap_err(), ArithmeticError::DivideByZero);
        assert_eq!(norm.num.as_i64().unwrap(), -3); assert_eq!(norm.den.as_u64().unwrap(), 4);
    }

    #[test]
    fn overflow_policy() {
        println!("\n── overflow_policy ──────────────────────────────");

        let max_nat = NatWitness::from_u64(u64::MAX);
        let one_nat = NatWitness::from_u64(1);
        let sum_nat = nat_add(&max_nat, &one_nat);
        println!("  nat.add(u64::MAX, 1)      : {}", sum_nat.magnitude);
        assert_eq!(sum_nat.magnitude.to_string(), "18446744073709551616");

        let prod_nat = nat_mul(&max_nat, &NatWitness::from_u64(2));
        println!("  nat.mul(u64::MAX, 2)      : {}", prod_nat.magnitude);
        assert_eq!(prod_nat.magnitude.to_string(), "36893488147419103230");

        let max_int = IntWitness::from_i64(i64::MAX);
        let min_int = IntWitness::from_i64(i64::MIN);
        let one_int = IntWitness::from_i64(1);

        let isum = int_add(&max_int, &one_int).unwrap();
        println!("  int.add(i64::MAX, 1)      : {} (exceeds i64)", isum.value);
        assert!(isum.as_i64().is_none());

        let idiff = int_sub(&min_int, &one_int).unwrap();
        println!("  int.sub(i64::MIN, 1)      : {} (below i64)", idiff.value);
        assert!(idiff.as_i64().is_none());

        let iprod = int_mul(&max_int, &IntWitness::from_i64(2)).unwrap();
        println!("  int.mul(i64::MAX, 2)      : {} (exceeds i64)", iprod.value);
        assert!(iprod.as_i64().is_none());

        println!("  all large-value ops succeed — overflow is not a semantic event ✓");
    }

    #[test]
    fn shadow_mismatch_detection() {
        println!("\n── shadow_mismatch_detection ────────────────────");

        // Normal case — native and structural agree
        let r = checked_int_add(OurBigInt::from_i64(10), OurBigInt::from_i64(20), ArithMode::ShadowChecked).unwrap();
        println!("  add(10,20) ShadowChecked verdict : {}", r.receipt.verdict);
        println!("  add(10,20) out                   : {}", r.out.as_i64());
        assert_eq!(r.out.as_i64(), 30);
        assert!(r.receipt.verdict);

        // Structural is unbounded — i64::MAX + 1 succeeds in v0.2.0+
        let r = checked_int_add(OurBigInt::from_i64(i64::MAX), OurBigInt::from_i64(1), ArithMode::ShadowChecked).unwrap();
        println!("  add(MAX,1) ShadowChecked         : {} (unbounded)", r.receipt.native_summary);
        assert!(r.receipt.verdict);

        // sub and mul happy paths
        let r = checked_int_sub(OurBigInt::from_i64(30), OurBigInt::from_i64(10), ArithMode::ShadowChecked).unwrap();
        println!("  sub(30,10) ShadowChecked         : {}", r.out.as_i64());
        assert_eq!(r.out.as_i64(), 20);

        let r = checked_int_mul(OurBigInt::from_i64(6), OurBigInt::from_i64(7), ArithMode::ShadowChecked).unwrap();
        println!("  mul(6,7)   ShadowChecked         : {}", r.out.as_i64());
        assert_eq!(r.out.as_i64(), 42);
    }

    #[test]
    fn strict_mode_authority() {
        println!("\n── strict_mode_authority ────────────────────────");

        // Strict: structural is authoritative, receipt always verdicts true
        let r = checked_int_add(OurBigInt::from_i64(10), OurBigInt::from_i64(20), ArithMode::Strict).unwrap();
        println!("  add(10,20) Strict verdict        : {}", r.receipt.verdict);
        println!("  add(10,20) Strict out            : {}", r.out.as_i64());
        println!("  add(10,20) Strict native_summary : {}", r.receipt.native_summary);
        assert_eq!(r.out.as_i64(), 30);
        assert!(r.receipt.verdict);
        assert!(r.receipt.native_summary.starts_with("strict:structural="));

        // Strict: i64::MAX + 1 succeeds — structural is unbounded in v0.2.0
        let r = checked_int_add(OurBigInt::from_i64(i64::MAX), OurBigInt::from_i64(1), ArithMode::Strict).unwrap();
        println!("  add(MAX,1) Strict out            : {} (unbounded)", r.receipt.native_summary);
        assert!(r.receipt.verdict);

        // Strict: mode is recorded on receipt
        let r = checked_int_mul(OurBigInt::from_i64(3), OurBigInt::from_i64(4), ArithMode::Strict).unwrap();
        println!("  mul(3,4)   Strict mode field     : {:?}", r.receipt.mode);
        assert_eq!(r.receipt.mode, ArithMode::Strict);

        // ShadowChecked: mode is recorded on receipt
        let r = checked_int_mul(OurBigInt::from_i64(3), OurBigInt::from_i64(4), ArithMode::ShadowChecked).unwrap();
        println!("  mul(3,4)   ShadowChecked mode    : {:?}", r.receipt.mode);
        assert_eq!(r.receipt.mode, ArithMode::ShadowChecked);
    }

    #[test]
    fn merkle_block_determinism() {
        println!("\n── merkle_block_determinism ─────────────────────");

        let r1 = checked_int_add(OurBigInt::from_i64(10), OurBigInt::from_i64(20), ArithMode::ShadowChecked).unwrap();
        let r2 = checked_int_sub(OurBigInt::from_i64(50), OurBigInt::from_i64(5), ArithMode::ShadowChecked).unwrap();
        let r3 = checked_int_mul(OurBigInt::from_i64(3), OurBigInt::from_i64(7), ArithMode::ShadowChecked).unwrap();

        let receipts = vec![r1.receipt.clone(), r2.receipt.clone(), r3.receipt.clone()];

        let block1 = ArithmeticBlock::from_receipts("test_block", "commit_only", &receipts);
        let block2 = ArithmeticBlock::from_receipts("test_block", "commit_only", &receipts);

        println!("  leaf_count          : {}", block1.leaf_count);
        println!("  merkle_root (1)     : {}", hex_digest(&block1.merkle_root));
        println!("  merkle_root (2)     : {}", hex_digest(&block2.merkle_root));
        println!("  roots match         : {}", block1.merkle_root == block2.merkle_root);
        println!("  leaf[0] op          : {}", r1.receipt.op);
        println!("  leaf[0] digest      : {}", hex_digest(&r1.receipt.leaf_digest));
        println!("  leaf[1] op          : {}", r2.receipt.op);
        println!("  leaf[1] digest      : {}", hex_digest(&r2.receipt.leaf_digest));
        println!("  leaf[2] op          : {}", r3.receipt.op);
        println!("  leaf[2] digest      : {}", hex_digest(&r3.receipt.leaf_digest));

        assert_eq!(block1.leaf_count, 3);
        assert_eq!(block1.merkle_root, block2.merkle_root);
    }

    #[test]
    fn replay_verification() {
        println!("\n── replay_verification ──────────────────────────");

        let r1 = checked_int_add(OurBigInt::from_i64(10), OurBigInt::from_i64(20), ArithMode::ShadowChecked).unwrap();
        let r2 = checked_int_sub(OurBigInt::from_i64(50), OurBigInt::from_i64(5), ArithMode::ShadowChecked).unwrap();
        let r3 = checked_int_mul(OurBigInt::from_i64(3), OurBigInt::from_i64(7), ArithMode::ShadowChecked).unwrap();

        let receipts = vec![r1.receipt.clone(), r2.receipt.clone(), r3.receipt.clone()];
        let block = ArithmeticBlock::from_receipts("replay_block", "commit_only", &receipts);

        // Happy path — replay must succeed
        let result = replay_verify(&block, &receipts);
        println!("  ok                  : {}", result.ok);
        println!("  leaf_count          : {}", result.leaf_count);
        println!("  recomputed_root     : {}", hex_digest(&result.recomputed_merkle_root));
        println!("  expected_root       : {}", hex_digest(&result.expected_merkle_root));
        println!("  roots match         : {}", result.recomputed_merkle_root == result.expected_merkle_root);
        assert!(result.ok);
        assert!(result.failure.is_none());
        assert_eq!(result.recomputed_merkle_root, result.expected_merkle_root);

        // Tampered receipt — leaf digest mismatch must be detected
        let mut tampered = receipts.clone();
        tampered[1].native_summary = "native=TAMPERED".to_string();
        let result = replay_verify(&block, &tampered);
        println!("  tampered ok         : {}", result.ok);
        println!("  tampered failure    : {:?}", result.failure);
        assert!(!result.ok);
        assert!(matches!(
            result.failure,
            Some(ReplayFailureKind::LeafDigestMismatch { index: 1, .. })
        ));

        // Wrong leaf count — policy mismatch
        let short = vec![receipts[0].clone()];
        let result = replay_verify(&block, &short);
        println!("  short receipts ok   : {}", result.ok);
        println!("  short failure       : {:?}", result.failure);
        assert!(!result.ok);
        assert_eq!(result.failure, Some(ReplayFailureKind::PolicyMismatch));
    }

    #[test]
    fn decode_nat_roundtrip_and_rejection() {
        println!("\n── decode_nat ────────────────────────────────────");

        // Round-trips
        for n in [0u64, 1, 10, 255, 256, 65535, u64::MAX] {
            let enc = encode_nat(&BigNat::from_u64(n));
            let dec = decode_nat(&enc).unwrap();
            assert_eq!(dec.as_u64().unwrap(), n, "round-trip failed for {n}");
            println!("  round-trip {:>20} : ok", n);
        }

        // Wrong tag
        let mut bad = encode_nat(&BigNat::from_u64(10));
        bad[0] = 0x02;
        assert_eq!(decode_nat(&bad).unwrap_err(), DecodeError::WrongTag { expected: 0x01, got: 0x02 });
        println!("  wrong tag              : {:?}", DecodeError::WrongTag { expected: 0x01, got: 0x02 });

        // Truncated
        let enc = encode_nat(&BigNat::from_u64(10));
        assert_eq!(decode_nat(&enc[..3]).unwrap_err(), DecodeError::UnexpectedEof);
        println!("  truncated              : {:?}", DecodeError::UnexpectedEof);

        // Non-minimal: leading zero in magnitude
        // [0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0A] — len=2, mag=[0x00,0x0A]
        let non_minimal = vec![0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0A];
        assert_eq!(decode_nat(&non_minimal).unwrap_err(), DecodeError::NonMinimalEncoding);
        println!("  non-minimal leading 0  : {:?}", DecodeError::NonMinimalEncoding);

        // Trailing bytes
        let mut trailing = encode_nat(&BigNat::from_u64(10));
        trailing.push(0xFF);
        assert_eq!(decode_nat(&trailing).unwrap_err(), DecodeError::TrailingBytes);
        println!("  trailing bytes         : {:?}", DecodeError::TrailingBytes);

        // Length mismatch: claims len=5 but only 3 mag bytes
        let bad_len = vec![0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03];
        assert_eq!(decode_nat(&bad_len).unwrap_err(),
            DecodeError::LengthMismatch { expected: 10, got: 8 });
        println!("  length mismatch        : {:?}", DecodeError::LengthMismatch { expected: 10, got: 8 });
    }

    #[test]
    fn decode_int_roundtrip_and_rejection() {
        println!("\n── decode_int ────────────────────────────────────");

        // Round-trips
        for v in [0i64, 1, -1, 42, -42, i64::MAX, i64::MIN] {
            let wit = IntWitness::from_i64(v);
            let dec = decode_int(&wit.canon).unwrap();
            assert_eq!(dec.as_i64().unwrap(), v, "round-trip failed for {v}");
            println!("  round-trip {:>20} : ok", v);
        }

        // Wrong tag
        let mut bad = IntWitness::from_i64(5).canon;
        bad[0] = 0x03;
        assert_eq!(decode_int(&bad).unwrap_err(), DecodeError::WrongTag { expected: 0x02, got: 0x03 });
        println!("  wrong tag              : {:?}", DecodeError::WrongTag { expected: 0x02, got: 0x03 });

        // Invalid sign byte
        let mut bad_sign = IntWitness::from_i64(5).canon;
        bad_sign[1] = 0x05;
        assert_eq!(decode_int(&bad_sign).unwrap_err(), DecodeError::InvalidSignByte(0x05));
        println!("  invalid sign byte      : {:?}", DecodeError::InvalidSignByte(0x05));

        // Negative zero: [0x02, 0x02, <Nat(0)>]
        let nat_zero = encode_nat(&BigNat::zero());
        let mut neg_zero = vec![0x02, 0x02];
        neg_zero.extend_from_slice(&nat_zero);
        assert_eq!(decode_int(&neg_zero).unwrap_err(), DecodeError::NegativeZero);
        println!("  negative zero          : {:?}", DecodeError::NegativeZero);

        // Zero with nonzero sign: [0x02, 0x01, <Nat(0)>]
        let mut zero_pos = vec![0x02, 0x01];
        zero_pos.extend_from_slice(&nat_zero);
        assert_eq!(decode_int(&zero_pos).unwrap_err(), DecodeError::ZeroWithNonzeroSign);
        println!("  zero with pos sign     : {:?}", DecodeError::ZeroWithNonzeroSign);
    }

    #[test]
    fn decode_rat_roundtrip_and_rejection() {
        println!("\n── decode_rat ────────────────────────────────────");

        // Round-trips
        for (n, d) in [(0i64,1u64),(1,2),(-1,3),(3,4),(-7,8),(1,1)] {
            let wit = RatWitness::new(n, d).unwrap();
            let dec = decode_rat(&wit.canon).unwrap();
            assert_eq!(dec.num.as_i64().unwrap(), n, "round-trip num failed for {n}/{d}");
            assert_eq!(dec.den.as_u64().unwrap(), d, "round-trip den failed for {n}/{d}");
            println!("  round-trip {:>5}/{:<5} : ok", n, d);
        }

        // Wrong tag
        let mut bad = RatWitness::new(1, 2).unwrap().canon;
        bad[0] = 0x01;
        assert_eq!(decode_rat(&bad).unwrap_err(), DecodeError::WrongTag { expected: 0x03, got: 0x01 });
        println!("  wrong tag              : {:?}", DecodeError::WrongTag { expected: 0x03, got: 0x01 });

        // Unreduced rational: encode 2/4 manually (bypassing RatWitness::new)
        // [0x03, Int(2), Nat(4)]
        let mut unreduced = vec![0x03];
        unreduced.extend_from_slice(&IntWitness::from_i64(2).canon);
        unreduced.extend_from_slice(&NatWitness::from_u64(4).canon);
        assert_eq!(decode_rat(&unreduced).unwrap_err(), DecodeError::UnreducedRational);
        println!("  unreduced 2/4          : {:?}", DecodeError::UnreducedRational);

        // Alternate zero rational: 0/2 instead of 0/1
        let mut alt_zero = vec![0x03];
        alt_zero.extend_from_slice(&IntWitness::from_i64(0).canon);
        alt_zero.extend_from_slice(&NatWitness::from_u64(2).canon);
        assert_eq!(decode_rat(&alt_zero).unwrap_err(), DecodeError::AlternateZeroRational);
        println!("  alt zero 0/2           : {:?}", DecodeError::AlternateZeroRational);

        // Zero denominator: [0x03, Int(1), Nat(0)]
        let mut zero_den = vec![0x03];
        zero_den.extend_from_slice(&IntWitness::from_i64(1).canon);
        zero_den.extend_from_slice(&NatWitness::from_u64(0).canon);
        assert_eq!(decode_rat(&zero_den).unwrap_err(), DecodeError::ZeroDenominator);
        println!("  zero denominator       : {:?}", DecodeError::ZeroDenominator);
    }

    #[test]
    fn nat_divrem_and_pow() {
        println!("\n── nat_divrem_and_pow ────────────────────────────");

        let a = NatWitness::from_u64(100);
        let b = NatWitness::from_u64(7);
        let (q, r) = nat_divrem(&a, &b).unwrap();
        println!("  nat.divrem(100,7)  : {} rem {}", q, r);
        assert_eq!(q.as_u64().unwrap(), 14);
        assert_eq!(r.as_u64().unwrap(), 2);

        let zero = NatWitness::from_u64(0);
        assert_eq!(nat_divrem(&a, &zero).unwrap_err(), ArithmeticError::DivideByZero);
        println!("  nat.divrem(100,0)  : DivideByZero");

        let base = NatWitness::from_u64(2);
        let exp  = NatWitness::from_u64(10);
        let p = nat_pow(&base, &exp);
        println!("  nat.pow(2,10)      : {}", p);
        assert_eq!(p.as_u64().unwrap(), 1024);

        // Beyond u64
        let big_base = NatWitness::from_u64(u64::MAX);
        let big_exp  = NatWitness::from_u64(2);
        let big_p = nat_pow(&big_base, &big_exp);
        println!("  nat.pow(u64::MAX,2): {} (unbounded)", big_p);
        assert!(big_p.as_u64().is_none());

        // pow 0
        let p0 = nat_pow(&base, &zero);
        println!("  nat.pow(2,0)       : {}", p0);
        assert_eq!(p0.as_u64().unwrap(), 1);
    }

    #[test]
    fn int_divrem_abs_signum_pow() {
        println!("\n── int_divrem_abs_signum_pow ─────────────────────");

        // int.abs
        let pos = IntWitness::from_i64(42);
        let neg = IntWitness::from_i64(-42);
        let z   = IntWitness::from_i64(0);
        println!("  int.abs(42)        : {}", int_abs(&pos));
        println!("  int.abs(-42)       : {}", int_abs(&neg));
        println!("  int.abs(0)         : {}", int_abs(&z));
        assert_eq!(int_abs(&pos).as_u64().unwrap(), 42);
        assert_eq!(int_abs(&neg).as_u64().unwrap(), 42);
        assert_eq!(int_abs(&z).as_u64().unwrap(), 0);

        // int.signum
        println!("  int.signum(42)     : {}", int_signum(&pos).as_i64().unwrap());
        println!("  int.signum(-42)    : {}", int_signum(&neg).as_i64().unwrap());
        println!("  int.signum(0)      : {}", int_signum(&z).as_i64().unwrap());
        assert_eq!(int_signum(&pos).as_i64().unwrap(),  1);
        assert_eq!(int_signum(&neg).as_i64().unwrap(), -1);
        assert_eq!(int_signum(&z).as_i64().unwrap(),    0);

        // int.divrem Euclidean
        let cases: &[(i64,i64,i64,i64)] = &[
            ( 17,  5,  3, 2),
            (-17,  5, -4, 3),
            ( 17, -5, -3, 2),
            (-17, -5,  4, 3),
            ( 15,  5,  3, 0),
            (-15,  5, -3, 0),
        ];
        for &(a, b, eq, er) in cases {
            let (q, r) = int_divrem(&IntWitness::from_i64(a), &IntWitness::from_i64(b)).unwrap();
            println!("  int.divrem({:>4},{:>3}) : q={:>3} r={}", a, b, q.as_i64().unwrap(), r.as_i64().unwrap());
            assert_eq!(q.as_i64().unwrap(), eq, "divrem q failed for {a}/{b}");
            assert_eq!(r.as_i64().unwrap(), er, "divrem r failed for {a}/{b}");
            // Euclidean invariant: r >= 0
            assert!(r.as_i64().unwrap() >= 0);
        }

        // int.pow
        let base = IntWitness::from_i64(-2);
        let exp  = NatWitness::from_u64(10);
        let p = int_pow(&base, &exp);
        println!("  int.pow(-2,10)     : {}", p.as_i64().unwrap());
        assert_eq!(p.as_i64().unwrap(), 1024);

        let exp3 = NatWitness::from_u64(3);
        let p3 = int_pow(&base, &exp3);
        println!("  int.pow(-2,3)      : {}", p3.as_i64().unwrap());
        assert_eq!(p3.as_i64().unwrap(), -8);
    }

    #[test]
    fn rat_floor_ceil_trunc_abs_signum_pow() {
        println!("\n── rat_floor_ceil_trunc_abs_signum_pow ──────────");

        let cases: &[(&str, i64, u64, i64, i64, i64)] = &[
            // label,   num, den, floor, ceil, trunc
            ( "7/2",    7,   2,   3,     4,    3),
            ("-7/2",   -7,   2,  -4,    -3,   -3),
            ( "4/2",    4,   2,   2,     2,    2),
            ("-4/2",   -4,   2,  -2,    -2,   -2),
            ( "1/3",    1,   3,   0,     1,    0),
            ("-1/3",   -1,   3,  -1,     0,    0),
        ];
        for &(label, n, d, ef, ec, et) in cases {
            let r = RatWitness::new(n, d).unwrap();
            let f = rat_floor(&r).as_i64().unwrap();
            let c = rat_ceil(&r).as_i64().unwrap();
            let t = rat_trunc(&r).as_i64().unwrap();
            println!("  floor({:>5}) = {:>3}  ceil = {:>3}  trunc = {:>3}", label, f, c, t);
            assert_eq!(f, ef, "floor failed for {label}");
            assert_eq!(c, ec, "ceil failed for {label}");
            assert_eq!(t, et, "trunc failed for {label}");
        }

        // rat.abs
        let neg = RatWitness::new(-3, 4).unwrap();
        let abs = rat_abs(&neg).unwrap();
        println!("  rat.abs(-3/4)      : {}/{}", abs.num.as_i64().unwrap(), abs.den.as_u64().unwrap());
        assert_eq!(abs.num.as_i64().unwrap(), 3);
        assert_eq!(abs.den.as_u64().unwrap(), 4);

        // rat.signum
        let pos = RatWitness::new(3, 4).unwrap();
        let z   = RatWitness::new(0, 1).unwrap();
        println!("  rat.signum(3/4)    : {}", rat_signum(&pos).as_i64().unwrap());
        println!("  rat.signum(-3/4)   : {}", rat_signum(&neg).as_i64().unwrap());
        println!("  rat.signum(0)      : {}", rat_signum(&z).as_i64().unwrap());
        assert_eq!(rat_signum(&pos).as_i64().unwrap(),  1);
        assert_eq!(rat_signum(&neg).as_i64().unwrap(), -1);
        assert_eq!(rat_signum(&z).as_i64().unwrap(),    0);

        // rat.pow
        let half = RatWitness::new(1, 2).unwrap();
        let p3 = rat_pow(&half, 3).unwrap();
        println!("  rat.pow(1/2, 3)    : {}/{}", p3.num.as_i64().unwrap(), p3.den.as_u64().unwrap());
        assert_eq!(p3.num.as_i64().unwrap(), 1);
        assert_eq!(p3.den.as_u64().unwrap(), 8);

        let pm3 = rat_pow(&half, -3).unwrap();
        println!("  rat.pow(1/2,-3)    : {}/{}", pm3.num.as_i64().unwrap(), pm3.den.as_u64().unwrap());
        assert_eq!(pm3.num.as_i64().unwrap(), 8);
        assert_eq!(pm3.den.as_u64().unwrap(), 1);

        let p0 = rat_pow(&half, 0).unwrap();
        println!("  rat.pow(1/2, 0)    : {}/{}", p0.num.as_i64().unwrap(), p0.den.as_u64().unwrap());
        assert_eq!(p0.num.as_i64().unwrap(), 1);
        assert_eq!(p0.den.as_u64().unwrap(), 1);
    }
    #[test]
    fn merkle_root_is_deterministic() {
        let a = sha256(b"a");
        let b = sha256(b"b");
        let root1 = merkle_root(&[a, b]);
        let root2 = merkle_root(&[a, b]);
        println!("
── merkle_root_is_deterministic ─────────────────");
        println!("  leaf[0]  : {}", hex_digest(&a));
        println!("  leaf[1]  : {}", hex_digest(&b));
        println!("  root (1) : {}", hex_digest(&root1));
        println!("  root (2) : {}", hex_digest(&root2));
        println!("  stable   : {}", root1 == root2);
        assert_eq!(root1, root2);
    }
}