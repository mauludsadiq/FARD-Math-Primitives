use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigestTrait, Sha256};
use std::cmp::Ordering;
use std::fmt;

pub type Digest = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArithMode {
    Native,
    ShadowChecked,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatWitness {
    pub extent: u64,
    pub canon: Vec<u8>,
    pub digest: Digest,
}

impl NatWitness {
    pub fn new(extent: u64) -> Self {
        let canon = encode_nat(extent);
        let digest = sha256(&canon);
        Self { extent, canon, digest }
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
    pub sign: Sign,
    pub magnitude: NatWitness,
    pub canon: Vec<u8>,
    pub digest: Digest,
}

impl IntWitness {
    pub fn new(value: i64) -> Self {
        let sign = match value.cmp(&0) {
            Ordering::Less => Sign::Negative,
            Ordering::Equal => Sign::Zero,
            Ordering::Greater => Sign::Positive,
        };
        let magnitude = NatWitness::new(value.unsigned_abs());
        let canon = encode_int(sign, magnitude.extent);
        let digest = sha256(&canon);
        Self {
            sign,
            magnitude,
            canon,
            digest,
        }
    }

    pub fn value(&self) -> i64 {
        match self.sign {
            Sign::Zero => 0,
            Sign::Positive => self.magnitude.extent as i64,
            Sign::Negative => (self.magnitude.extent as i64).wrapping_neg(),
        }
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
    pub fn new(num: i64, den: u64) -> Result<Self, ArithmeticError> {
        if den == 0 {
            return Err(ArithmeticError::ZeroDenominator);
        }
        let mut n = num;
        let mut d = den;
        let g = gcd_u64(n.unsigned_abs(), d);
        n /= g as i64;
        d /= g;
        if n == 0 {
            d = 1;
        }
        let num = IntWitness::new(n);
        let den = NatWitness::new(d);
        let mut canon = Vec::with_capacity(1 + num.canon.len() + den.canon.len());
        canon.push(0x03);
        canon.extend_from_slice(&num.canon);
        canon.extend_from_slice(&den.canon);
        let digest = sha256(&canon);
        Ok(Self {
            num,
            den,
            canon,
            digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StructuralRepr {
    HostInt(i64),
    ExactRational { num: i64, den: u64 },
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
        let wit = IntWitness::new(value);
        Self {
            repr: StructuralRepr::HostInt(value),
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
                num: wit.num.value(),
                den: wit.den.extent,
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
    let structural = IntWitness::new(lhs_num.as_i64() + rhs_num.as_i64());
    let verdict = native == structural.value();
    if matches!(mode, ArithMode::Strict) && !verdict {
        return Err(ArithmeticError::ShadowMismatch);
    }

    let out = StructuralNumber {
        repr: StructuralRepr::HostInt(structural.value()),
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
            StructuralWitness::Int(v) => v.value(),
            StructuralWitness::Nat(v) => v.extent as i64,
            StructuralWitness::Rat(v) => {
                if v.den.extent == 1 {
                    v.num.value()
                } else {
                    panic!("cannot losslessly coerce rational witness to i64")
                }
            }
        }
    }
}

pub fn encode_nat(n: u64) -> Vec<u8> {
    let mag = minimal_be_bytes_u64(n);
    let mut out = Vec::with_capacity(1 + 4 + mag.len());
    out.push(0x01);
    out.extend_from_slice(&(mag.len() as u32).to_be_bytes());
    out.extend_from_slice(&mag);
    out
}

pub fn encode_int(sign: Sign, magnitude: u64) -> Vec<u8> {
    let normalized_sign = if magnitude == 0 { Sign::Zero } else { sign };
    let nat = encode_nat(if matches!(normalized_sign, Sign::Zero) { 0 } else { magnitude });
    let mut out = Vec::with_capacity(1 + 1 + nat.len());
    out.push(0x02);
    out.push(match normalized_sign {
        Sign::Zero => 0x00,
        Sign::Positive => 0x01,
        Sign::Negative => 0x02,
    });
    out.extend_from_slice(&nat);
    out
}

pub fn encode_rat(num: i64, den: u64) -> Vec<u8> {
    let rat = RatWitness::new(num, den).expect("encode_rat requires nonzero denominator");
    let mut out = Vec::with_capacity(1 + rat.num.canon.len() + rat.den.canon.len());
    out.push(0x03);
    out.extend_from_slice(&rat.num.canon);
    out.extend_from_slice(&rat.den.canon);
    out
}

fn minimal_be_bytes_u64(n: u64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let bytes = n.to_be_bytes();
    let first_nonzero = bytes.iter().position(|b| *b != 0).unwrap();
    bytes[first_nonzero..].to_vec()
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
    a.extent == b.extent
}

// nat.cmp
pub fn nat_cmp(a: &NatWitness, b: &NatWitness) -> std::cmp::Ordering {
    a.extent.cmp(&b.extent)
}

// nat.add
pub fn nat_add(a: &NatWitness, b: &NatWitness) -> Result<NatWitness, ArithmeticError> {
    let v = a.extent.checked_add(b.extent).ok_or(ArithmeticError::NativeOverflow)?;
    Ok(NatWitness::new(v))
}

// nat.sub_checked
pub fn nat_sub_checked(a: &NatWitness, b: &NatWitness) -> Result<NatWitness, ArithmeticError> {
    if a.extent >= b.extent {
        Ok(NatWitness::new(a.extent - b.extent))
    } else {
        Err(ArithmeticError::NegativeNatResult)
    }
}

// nat.mul
pub fn nat_mul(a: &NatWitness, b: &NatWitness) -> Result<NatWitness, ArithmeticError> {
    let v = a.extent.checked_mul(b.extent).ok_or(ArithmeticError::NativeOverflow)?;
    Ok(NatWitness::new(v))
}

// int.eq
pub fn int_eq(a: &IntWitness, b: &IntWitness) -> bool {
    a.canon == b.canon
}

// int.cmp
pub fn int_cmp(a: &IntWitness, b: &IntWitness) -> std::cmp::Ordering {
    a.value().cmp(&b.value())
}

// int.add
pub fn int_add(a: &IntWitness, b: &IntWitness) -> Result<IntWitness, ArithmeticError> {
    let v = a.value().checked_add(b.value()).ok_or(ArithmeticError::NativeOverflow)?;
    Ok(IntWitness::new(v))
}

// int.sub
pub fn int_sub(a: &IntWitness, b: &IntWitness) -> Result<IntWitness, ArithmeticError> {
    let v = a.value().checked_sub(b.value()).ok_or(ArithmeticError::NativeOverflow)?;
    Ok(IntWitness::new(v))
}

// int.mul
pub fn int_mul(a: &IntWitness, b: &IntWitness) -> Result<IntWitness, ArithmeticError> {
    let v = a.value().checked_mul(b.value()).ok_or(ArithmeticError::NativeOverflow)?;
    Ok(IntWitness::new(v))
}

// int.neg
pub fn int_neg(a: &IntWitness) -> IntWitness {
    IntWitness::new(-a.value())
}

// rat.eq
pub fn rat_eq(a: &RatWitness, b: &RatWitness) -> bool {
    a.canon == b.canon
}

// rat.cmp
pub fn rat_cmp(a: &RatWitness, b: &RatWitness) -> std::cmp::Ordering {
    let lhs = a.num.value() * b.den.extent as i64;
    let rhs = b.num.value() * a.den.extent as i64;
    lhs.cmp(&rhs)
}

// rat.add
pub fn rat_add(a: &RatWitness, b: &RatWitness) -> Result<RatWitness, ArithmeticError> {
    let num = a.num.value() * b.den.extent as i64 + b.num.value() * a.den.extent as i64;
    let den = a.den.extent * b.den.extent;
    RatWitness::new(num, den)
}

// rat.sub
pub fn rat_sub(a: &RatWitness, b: &RatWitness) -> Result<RatWitness, ArithmeticError> {
    let num = a.num.value() * b.den.extent as i64 - b.num.value() * a.den.extent as i64;
    let den = a.den.extent * b.den.extent;
    RatWitness::new(num, den)
}

// rat.mul
pub fn rat_mul(a: &RatWitness, b: &RatWitness) -> Result<RatWitness, ArithmeticError> {
    let num = a.num.value() * b.num.value();
    let den = a.den.extent * b.den.extent;
    RatWitness::new(num, den)
}

// rat.div_checked
pub fn rat_div_checked(a: &RatWitness, b: &RatWitness) -> Result<RatWitness, ArithmeticError> {
    if b.num.value() == 0 {
        return Err(ArithmeticError::DivideByZero);
    }
    let num = a.num.value() * b.den.extent as i64;
    let den_raw = b.num.value() * a.den.extent as i64;
    if den_raw < 0 {
        RatWitness::new(-num, (-den_raw) as u64)
    } else {
        RatWitness::new(num, den_raw as u64)
    }
}

// rat.normalize (exposed as standalone — RatWitness::new already normalizes,
// this is the explicit contract entry point for candidate (num, den) pairs)
pub fn rat_normalize(num: i64, den: i64) -> Result<RatWitness, ArithmeticError> {
    if den == 0 {
        return Err(ArithmeticError::ZeroDenominator);
    }
    if den < 0 {
        RatWitness::new(-num, (-den) as u64)
    } else {
        RatWitness::new(num, den as u64)
    }
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
    let lhs_wit = IntWitness::new(lhs);
    let rhs_wit = IntWitness::new(rhs);
    let lhs_digest = lhs_wit.digest;
    let rhs_digest = rhs_wit.digest;

    let structural = structural_fn(&lhs_wit, &rhs_wit)?;

    let (native_val, native_summary, verdict) = match mode {
        ArithMode::Strict => {
            // native is optional cache only — structural is authoritative
            let summary = format!("strict:structural={}", structural.value());
            (structural.value(), summary, true)
        }
        ArithMode::ShadowChecked | ArithMode::Native => {
            let native = native_fn(lhs, rhs).ok_or(ArithmeticError::NativeOverflow)?;
            let verdict = native == structural.value();
            if !verdict {
                return Err(ArithmeticError::ShadowMismatch);
            }
            (native, format!("native={native}"), verdict)
        }
    };

    let _ = native_val;
    let out = StructuralNumber {
        repr: StructuralRepr::HostInt(structural.value()),
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

pub fn checked_int_add(lhs: i64, rhs: i64, mode: ArithMode) -> Result<OpResult, ArithmeticError> {
    execute_int_op("int.add", lhs, rhs, mode, |a, b| int_add(a, b), |a, b| a.checked_add(b))
}

pub fn checked_int_sub(lhs: i64, rhs: i64, mode: ArithMode) -> Result<OpResult, ArithmeticError> {
    execute_int_op("int.sub", lhs, rhs, mode, |a, b| int_sub(a, b), |a, b| a.checked_sub(b))
}

pub fn checked_int_mul(lhs: i64, rhs: i64, mode: ArithMode) -> Result<OpResult, ArithmeticError> {
    execute_int_op("int.mul", lhs, rhs, mode, |a, b| int_mul(a, b), |a, b| a.checked_mul(b))
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_canon_is_stable() {
        let n = NatWitness::new(10);
        let expected = encode_nat(10);
        println!("
── nat_canon_is_stable ──────────────────────────");
        println!("  value       : {}", n.extent);
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
        println!("  reduced num : {} (sign={})", r.num.magnitude.extent, r.num.sign);
        println!("  reduced den : {}", r.den.extent);
        println!("  canon bytes : {:02x?}", r.canon);
        println!("  digest      : {}", hex_digest(&r.digest));
        println!("  gcd(6,8)=2  → 6/8 reduces to {}/{}", r.num.value(), r.den.extent);
        assert_eq!(r.num.value(), 3);
        assert_eq!(r.den.extent, 4);
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
        let a = NatWitness::new(10);
        let b = NatWitness::new(4);
        println!("\n── nat_ops ──────────────────────────────────────");
        println!("  nat.eq(10,10)       : {}", nat_eq(&a, &NatWitness::new(10)));
        println!("  nat.eq(10,4)        : {}", nat_eq(&a, &b));
        println!("  nat.cmp(10,4)       : {:?}", nat_cmp(&a, &b));
        println!("  nat.add(10,4)       : {}", nat_add(&a, &b).unwrap().extent);
        println!("  nat.sub_checked(10,4): {}", nat_sub_checked(&a, &b).unwrap().extent);
        println!("  nat.sub_checked(4,10): {:?}", nat_sub_checked(&b, &a).unwrap_err());
        println!("  nat.mul(10,4)       : {}", nat_mul(&a, &b).unwrap().extent);
        assert!(nat_eq(&a, &NatWitness::new(10)));
        assert!(!nat_eq(&a, &b));
        assert_eq!(nat_cmp(&a, &b), std::cmp::Ordering::Greater);
        assert_eq!(nat_add(&a, &b).unwrap().extent, 14);
        assert_eq!(nat_sub_checked(&a, &b).unwrap().extent, 6);
        assert_eq!(nat_sub_checked(&b, &a).unwrap_err(), ArithmeticError::NegativeNatResult);
        assert_eq!(nat_mul(&a, &b).unwrap().extent, 40);
    }

    #[test]
    fn int_ops() {
        let a = IntWitness::new(10);
        let b = IntWitness::new(-4);
        let z = IntWitness::new(0);
        println!("\n── int_ops ──────────────────────────────────────");
        println!("  int.eq(10,10)  : {}", int_eq(&a, &IntWitness::new(10)));
        println!("  int.eq(10,-4)  : {}", int_eq(&a, &b));
        println!("  int.cmp(10,-4) : {:?}", int_cmp(&a, &b));
        println!("  int.add(10,-4) : {}", int_add(&a, &b).unwrap().value());
        println!("  int.sub(10,-4) : {}", int_sub(&a, &b).unwrap().value());
        println!("  int.mul(10,-4) : {}", int_mul(&a, &b).unwrap().value());
        println!("  int.neg(10)    : {}", int_neg(&a).value());
        println!("  int.neg(0)     : {}", int_neg(&z).value());
        println!("  neg(0) sign    : {:?}", int_neg(&z).sign);
        assert!(int_eq(&a, &IntWitness::new(10)));
        assert!(!int_eq(&a, &b));
        assert_eq!(int_cmp(&a, &b), std::cmp::Ordering::Greater);
        assert_eq!(int_add(&a, &b).unwrap().value(), 6);
        assert_eq!(int_sub(&a, &b).unwrap().value(), 14);
        assert_eq!(int_mul(&a, &b).unwrap().value(), -40);
        assert_eq!(int_neg(&a).value(), -10);
        assert_eq!(int_neg(&z).value(), 0);
        assert_eq!(int_neg(&z).sign, Sign::Zero);
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
        println!("  rat.add(1/2,1/3)     : {}/{}", sum.num.value(), sum.den.extent);
        let diff = rat_sub(&a, &b).unwrap();
        println!("  rat.sub(1/2,1/3)     : {}/{}", diff.num.value(), diff.den.extent);
        let prod = rat_mul(&a, &b).unwrap();
        println!("  rat.mul(1/2,1/3)     : {}/{}", prod.num.value(), prod.den.extent);
        let quot = rat_div_checked(&a, &b).unwrap();
        println!("  rat.div(1/2,1/3)     : {}/{}", quot.num.value(), quot.den.extent);
        println!("  rat.div_by_zero      : {:?}", rat_div_checked(&a, &c).unwrap_err());
        let norm = rat_normalize(6, -8).unwrap();
        println!("  rat.normalize(6,-8)  : {}/{}", norm.num.value(), norm.den.extent);
        assert!(rat_eq(&a, &RatWitness::new(1, 2).unwrap()));
        assert!(!rat_eq(&a, &b));
        assert_eq!(rat_cmp(&a, &b), std::cmp::Ordering::Greater);
        assert_eq!(sum.num.value(), 5);   assert_eq!(sum.den.extent, 6);
        assert_eq!(diff.num.value(), 1);  assert_eq!(diff.den.extent, 6);
        assert_eq!(prod.num.value(), 1);  assert_eq!(prod.den.extent, 6);
        assert_eq!(quot.num.value(), 3);  assert_eq!(quot.den.extent, 2);
        assert_eq!(rat_div_checked(&a, &c).unwrap_err(), ArithmeticError::DivideByZero);
        assert_eq!(norm.num.value(), -3); assert_eq!(norm.den.extent, 4);
    }

    #[test]
    fn overflow_policy() {
        println!("\n── overflow_policy ──────────────────────────────");

        let max_nat = NatWitness::new(u64::MAX);
        let one_nat = NatWitness::new(1);
        let r = nat_add(&max_nat, &one_nat);
        println!("  nat.add(u64::MAX, 1)      : {:?}", r.as_ref().unwrap_err());
        assert_eq!(r.unwrap_err(), ArithmeticError::NativeOverflow);

        let r = nat_mul(&max_nat, &NatWitness::new(2));
        println!("  nat.mul(u64::MAX, 2)      : {:?}", r.as_ref().unwrap_err());
        assert_eq!(r.unwrap_err(), ArithmeticError::NativeOverflow);

        let max_int = IntWitness::new(i64::MAX);
        let min_int = IntWitness::new(i64::MIN);
        let one_int = IntWitness::new(1);

        let r = int_add(&max_int, &one_int);
        println!("  int.add(i64::MAX, 1)      : {:?}", r.as_ref().unwrap_err());
        assert_eq!(r.unwrap_err(), ArithmeticError::NativeOverflow);

        let r = int_sub(&min_int, &one_int);
        println!("  int.sub(i64::MIN, 1)      : {:?}", r.as_ref().unwrap_err());
        assert_eq!(r.unwrap_err(), ArithmeticError::NativeOverflow);

        let r = int_mul(&max_int, &IntWitness::new(2));
        println!("  int.mul(i64::MAX, 2)      : {:?}", r.as_ref().unwrap_err());
        assert_eq!(r.unwrap_err(), ArithmeticError::NativeOverflow);

        println!("  all overflow paths → NativeOverflow ✓");
    }

    #[test]
    fn shadow_mismatch_detection() {
        println!("\n── shadow_mismatch_detection ────────────────────");

        // Normal case — native and structural agree
        let r = checked_int_add(10, 20, ArithMode::ShadowChecked).unwrap();
        println!("  add(10,20) ShadowChecked verdict : {}", r.receipt.verdict);
        println!("  add(10,20) out                   : {}", r.out.as_i64());
        assert_eq!(r.out.as_i64(), 30);
        assert!(r.receipt.verdict);

        // Overflow caught before mismatch check
        let r = checked_int_add(i64::MAX, 1, ArithMode::ShadowChecked);
        println!("  add(MAX,1) ShadowChecked         : {:?}", r.as_ref().unwrap_err());
        assert_eq!(r.unwrap_err(), ArithmeticError::NativeOverflow);

        // sub and mul happy paths
        let r = checked_int_sub(30, 10, ArithMode::ShadowChecked).unwrap();
        println!("  sub(30,10) ShadowChecked         : {}", r.out.as_i64());
        assert_eq!(r.out.as_i64(), 20);

        let r = checked_int_mul(6, 7, ArithMode::ShadowChecked).unwrap();
        println!("  mul(6,7)   ShadowChecked         : {}", r.out.as_i64());
        assert_eq!(r.out.as_i64(), 42);
    }

    #[test]
    fn strict_mode_authority() {
        println!("\n── strict_mode_authority ────────────────────────");

        // Strict: structural is authoritative, receipt always verdicts true
        let r = checked_int_add(10, 20, ArithMode::Strict).unwrap();
        println!("  add(10,20) Strict verdict        : {}", r.receipt.verdict);
        println!("  add(10,20) Strict out            : {}", r.out.as_i64());
        println!("  add(10,20) Strict native_summary : {}", r.receipt.native_summary);
        assert_eq!(r.out.as_i64(), 30);
        assert!(r.receipt.verdict);
        assert!(r.receipt.native_summary.starts_with("strict:structural="));

        // Strict: overflow in structural propagates as NativeOverflow
        let r = checked_int_add(i64::MAX, 1, ArithMode::Strict);
        println!("  add(MAX,1) Strict                : {:?}", r.as_ref().unwrap_err());
        assert_eq!(r.unwrap_err(), ArithmeticError::NativeOverflow);

        // Strict: mode is recorded on receipt
        let r = checked_int_mul(3, 4, ArithMode::Strict).unwrap();
        println!("  mul(3,4)   Strict mode field     : {:?}", r.receipt.mode);
        assert_eq!(r.receipt.mode, ArithMode::Strict);

        // ShadowChecked: mode is recorded on receipt
        let r = checked_int_mul(3, 4, ArithMode::ShadowChecked).unwrap();
        println!("  mul(3,4)   ShadowChecked mode    : {:?}", r.receipt.mode);
        assert_eq!(r.receipt.mode, ArithMode::ShadowChecked);
    }

    #[test]
    fn merkle_block_determinism() {
        println!("\n── merkle_block_determinism ─────────────────────");

        let r1 = checked_int_add(10, 20, ArithMode::ShadowChecked).unwrap();
        let r2 = checked_int_sub(50, 5,  ArithMode::ShadowChecked).unwrap();
        let r3 = checked_int_mul(3,  7,  ArithMode::ShadowChecked).unwrap();

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

        let r1 = checked_int_add(10, 20, ArithMode::ShadowChecked).unwrap();
        let r2 = checked_int_sub(50, 5,  ArithMode::ShadowChecked).unwrap();
        let r3 = checked_int_mul(3,  7,  ArithMode::ShadowChecked).unwrap();

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