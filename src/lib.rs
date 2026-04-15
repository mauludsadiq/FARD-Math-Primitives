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
            Sign::Negative => -(self.magnitude.extent as i64),
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
        let canon = encode_rat(num.value(), den.extent);
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
    let mut out = b"NAT\0".to_vec();
    out.extend_from_slice(&n.to_be_bytes());
    out
}

pub fn encode_int(sign: Sign, magnitude: u64) -> Vec<u8> {
    let mut out = b"INT\0".to_vec();
    out.push(match sign {
        Sign::Negative => 0,
        Sign::Zero => 1,
        Sign::Positive => 2,
    });
    out.extend_from_slice(&magnitude.to_be_bytes());
    out
}

pub fn encode_rat(num: i64, den: u64) -> Vec<u8> {
    let mut out = b"RAT\0".to_vec();
    out.extend_from_slice(&num.to_be_bytes());
    out.extend_from_slice(&den.to_be_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_canon_is_stable() {
        let n = NatWitness::new(10);
        assert_eq!(n.canon, encode_nat(10));
        assert_eq!(n.digest, sha256(&n.canon));
    }

    #[test]
    fn rat_reduces() {
        let r = RatWitness::new(6, 8).unwrap();
        assert_eq!(r.num.value(), 3);
        assert_eq!(r.den.extent, 4);
    }

    #[test]
    fn shadow_add_produces_receipt() {
        let (out, receipt) = shadow_add_int(10, 20, ArithMode::ShadowChecked).unwrap();
        assert_eq!(out.as_i64(), 30);
        assert!(receipt.verdict);
    }

    #[test]
    fn merkle_root_is_deterministic() {
        let a = sha256(b"a");
        let b = sha256(b"b");
        assert_eq!(merkle_root(&[a, b]), merkle_root(&[a, b]));
    }
}
