// ── BigNat: unbounded natural number ─────────────────────────────────────────
// Limbs are u32, stored least-significant first (little-endian limb order).
// External canonical form is always big-endian minimal bytes.

use crate::Sign;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BigNat {
    // limbs[0] is least significant
    limbs: Vec<u32>,
}

impl BigNat {
    pub fn zero() -> Self {
        Self { limbs: vec![] }
    }

    pub fn from_u64(n: u64) -> Self {
        if n == 0 {
            return Self::zero();
        }
        let lo = n as u32;
        let hi = (n >> 32) as u32;
        if hi == 0 {
            Self { limbs: vec![lo] }
        } else {
            Self { limbs: vec![lo, hi] }
        }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    // Normalize: remove trailing zero limbs
    fn normalize(mut self) -> Self {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
        self
    }

    // Convert to minimal big-endian bytes (no leading zeros)
    pub fn to_be_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![];
        }
        // most significant limb first
        let mut out = Vec::new();
        for &limb in self.limbs.iter().rev() {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        // strip leading zeros
        let first_nonzero = out.iter().position(|&b| b != 0).unwrap_or(out.len());
        out[first_nonzero..].to_vec()
    }

    // Build from minimal big-endian bytes
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        // pad to multiple of 4
        let mut padded = vec![0u8; (4 - bytes.len() % 4) % 4];
        padded.extend_from_slice(bytes);
        let mut limbs = Vec::new();
        for chunk in padded.chunks(4).rev() {
            limbs.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        Self { limbs }.normalize()
    }

    pub fn cmp_nat(&self, other: &BigNat) -> Ordering {
        match self.limbs.len().cmp(&other.limbs.len()) {
            Ordering::Equal => {
                for (a, b) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
                    match a.cmp(b) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    }
                }
                Ordering::Equal
            }
            ord => ord,
        }
    }

    pub fn add(&self, other: &BigNat) -> BigNat {
        let len = self.limbs.len().max(other.limbs.len()) + 1;
        let mut result = vec![0u32; len];
        let mut carry: u64 = 0;
        for i in 0..len {
            let a = self.limbs.get(i).copied().unwrap_or(0) as u64;
            let b = other.limbs.get(i).copied().unwrap_or(0) as u64;
            let sum = a + b + carry;
            result[i] = sum as u32;
            carry = sum >> 32;
        }
        BigNat { limbs: result }.normalize()
    }

    // Subtract: panics if self < other — caller must check
    pub fn sub(&self, other: &BigNat) -> BigNat {
        assert!(self.cmp_nat(other) != Ordering::Less, "BigNat::sub underflow");
        let mut result = self.limbs.clone();
        let mut borrow: i64 = 0;
        for i in 0..result.len() {
            let b = other.limbs.get(i).copied().unwrap_or(0) as i64;
            let diff = result[i] as i64 - b - borrow;
            if diff < 0 {
                result[i] = (diff + (1i64 << 32)) as u32;
                borrow = 1;
            } else {
                result[i] = diff as u32;
                borrow = 0;
            }
        }
        BigNat { limbs: result }.normalize()
    }

    pub fn mul(&self, other: &BigNat) -> BigNat {
        if self.is_zero() || other.is_zero() {
            return BigNat::zero();
        }
        let len = self.limbs.len() + other.limbs.len();
        let mut result = vec![0u128; len];
        for (i, &a) in self.limbs.iter().enumerate() {
            for (j, &b) in other.limbs.iter().enumerate() {
                result[i + j] += a as u128 * b as u128;
            }
        }
        // propagate carries
        let mut limbs = vec![0u32; len];
        let mut carry: u128 = 0;
        for i in 0..len {
            let val = result[i] + carry;
            limbs[i] = val as u32;
            carry = val >> 32;
        }
        BigNat { limbs }.normalize()
    }

    // Division: returns (quotient, remainder)
    pub fn divrem(&self, other: &BigNat) -> (BigNat, BigNat) {
        assert!(!other.is_zero(), "BigNat::divrem divide by zero");
        if self.cmp_nat(other) == Ordering::Less {
            return (BigNat::zero(), self.clone());
        }
        // Long division on be_bytes for simplicity
        let a = self.to_be_bytes();
        let b = other.clone();
        let mut rem = BigNat::zero();
        let mut quot_bytes = vec![0u8; a.len()];
        for (i, &byte) in a.iter().enumerate() {
            // rem = rem * 256 + byte
            rem = rem.mul(&BigNat::from_u64(256)).add(&BigNat::from_u64(byte as u64));
            // find how many times b fits in rem
            let mut q: u8 = 0;
            while rem.cmp_nat(&b) != Ordering::Less {
                rem = rem.sub(&b);
                q += 1;
            }
            quot_bytes[i] = q;
        }
        (BigNat::from_be_bytes(&quot_bytes), rem)
    }

    pub fn gcd(mut a: BigNat, mut b: BigNat) -> BigNat {
        while !b.is_zero() {
            let (_, r) = a.divrem(&b);
            a = b;
            b = r;
        }
        a
    }

    pub fn to_u64(&self) -> Option<u64> {
        match self.limbs.len() {
            0 => Some(0),
            1 => Some(self.limbs[0] as u64),
            2 => Some(self.limbs[0] as u64 | ((self.limbs[1] as u64) << 32)),
            _ => None,
        }
    }
}

impl fmt::Display for BigNat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }
        // divide by 10 repeatedly
        let mut n = self.clone();
        let ten = BigNat::from_u64(10);
        let mut digits = Vec::new();
        while !n.is_zero() {
            let (q, r) = n.divrem(&ten);
            digits.push(r.to_u64().unwrap_or(0) as u8 + b'0');
            n = q;
        }
        digits.reverse();
        write!(f, "{}", String::from_utf8(digits).unwrap())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BigInt {
    pub sign: Sign,
    pub magnitude: BigNat,
}

impl BigInt {
    pub fn zero() -> Self {
        Self { sign: Sign::Zero, magnitude: BigNat::zero() }
    }

    pub fn from_i64(n: i64) -> Self {
        let sign = match n.cmp(&0) {
            Ordering::Less => Sign::Negative,
            Ordering::Equal => Sign::Zero,
            Ordering::Greater => Sign::Positive,
        };
        let magnitude = BigNat::from_u64(n.unsigned_abs());
        Self { sign, magnitude }
    }

    pub fn from_bignat(sign: Sign, magnitude: BigNat) -> Self {
        if magnitude.is_zero() {
            return Self::zero();
        }
        Self { sign, magnitude }
    }

    pub fn is_zero(&self) -> bool {
        matches!(self.sign, Sign::Zero)
    }

    pub fn negate(&self) -> Self {
        match self.sign {
            Sign::Zero => Self::zero(),
            Sign::Positive => Self { sign: Sign::Negative, magnitude: self.magnitude.clone() },
            Sign::Negative => Self { sign: Sign::Positive, magnitude: self.magnitude.clone() },
        }
    }

    pub fn abs(&self) -> BigNat {
        self.magnitude.clone()
    }

    pub fn add(&self, other: &BigInt) -> BigInt {
        match (self.sign, other.sign) {
            (Sign::Zero, _) => other.clone(),
            (_, Sign::Zero) => self.clone(),
            (Sign::Positive, Sign::Positive) => {
                BigInt::from_bignat(Sign::Positive, self.magnitude.add(&other.magnitude))
            }
            (Sign::Negative, Sign::Negative) => {
                BigInt::from_bignat(Sign::Negative, self.magnitude.add(&other.magnitude))
            }
            (Sign::Positive, Sign::Negative) | (Sign::Negative, Sign::Positive) => {
                match self.magnitude.cmp_nat(&other.magnitude) {
                    Ordering::Equal => BigInt::zero(),
                    Ordering::Greater => {
                        let mag = self.magnitude.sub(&other.magnitude);
                        BigInt::from_bignat(self.sign, mag)
                    }
                    Ordering::Less => {
                        let mag = other.magnitude.sub(&self.magnitude);
                        BigInt::from_bignat(other.sign, mag)
                    }
                }
            }
        }
    }

    pub fn sub(&self, other: &BigInt) -> BigInt {
        self.add(&other.negate())
    }

    pub fn mul(&self, other: &BigInt) -> BigInt {
        if self.is_zero() || other.is_zero() {
            return BigInt::zero();
        }
        let mag = self.magnitude.mul(&other.magnitude);
        let sign = match (self.sign, other.sign) {
            (Sign::Positive, Sign::Positive) => Sign::Positive,
            (Sign::Negative, Sign::Negative) => Sign::Positive,
            _ => Sign::Negative,
        };
        BigInt::from_bignat(sign, mag)
    }

    pub fn cmp_int(&self, other: &BigInt) -> Ordering {
        match (self.sign, other.sign) {
            (Sign::Zero, Sign::Zero) => Ordering::Equal,
            (Sign::Positive, Sign::Negative) => Ordering::Greater,
            (Sign::Negative, Sign::Positive) => Ordering::Less,
            (Sign::Zero, Sign::Positive) => Ordering::Less,
            (Sign::Zero, Sign::Negative) => Ordering::Greater,
            (Sign::Positive, Sign::Zero) => Ordering::Greater,
            (Sign::Negative, Sign::Zero) => Ordering::Less,
            (Sign::Positive, Sign::Positive) => self.magnitude.cmp_nat(&other.magnitude),
            (Sign::Negative, Sign::Negative) => other.magnitude.cmp_nat(&self.magnitude),
        }
    }

    pub fn to_i64(&self) -> Option<i64> {
        match self.sign {
            Sign::Zero => Some(0),
            Sign::Positive => self.magnitude.to_u64().and_then(|n| i64::try_from(n).ok()),
            Sign::Negative => self.magnitude.to_u64().map(|n| (n as i64).wrapping_neg()),
        }
    }
}

impl fmt::Display for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.sign {
            Sign::Negative => write!(f, "-{}", self.magnitude),
            _ => write!(f, "{}", self.magnitude),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bignat_basics() {
        println!("\n── bignat_basics ────────────────────────────────");

        let zero = BigNat::zero();
        let one  = BigNat::from_u64(1);
        let ten  = BigNat::from_u64(10);
        let big  = BigNat::from_u64(u64::MAX);

        println!("  zero           : {}", zero);
        println!("  one            : {}", one);
        println!("  ten            : {}", ten);
        println!("  u64::MAX       : {}", big);
        println!("  is_zero(zero)  : {}", zero.is_zero());
        println!("  is_zero(one)   : {}", one.is_zero());

        assert!(zero.is_zero());
        assert!(!one.is_zero());
        assert_eq!(zero.to_u64(), Some(0));
        assert_eq!(one.to_u64(), Some(1));
        assert_eq!(big.to_u64(), Some(u64::MAX));
    }

    #[test]
    fn bignat_add() {
        println!("\n── bignat_add ───────────────────────────────────");

        let a = BigNat::from_u64(u64::MAX);
        let b = BigNat::from_u64(1);
        let sum = a.add(&b);
        println!("  u64::MAX + 1   : {}", sum);
        println!("  limbs          : {:?}", sum.to_be_bytes());

        // Must exceed u64 — to_u64 returns None
        assert_eq!(sum.to_u64(), None);

        // Round-trip via be_bytes
        let rt = BigNat::from_be_bytes(&sum.to_be_bytes());
        assert_eq!(rt, sum);
        println!("  round-trip     : ok");

        let x = BigNat::from_u64(12345);
        let y = BigNat::from_u64(67890);
        let s = x.add(&y);
        println!("  12345 + 67890  : {}", s);
        assert_eq!(s.to_u64(), Some(80235));
    }

    #[test]
    fn bignat_sub() {
        println!("\n── bignat_sub ───────────────────────────────────");

        let a = BigNat::from_u64(100);
        let b = BigNat::from_u64(37);
        let d = a.sub(&b);
        println!("  100 - 37       : {}", d);
        assert_eq!(d.to_u64(), Some(63));

        let zero = a.sub(&a);
        println!("  100 - 100      : {}", zero);
        assert!(zero.is_zero());
    }

    #[test]
    fn bignat_mul() {
        println!("\n── bignat_mul ───────────────────────────────────");

        let a = BigNat::from_u64(u64::MAX);
        let b = BigNat::from_u64(u64::MAX);
        let p = a.mul(&b);
        println!("  u64::MAX * u64::MAX : {}", p);
        assert_eq!(p.to_u64(), None); // exceeds u64

        let x = BigNat::from_u64(1234);
        let y = BigNat::from_u64(5678);
        let q = x.mul(&y);
        println!("  1234 * 5678    : {}", q);
        assert_eq!(q.to_u64(), Some(7006652));
    }

    #[test]
    fn bignat_divrem() {
        println!("\n── bignat_divrem ────────────────────────────────");

        let a = BigNat::from_u64(100);
        let b = BigNat::from_u64(7);
        let (q, r) = a.divrem(&b);
        println!("  100 / 7        : {} rem {}", q, r);
        assert_eq!(q.to_u64(), Some(14));
        assert_eq!(r.to_u64(), Some(2));

        let big = BigNat::from_u64(u64::MAX).add(&BigNat::from_u64(1));
        let (q2, r2) = big.divrem(&BigNat::from_u64(2));
        println!("  (u64::MAX+1)/2 : {} rem {}", q2, r2);
        assert_eq!(q2.to_u64(), Some(1u64 << 63));
        assert!(r2.is_zero());
    }

    #[test]
    fn bignat_gcd() {
        println!("\n── bignat_gcd ───────────────────────────────────");

        let cases = [(12u64, 8u64, 4u64), (100, 75, 25), (17, 13, 1), (0, 5, 5)];
        for (a, b, expected) in cases {
            let g = BigNat::gcd(BigNat::from_u64(a), BigNat::from_u64(b));
            println!("  gcd({},{}) = {}", a, b, g);
            assert_eq!(g.to_u64(), Some(expected));
        }
    }

    #[test]
    fn bigint_arithmetic() {
        println!("\n── bigint_arithmetic ────────────────────────────");

        let pos = BigInt::from_i64(42);
        let neg = BigInt::from_i64(-17);
        let zero = BigInt::zero();

        println!("  42 + (-17)     : {}", pos.add(&neg));
        println!("  42 - (-17)     : {}", pos.sub(&neg));
        println!("  42 * (-17)     : {}", pos.mul(&neg));
        println!("  neg(42)        : {}", pos.negate());
        println!("  neg(0)         : {}", zero.negate());
        println!("  cmp(42,-17)    : {:?}", pos.cmp_int(&neg));

        assert_eq!(pos.add(&neg).to_i64(), Some(25));
        assert_eq!(pos.sub(&neg).to_i64(), Some(59));
        assert_eq!(pos.mul(&neg).to_i64(), Some(-714));
        assert_eq!(pos.negate().to_i64(), Some(-42));
        assert_eq!(zero.negate().to_i64(), Some(0));
        assert_eq!(pos.cmp_int(&neg), Ordering::Greater);

        // Beyond i64 range
        let big_a = BigInt::from_i64(i64::MAX);
        let big_b = BigInt::from_i64(1);
        let big_sum = big_a.add(&big_b);
        println!("  i64::MAX + 1   : {}", big_sum);
        assert_eq!(big_sum.to_i64(), None); // exceeds i64
        assert!(!big_sum.is_zero());
    }

    #[test]
    fn bignat_be_bytes_roundtrip() {
        println!("\n── bignat_be_bytes_roundtrip ────────────────────");

        for n in [0u64, 1, 127, 128, 255, 256, 65535, 65536, u64::MAX] {
            let bn = BigNat::from_u64(n);
            let bytes = bn.to_be_bytes();
            let rt = BigNat::from_be_bytes(&bytes);
            assert_eq!(rt, bn, "round-trip failed for {n}");
            println!("  {:>20} : ok  bytes={:02x?}", n, bytes);
        }
    }
}
