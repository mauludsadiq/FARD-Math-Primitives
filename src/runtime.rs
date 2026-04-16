//! ArithCore Runtime Integration Layer
//!
//! This module is the stable entry point that the FARD runtime will call.
//! It does not touch the FARD runtime itself — it defines the contract
//! that the runtime will eventually call into.
//!
//! Design:
//! - Every numeric literal construction goes through runtime_nat / runtime_int / runtime_rat
//! - Every arithmetic operation goes through runtime_add / runtime_sub etc.
//! - Every op returns (StructuralNumber, ArithmeticStepReceipt)
//! - The caller (future runtime) attaches receipts to its trace segment
//! - Mode is set at the call site — shadow or strict

use crate::{
    ArithmeticError, ArithmeticStepReceipt, ArithmeticBlock,
    ArithMode, IntWitness, NatWitness, RatWitness,
    StructuralNumber, StructuralRepr, StructuralWitness,
    int_add, int_sub, int_mul, int_neg, int_abs, int_signum,
    int_divrem, int_pow, int_eq, int_cmp,
    nat_add, nat_sub_checked, nat_mul, nat_divrem, nat_pow,
    nat_eq, nat_cmp,
    rat_add, rat_sub, rat_mul, rat_div_checked,
    rat_eq, rat_cmp, rat_floor, rat_ceil, rat_trunc,
    rat_abs, rat_signum, rat_pow,
    ArithmeticStepReceipt as Receipt,
};
use crate::bignum::{BigNat, BigInt as OurBigInt};
use std::cmp::Ordering;

// ── Literal Construction ──────────────────────────────────────────────────────

/// Construct a runtime natural number witness from a BigNat value.
/// This is the entry point for Nat literal construction in the FARD runtime.
pub fn runtime_nat(value: BigNat, mode: ArithMode) -> StructuralNumber {
    StructuralNumber::from_nat(value, mode)
}

/// Construct a runtime integer witness from a BigInt value.
/// This is the entry point for Int literal construction in the FARD runtime.
pub fn runtime_int(value: OurBigInt, mode: ArithMode) -> StructuralNumber {
    StructuralNumber::from_bigint(value, mode)
}

/// Construct a runtime rational witness from a BigInt numerator and BigNat denominator.
/// This is the entry point for Rat literal construction in the FARD runtime.
pub fn runtime_rat(num: OurBigInt, den: BigNat, mode: ArithMode) -> Result<StructuralNumber, ArithmeticError> {
    StructuralNumber::from_rat_big(num, den, mode)
}

// ── Runtime Op Result ─────────────────────────────────────────────────────────

/// The result of a runtime arithmetic operation.
/// The caller attaches the receipt to its trace segment.
pub struct RuntimeOpResult {
    pub value: StructuralNumber,
    pub receipt: ArithmeticStepReceipt,
}

// ── Integer Operations ────────────────────────────────────────────────────────

pub fn runtime_int_add(a: &StructuralNumber, b: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_int_witness()?;
    let bw = b.as_int_witness()?;
    let out_wit = int_add(aw, bw)?;
    Ok(make_int_result("int.add", a, b, out_wit, mode))
}

pub fn runtime_int_sub(a: &StructuralNumber, b: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_int_witness()?;
    let bw = b.as_int_witness()?;
    let out_wit = int_sub(aw, bw)?;
    Ok(make_int_result("int.sub", a, b, out_wit, mode))
}

pub fn runtime_int_mul(a: &StructuralNumber, b: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_int_witness()?;
    let bw = b.as_int_witness()?;
    let out_wit = int_mul(aw, bw)?;
    Ok(make_int_result("int.mul", a, b, out_wit, mode))
}

pub fn runtime_int_divrem(a: &StructuralNumber, b: &StructuralNumber, mode: ArithMode)
    -> Result<(RuntimeOpResult, RuntimeOpResult), ArithmeticError>
{
    let aw = a.as_int_witness()?;
    let bw = b.as_int_witness()?;
    let (q_wit, r_wit) = int_divrem(aw, bw)?;
    let q = make_int_result("int.divrem.q", a, b, q_wit, mode);
    let r = make_int_result("int.divrem.r", a, b, r_wit, mode);
    Ok((q, r))
}

pub fn runtime_int_neg(a: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_int_witness()?;
    let out_wit = int_neg(aw);
    Ok(make_unary_int_result("int.neg", a, out_wit, mode))
}

pub fn runtime_int_abs(a: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_int_witness()?;
    let out_wit = int_abs(aw);
    Ok(make_unary_nat_result("int.abs", a, out_wit, mode))
}

pub fn runtime_int_pow(base: &StructuralNumber, exp: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let bw = base.as_int_witness()?;
    let ew = exp.as_nat_witness()?;
    let out_wit = int_pow(bw, ew);
    Ok(make_int_result("int.pow", base, exp, out_wit, mode))
}

pub fn runtime_int_eq(a: &StructuralNumber, b: &StructuralNumber)
    -> Result<bool, ArithmeticError>
{
    Ok(int_eq(a.as_int_witness()?, b.as_int_witness()?))
}

pub fn runtime_int_cmp(a: &StructuralNumber, b: &StructuralNumber)
    -> Result<Ordering, ArithmeticError>
{
    Ok(int_cmp(a.as_int_witness()?, b.as_int_witness()?))
}

// ── Nat Operations ────────────────────────────────────────────────────────────

pub fn runtime_nat_add(a: &StructuralNumber, b: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_nat_witness()?;
    let bw = b.as_nat_witness()?;
    let out_wit = nat_add(aw, bw);
    Ok(make_unary_nat_result("nat.add", a, out_wit, mode))
}

pub fn runtime_nat_mul(a: &StructuralNumber, b: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_nat_witness()?;
    let bw = b.as_nat_witness()?;
    let out_wit = nat_mul(aw, bw);
    Ok(make_unary_nat_result("nat.mul", a, out_wit, mode))
}

pub fn runtime_nat_divrem(a: &StructuralNumber, b: &StructuralNumber, mode: ArithMode)
    -> Result<(RuntimeOpResult, RuntimeOpResult), ArithmeticError>
{
    let aw = a.as_nat_witness()?;
    let bw = b.as_nat_witness()?;
    let (q_wit, r_wit) = nat_divrem(aw, bw)?;
    let q = make_unary_nat_result("nat.divrem.q", a, q_wit, mode);
    let r = make_unary_nat_result("nat.divrem.r", a, r_wit, mode);
    Ok((q, r))
}

pub fn runtime_nat_eq(a: &StructuralNumber, b: &StructuralNumber)
    -> Result<bool, ArithmeticError>
{
    Ok(nat_eq(a.as_nat_witness()?, b.as_nat_witness()?))
}

pub fn runtime_nat_cmp(a: &StructuralNumber, b: &StructuralNumber)
    -> Result<Ordering, ArithmeticError>
{
    Ok(nat_cmp(a.as_nat_witness()?, b.as_nat_witness()?))
}

// ── Rat Operations ────────────────────────────────────────────────────────────

pub fn runtime_rat_add(a: &StructuralNumber, b: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_rat_witness()?;
    let bw = b.as_rat_witness()?;
    let out_wit = rat_add(aw, bw)?;
    Ok(make_rat_result("rat.add", a, b, out_wit, mode))
}

pub fn runtime_rat_sub(a: &StructuralNumber, b: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_rat_witness()?;
    let bw = b.as_rat_witness()?;
    let out_wit = rat_sub(aw, bw)?;
    Ok(make_rat_result("rat.sub", a, b, out_wit, mode))
}

pub fn runtime_rat_mul(a: &StructuralNumber, b: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_rat_witness()?;
    let bw = b.as_rat_witness()?;
    let out_wit = rat_mul(aw, bw)?;
    Ok(make_rat_result("rat.mul", a, b, out_wit, mode))
}

pub fn runtime_rat_div(a: &StructuralNumber, b: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_rat_witness()?;
    let bw = b.as_rat_witness()?;
    let out_wit = rat_div_checked(aw, bw)?;
    Ok(make_rat_result("rat.div", a, b, out_wit, mode))
}

pub fn runtime_rat_floor(a: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_rat_witness()?;
    let out_wit = rat_floor(aw);
    Ok(make_unary_int_result("rat.floor", a, out_wit, mode))
}

pub fn runtime_rat_ceil(a: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_rat_witness()?;
    let out_wit = rat_ceil(aw);
    Ok(make_unary_int_result("rat.ceil", a, out_wit, mode))
}

pub fn runtime_rat_trunc(a: &StructuralNumber, mode: ArithMode)
    -> Result<RuntimeOpResult, ArithmeticError>
{
    let aw = a.as_rat_witness()?;
    let out_wit = rat_trunc(aw);
    Ok(make_unary_int_result("rat.trunc", a, out_wit, mode))
}

pub fn runtime_rat_eq(a: &StructuralNumber, b: &StructuralNumber)
    -> Result<bool, ArithmeticError>
{
    Ok(rat_eq(a.as_rat_witness()?, b.as_rat_witness()?))
}

pub fn runtime_rat_cmp(a: &StructuralNumber, b: &StructuralNumber)
    -> Result<Ordering, ArithmeticError>
{
    Ok(rat_cmp(a.as_rat_witness()?, b.as_rat_witness()?))
}

// ── Trace Block ───────────────────────────────────────────────────────────────

/// Aggregate a sequence of receipts from a runtime region into a Merkle block.
/// The caller provides a block_id corresponding to its trace segment.
pub fn runtime_commit_block(
    block_id: &str,
    receipts: &[ArithmeticStepReceipt],
) -> ArithmeticBlock {
    ArithmeticBlock::from_receipts(block_id, "commit_only", receipts)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn make_receipt(
    op: &str,
    lhs: &StructuralNumber,
    rhs: &StructuralNumber,
    out: &StructuralNumber,
    mode: ArithMode,
) -> ArithmeticStepReceipt {
    let summary = format!("structural={}", out.canon_hex());
    ArithmeticStepReceipt::new(
        op,
        lhs.receipt_link,
        rhs.receipt_link,
        out.receipt_link,
        summary,
        true,
        mode,
    )
}

fn make_unary_receipt(
    op: &str,
    input: &StructuralNumber,
    out: &StructuralNumber,
    mode: ArithMode,
) -> ArithmeticStepReceipt {
    let summary = format!("structural={}", out.canon_hex());
    // use input digest for both lhs and rhs slots for unary ops
    ArithmeticStepReceipt::new(
        op,
        input.receipt_link,
        input.receipt_link,
        out.receipt_link,
        summary,
        true,
        mode,
    )
}

fn make_int_result(
    op: &str,
    lhs: &StructuralNumber,
    rhs: &StructuralNumber,
    out_wit: IntWitness,
    mode: ArithMode,
) -> RuntimeOpResult {
    let out = StructuralNumber::from_bigint(out_wit.value.clone(), mode);
    let receipt = make_receipt(op, lhs, rhs, &out, mode);
    RuntimeOpResult { value: out, receipt }
}

fn make_unary_int_result(
    op: &str,
    input: &StructuralNumber,
    out_wit: IntWitness,
    mode: ArithMode,
) -> RuntimeOpResult {
    let out = StructuralNumber::from_bigint(out_wit.value.clone(), mode);
    let receipt = make_unary_receipt(op, input, &out, mode);
    RuntimeOpResult { value: out, receipt }
}

fn make_unary_nat_result(
    op: &str,
    input: &StructuralNumber,
    out_wit: NatWitness,
    mode: ArithMode,
) -> RuntimeOpResult {
    let out = StructuralNumber::from_nat(out_wit.magnitude.clone(), mode);
    let receipt = make_unary_receipt(op, input, &out, mode);
    RuntimeOpResult { value: out, receipt }
}

fn make_rat_result(
    op: &str,
    lhs: &StructuralNumber,
    rhs: &StructuralNumber,
    out_wit: RatWitness,
    mode: ArithMode,
) -> RuntimeOpResult {
    let out = StructuralNumber {
        repr: crate::StructuralRepr::ExactRational {
            num: out_wit.num.value.clone(),
            den: out_wit.den.magnitude.clone(),
        },
        canon: out_wit.canon.clone(),
        mode,
        receipt_link: out_wit.digest,
        witness: StructuralWitness::Rat(out_wit),
    };
    let receipt = make_receipt(op, lhs, rhs, &out, mode);
    RuntimeOpResult { value: out, receipt }
}
