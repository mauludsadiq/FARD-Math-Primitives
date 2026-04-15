use fard_math_primitives::{hex_digest, shadow_add_int, ArithMode, ArithmeticBlock};

fn main() {
    let (_, r1) = shadow_add_int(10, 20, ArithMode::ShadowChecked).expect("shadow add 1");
    let (_, r2) = shadow_add_int(30, 12, ArithMode::ShadowChecked).expect("shadow add 2");

    let block = ArithmeticBlock::from_receipts("demo-block", "shadow-commit", &[r1.clone(), r2.clone()]);

    println!("r1 leaf = {}", hex_digest(&r1.leaf_digest));
    println!("r2 leaf = {}", hex_digest(&r2.leaf_digest));
    println!("block root = {}", hex_digest(&block.merkle_root));
}
