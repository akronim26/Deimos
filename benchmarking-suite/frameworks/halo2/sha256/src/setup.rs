use halo2_proofs::{
    pasta::EqAffine,
    poly::commitment::Params,
};
use std::fs::File;

fn main() {
    let k = 18;
    let params = Params::<EqAffine>::new(k);

    let mut f = File::create("params.bin").unwrap();
    params.write(&mut f).unwrap();

    println!("Generated params.bin");
}
