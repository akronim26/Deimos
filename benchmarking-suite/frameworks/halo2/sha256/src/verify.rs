use halo2_proofs::{
    pasta::{EqAffine, Fp},
    plonk::{verify_proof, keygen_vk},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use std::fs::File;

mod circuit;
use circuit::Sha256Circuit;

fn main() {
    // LOAD PARAMS
    let mut f = File::open("params.bin").unwrap();
    let params = Params::<EqAffine>::read(&mut f).unwrap();

    // LOAD PROOF
    let proof = std::fs::read("proof.bin").unwrap();

    // LOAD PUBLIC DIGEST
    let digest_words: [u32; 8] =
        bincode::deserialize(&std::fs::read("public.bin").unwrap()).unwrap();

    let instance_row: Vec<Fp> =
        digest_words.iter().map(|w| Fp::from(*w as u64)).collect();
    let instances: &[&[&[Fp]]] = &[ &[ &instance_row[..] ] ];

    // recreate vk (fast)
    let empty = Sha256Circuit { input: vec![] };
    let vk = keygen_vk(&params, &empty).unwrap();

    let mut transcript = Blake2bRead::<_,_,Challenge255<_>>::init(&proof[..]);

    let res = verify_proof(
        &params,
        &vk,
        halo2_proofs::plonk::SingleVerifier::new(&params),
        instances,
        &mut transcript,
    );

    println!("Verification: {:?}", res);
}
