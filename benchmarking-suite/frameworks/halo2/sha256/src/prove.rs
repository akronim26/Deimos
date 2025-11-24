use halo2_proofs::{
    pasta::{EqAffine, Fp},
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};
use rand_core::OsRng;
use sha2::{Sha256, Digest};
use std::{fs::File, io::Read};

mod circuit;
use circuit::Sha256Circuit;

fn main() {
    // LOAD PARAMS
    let mut f = File::open("params.bin").unwrap();
    let params = Params::<EqAffine>::read(&mut f).unwrap();

    let message = std::env::args().nth(1).unwrap_or("hello world".to_string());
    let message_bytes = message.as_bytes().to_vec();

    // Native digest
    let mut h = Sha256::new();
    h.update(&message_bytes);
    let digest = h.finalize();

    let mut digest_words = [0u32; 8];
    for i in 0..8 {
        let b = 4 * i;
        digest_words[i] = u32::from_be_bytes([digest[b], digest[b+1], digest[b+2], digest[b+3]]);
    }

    // public inputs
    let instance_row: Vec<Fp> = digest_words.iter().map(|w| Fp::from(*w as u64)).collect();
    let instances: &[&[&[Fp]]] = &[ &[ &instance_row[..] ] ];

    // circuit
    let circuit = Sha256Circuit { input: message_bytes.clone() };

    // keygen
    let empty = Sha256Circuit { input: vec![] };
    let vk = keygen_vk(&params, &empty).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &empty).unwrap();

    // create proof
    let mut transcript = Blake2bWrite::<_,_,Challenge255<_>>::init(vec![]);
    create_proof(&params, &pk, &[circuit], instances, OsRng, &mut transcript).unwrap();
    let proof = transcript.finalize();

    std::fs::write("proof.bin", &proof).unwrap();
    std::fs::write("public.bin", &bincode::serialize(&digest_words).unwrap()).unwrap();

    println!("proof.bin and public.bin generated");
}
