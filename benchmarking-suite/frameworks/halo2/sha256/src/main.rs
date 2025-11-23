use std::time::Instant;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::{EqAffine, Fp},
    plonk::{
        Circuit, ConstraintSystem, Error,
        create_proof, keygen_pk, keygen_vk,
        ProvingKey, VerifyingKey, verify_proof, SingleVerifier,
    },
    poly::commitment::Params,
    transcript::{Blake2bWrite, Blake2bRead, Challenge255},
};

use halo2_gadgets::sha256::{
    BlockWord, Table16Chip, Table16Config, BLOCK_SIZE, Sha256Instructions,
};

use rand_core::OsRng;
use sha2::{Digest, Sha256 as Sha2Native};

fn pad_to_single_block(msg: &[u8]) -> [u32; 16] {
    assert!(
        msg.len() <= 55,
        "pad_to_single_block only supports messages up to 55 bytes"
    );

    let mut bytes = msg.to_vec();

    bytes.push(0x80);

    while bytes.len() < 56 {
        bytes.push(0);
    }

    let bit_len: u64 = (msg.len() as u64) * 8;
    bytes.extend_from_slice(&bit_len.to_be_bytes());

    assert_eq!(bytes.len(), 64);

    let mut words = [0u32; 16];
    for i in 0..16 {
        let base = 4 * i;
        words[i] = u32::from_be_bytes([
            bytes[base],
            bytes[base + 1],
            bytes[base + 2],
            bytes[base + 3],
        ]);
    }

    words
}

#[derive(Clone)]
struct Sha256Circuit {
    block_words: [u32; BLOCK_SIZE],
}

impl Circuit<Fp> for Sha256Circuit {
    type Config = Table16Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Sha256Circuit {
            block_words: [0u32; BLOCK_SIZE],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        Table16Chip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = Table16Chip::construct(config.clone());

        Table16Chip::load(config, &mut layouter)?;

        let mut block = [BlockWord::default(); BLOCK_SIZE];
        for (i, w) in self.block_words.iter().enumerate() {
            block[i] = BlockWord(Value::known(*w));
        }

        let state0 = chip.initialization_vector(&mut layouter.namespace(|| "iv"))?;

        let state1 = chip.compress(
            &mut layouter.namespace(|| "compress"),
            &state0,
            block,
        )?;

        let _digest = chip.digest(&mut layouter.namespace(|| "digest"), &state1)?;

        Ok(())
    }
}

fn empty_circuit() -> Sha256Circuit {
    Sha256Circuit {
        block_words: [0u32; BLOCK_SIZE],
    }
}

fn generate_setup_params(k: u32) -> Params<EqAffine> {
    Params::<EqAffine>::new(k)
}

fn generate_keys(
    params: &Params<EqAffine>,
    circuit: &Sha256Circuit,
) -> (ProvingKey<EqAffine>, VerifyingKey<EqAffine>) {
    let vk = keygen_vk(params, circuit).expect("vk should not fail");
    let pk = keygen_pk(params, vk.clone(), circuit).expect("pk should not fail");
    (pk, vk)
}

fn generate_proof(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    circuit: Sha256Circuit,
) -> Vec<u8> {
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    let instances: &[&[Fp]] = &[&[]];

    create_proof(
        params,
        pk,
        &[circuit],
        &[instances[0]],
        OsRng,
        &mut transcript,
    )
    .expect("prover should not fail");

    transcript.finalize()
}

fn verify(
    params: &Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    proof: Vec<u8>,
) -> Result<(), Error> {
    let strategy = SingleVerifier::new(params);
    let instances: &[&[Fp]] = &[&[]];

    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof(
        params,
        vk,
        strategy,
        &[instances[0]],
        &mut transcript,
    )
}

fn main() {
    let input_str = "hello world";
    let input_bytes = input_str.as_bytes();

    let mut hasher = Sha2Native::new();
    hasher.update(input_bytes);
    let native_digest = hasher.finalize();
    println!("Native SHA-256(\"{input_str}\") = {:x}", native_digest);

    let block_words = pad_to_single_block(input_bytes);

    let circuit = Sha256Circuit { block_words };

    let k: u32 = 18;

    let t_params_start = Instant::now();
    let params = generate_setup_params(k);
    let params_time = t_params_start.elapsed();
    println!("Param generation: {:?}", params_time);

    let empty = empty_circuit();
    let t_keygen_start = Instant::now();
    let (pk, vk) = generate_keys(&params, &empty);
    let keygen_time = t_keygen_start.elapsed();
    println!("Keygen (vk+pk): {:?}", keygen_time);

    let t_prove_start = Instant::now();
    let proof = generate_proof(&params, &pk, circuit);
    let prove_time = t_prove_start.elapsed();
    println!("Proving time: {:?}", prove_time);

    let t_verify_start = Instant::now();
    let res = verify(&params, &vk, proof);
    let verify_time = t_verify_start.elapsed();
    println!("Verify result: {:?}", res);
    println!("Verification time: {:?}", verify_time);
}
