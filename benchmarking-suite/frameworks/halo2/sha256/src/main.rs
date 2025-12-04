use halo2_gadgets::sha256::{BlockWord, Sha256Instructions, Table16Chip, Table16Config};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::{EqAffine, Fp},
    plonk::{Circuit, ConstraintSystem, Error},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    path::Path,
    time::{Instant, SystemTime},
};

#[derive(Clone)]
pub struct Sha256Config {
    pub table: Table16Config,
}

#[derive(Clone)]
pub struct Sha256Circuit {
    pub input: Vec<u8>,
}

impl Circuit<Fp> for Sha256Circuit {
    type Config = Sha256Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Sha256Circuit { input: vec![] }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let table = Table16Chip::configure(meta);
        Sha256Config { table }
    }

    fn synthesize(
        &self,
        config: Sha256Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = Table16Chip::construct(config.table.clone());
        Table16Chip::load(config.table.clone(), &mut layouter)?;

        let padded = sha256_pad(&self.input);

        let mut word_values = vec![];
        for chunk in padded.chunks(64) {
            for i in 0..16 {
                let b = 4 * i;
                let word = u32::from_be_bytes([chunk[b], chunk[b + 1], chunk[b + 2], chunk[b + 3]]);
                word_values.push(word);
            }
        }

        let state0 = chip.initialization_vector(&mut layouter.namespace(|| "iv"))?;
        let mut state = state0;

        let num_blocks = word_values.len() / 16;
        for block_idx in 0..num_blocks {
            let block_start = block_idx * 16;
            let block_words = &word_values[block_start..block_start + 16];

            let block_input: [BlockWord; 16] =
                std::array::from_fn(|i| BlockWord(Value::known(block_words[i])));

            state = chip.compress(
                &mut layouter.namespace(|| format!("compress block {}", block_idx)),
                &state,
                block_input,
            )?;
        }

        let _digest = chip.digest(&mut layouter.namespace(|| "digest"), &state)?;

        Ok(())
    }
}

fn needs_regeneration(file: &str) -> bool {
    let path = Path::new(file);
    if !path.exists() {
        return true;
    }
    let exe = std::env::current_exe().unwrap();
    let exe_meta = std::fs::metadata(exe).unwrap();
    let exe_mtime = exe_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let file_meta = std::fs::metadata(path).unwrap();
    let file_mtime = file_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    if exe_mtime > file_mtime {
        let _ = std::fs::remove_file(path);
        return true;
    }
    false
}

fn sha256_pad(msg: &[u8]) -> Vec<u8> {
    let mut out = msg.to_vec();
    out.push(0x80);
    while (out.len() % 64) != 56 {
        out.push(0x00);
    }
    let bit_len = (msg.len() as u64) * 8;
    out.extend_from_slice(&bit_len.to_be_bytes());
    out
}

fn main() {
    let k = 17;
    let params_path = "params.bin";

    let params = if needs_regeneration(params_path) {
        let params = Params::<EqAffine>::new(k);
        let mut f = File::create(params_path).unwrap();
        params.write(&mut f).unwrap();
        params
    } else {
        let mut f = File::open(params_path).unwrap();
        let params = Params::<EqAffine>::read(&mut f).unwrap();
        params
    };

    let message = std::env::args()
        .nth(1)
        .unwrap_or("Is this for real".to_string());
    let message_bytes = message.as_bytes().to_vec();

    let mut h = Sha256::new();
    h.update(&message_bytes);
    let digest = h.finalize();

    let circuit = Sha256Circuit {
        input: message_bytes.clone(),
    };

    let empty = Sha256Circuit { input: vec![] };
    let vk = keygen_vk(&params, &empty).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &empty).unwrap();

    let proving_start = Instant::now();

    let instances: &[&[&[Fp]]] = &[&[]];
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(&params, &pk, &[circuit], instances, OsRng, &mut transcript).unwrap();
    let proof = transcript.finalize();

    let proving_time = proving_start.elapsed();

    std::fs::write("proof.bin", &proof).unwrap();

    let proof = std::fs::read("proof.bin").unwrap();

    let empty = Sha256Circuit { input: vec![] };
    let vk = keygen_vk(&params, &empty).unwrap();

    let instances: &[&[&[Fp]]] = &[&[]];
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let verification_start = Instant::now();

    let res = verify_proof(
        &params,
        &vk,
        halo2_proofs::plonk::SingleVerifier::new(&params),
        instances,
        &mut transcript,
    );
}
