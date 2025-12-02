use halo2_gadgets::sha256::{BlockWord, Sha256Instructions, Table16Chip, Table16Config};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::{EqAffine, Fp},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Instance,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fs::File;

#[derive(Clone)]
pub struct Sha256Config {
    pub table: Table16Config,
    pub input_advice: Column<Advice>,
    pub digest_advice: Column<Advice>,
    pub instance: Column<Instance>,
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
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let input_advice = meta.advice_column();
        meta.enable_equality(input_advice);

        let digest_advice = meta.advice_column();
        meta.enable_equality(digest_advice);

        let table = Table16Chip::configure(meta);

        Sha256Config {
            table,
            input_advice,
            digest_advice,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Sha256Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = Table16Chip::construct(config.table.clone());
        Table16Chip::load(config.table.clone(), &mut layouter)?;

        let mut input_cells: Vec<AssignedCell<Fp, Fp>> = vec![];

        layouter.assign_region(
            || "assign input",
            |mut region| {
                for (i, byte) in self.input.iter().enumerate() {
                    let val = Value::known(Fp::from(*byte as u64));
                    let cell = region.assign_advice(
                        || format!("input_{i}"),
                        config.input_advice,
                        i,
                        || val,
                    )?;
                    input_cells.push(cell);
                }
                Ok(())
            },
        )?;

        for (i, cell) in input_cells.iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.instance, i)?;
        }

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

            // For subsequent blocks, we need to initialize the state from the previous block's output
            if block_idx > 0 {
                state = chip.initialization(
                    &mut layouter.namespace(|| format!("init block {}", block_idx)),
                    &state,
                )?;
            }

            state = chip.compress(
                &mut layouter.namespace(|| format!("compress block {}", block_idx)),
                &state,
                block_input,
            )?;
        }

        let digest = chip.digest(&mut layouter.namespace(|| "digest"), &state)?;

        let mut digest_cells: Vec<AssignedCell<Fp, Fp>> = vec![];

        layouter.assign_region(
            || "assign digest",
            |mut region| {
                for i in 0..8 {
                    let val = digest[i].0.map(|v| Fp::from(v as u64));
                    let cell = region.assign_advice(
                        || format!("digest_{i}"),
                        config.digest_advice,
                        i,
                        || val,
                    )?;
                    digest_cells.push(cell);
                }
                Ok(())
            },
        )?;

        let digest_offset = self.input.len();
        for i in 0..8 {
            layouter.constrain_instance(
                digest_cells[i].cell(),
                config.instance,
                digest_offset + i,
            )?;
        }

        Ok(())
    }
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
    println!("=== Halo2 SHA-256 Circuit with Public Input and Output ===\n");

    let k = 18;
    println!("Generating parameters with k = {}...", k);
    let params = Params::<EqAffine>::new(k);

    let mut f = File::create("params.bin").unwrap();
    params.write(&mut f).unwrap();
    println!("✓ Generated params.bin\n");

    let mut f = File::open("params.bin").unwrap();
    let params = Params::<EqAffine>::read(&mut f).unwrap();

    let message = std::env::args().nth(1).unwrap_or("hello world".to_string());
    println!("Input message: \"{}\"", message);
    let message_bytes = message.as_bytes().to_vec();
    println!("Input length: {} bytes\n", message_bytes.len());

    let mut h = Sha256::new();
    h.update(&message_bytes);
    let digest = h.finalize();

    println!("Expected SHA-256 hash:");
    print!("  Hex: ");
    for byte in digest.iter() {
        print!("{:02x}", byte);
    }
    println!();

    let mut digest_words = [0u32; 8];
    for i in 0..8 {
        let b = 4 * i;
        digest_words[i] =
            u32::from_be_bytes([digest[b], digest[b + 1], digest[b + 2], digest[b + 3]]);
    }
    println!("  Words: {:?}\n", digest_words);

    let mut instance_row: Vec<Fp> = Vec::new();

    for byte in &message_bytes {
        instance_row.push(Fp::from(*byte as u64));
    }

    for word in &digest_words {
        instance_row.push(Fp::from(*word as u64));
    }

    let instances: &[&[&[Fp]]] = &[&[&instance_row[..]]];

    println!("Public inputs/outputs:");
    println!("  Input bytes: {} elements", message_bytes.len());
    println!("  Output digest: 8 words (32 bytes)\n");

    let circuit = Sha256Circuit {
        input: message_bytes.clone(),
    };

    println!("Generating verification key...");
    let empty = Sha256Circuit { input: vec![] };
    let vk = keygen_vk(&params, &empty).unwrap();
    println!("✓ Verification key generated");

    println!("Generating proving key...");
    let pk = keygen_pk(&params, vk.clone(), &empty).unwrap();
    println!("✓ Proving key generated\n");

    println!("Creating proof...");
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(&params, &pk, &[circuit], instances, OsRng, &mut transcript).unwrap();
    let proof = transcript.finalize();
    println!("✓ Proof created ({} bytes)\n", proof.len());

    std::fs::write("proof.bin", &proof).unwrap();

    std::fs::write("input.txt", &message_bytes).unwrap();

    let mut digest_bytes = Vec::new();
    for word in &digest_words {
        digest_bytes.extend_from_slice(&word.to_be_bytes());
    }
    std::fs::write("digest.bin", &digest_bytes).unwrap();

    println!("✓ Saved proof.bin, input.txt, and digest.bin\n");

    println!("=== Verification ===\n");

    let proof = std::fs::read("proof.bin").unwrap();
    let input_bytes = std::fs::read("input.txt").unwrap();
    let digest_bytes = std::fs::read("digest.bin").unwrap();

    let mut digest_words_loaded = [0u32; 8];
    for i in 0..8 {
        let b = 4 * i;
        digest_words_loaded[i] = u32::from_be_bytes([
            digest_bytes[b],
            digest_bytes[b + 1],
            digest_bytes[b + 2],
            digest_bytes[b + 3],
        ]);
    }

    println!("Loaded public inputs:");
    println!("  Input: \"{}\"", String::from_utf8_lossy(&input_bytes));
    print!("  Digest: ");
    for word in &digest_words_loaded {
        for byte in &word.to_be_bytes() {
            print!("{:02x}", byte);
        }
    }
    println!("\n");

    let mut instance_row: Vec<Fp> = Vec::new();
    for byte in &input_bytes {
        instance_row.push(Fp::from(*byte as u64));
    }
    for word in &digest_words_loaded {
        instance_row.push(Fp::from(*word as u64));
    }
    let instances: &[&[&[Fp]]] = &[&[&instance_row[..]]];
    let empty = Sha256Circuit { input: vec![] };
    let vk = keygen_vk(&params, &empty).unwrap();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let res = verify_proof(
        &params,
        &vk,
        halo2_proofs::plonk::SingleVerifier::new(&params),
        instances,
        &mut transcript,
    );
    println!("{:?}", res);

    match res {
        Ok(_) => println!("✓ Verification PASSED - Proof is valid!"),
        Err(e) => println!("✗ Verification FAILED: {:?}", e),
    }
}
