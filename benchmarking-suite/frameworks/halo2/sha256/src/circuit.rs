use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value, AssignedCell},
    pasta::Fp,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Instance,
    },
};
use halo2_gadgets::sha256::{Table16Chip, Table16Config, BlockWord, Sha256Instructions};

#[derive(Clone)]
pub struct Sha256Config {
    pub table: Table16Config,
    pub digest_advice: Column<Advice>,   // advice to temporarily hold digest
    pub instance: Column<Instance>,      // public digest words
}

#[derive(Clone)]
pub struct Sha256Circuit {
    pub input: Vec<u8>,   // PUBLIC input bytes
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

        let digest_advice = meta.advice_column();
        meta.enable_equality(digest_advice);

        let table = Table16Chip::configure(meta);

        Sha256Config {
            table,
            instance,
            digest_advice,
        }
    }

    fn synthesize(
        &self,
        config: Sha256Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = Table16Chip::construct(config.table.clone());
        Table16Chip::load(config.table.clone(), &mut layouter)?;

        // -------------------------
        //      1. PAD MESSAGE
        // -------------------------
        let padded = sha256_pad(&self.input);

        // -------------------------
        //      2. SPLIT INTO BLOCKS
        // -------------------------
        let mut blocks = vec![];
        for chunk in padded.chunks(64) {
            let mut w = [0u32; 16];
            for i in 0..16 {
                let b = 4 * i;
                w[i] = u32::from_be_bytes([
                    chunk[b],
                    chunk[b + 1],
                    chunk[b + 2],
                    chunk[b + 3],
                ]);
            }
            blocks.push(w);
        }

        // -------------------------
        //      3. SHA-256 HASH
        // -------------------------
        let state0 = chip.initialization_vector(&mut layouter.namespace(|| "iv"))?;
        let mut state = state0;

        for (i, block) in blocks.iter().enumerate() {
            let br: [BlockWord; 16] = block.map(|w| BlockWord(Value::known(w)));
            state = chip.compress(&mut layouter.namespace(|| format!("compress {}", i)), &state, br)?;
        }

        let digest = chip.digest(&mut layouter.namespace(|| "digest"), &state)?;

        // -------------------------
        //    4. EXPOSE DIGEST
        // -------------------------
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

        for i in 0..8 {
            layouter.constrain_instance(digest_cells[i].cell(), config.instance, i)?;
        }

        Ok(())
    }
}


// ------------------------------------------------------
// SHA-256 Padding identical to RFC 6234
// ------------------------------------------------------
fn sha256_pad(msg: &[u8]) -> Vec<u8> {
    let mut out = msg.to_vec();

    // append 1 bit
    out.push(0x80);

    // pad with zeros until len ≡ 56 mod 64
    while (out.len() % 64) != 56 {
        out.push(0x00);
    }

    // append 64-bit length
    let bit_len = (msg.len() as u64) * 8;
    out.extend_from_slice(&bit_len.to_be_bytes());

    out
}
