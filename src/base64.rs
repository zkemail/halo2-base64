// use halo2::halo2curves::bn256::G1Affine;
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
        plonk::{
            Advice, Assigned, Circuit, Column, ConstraintSystem, Constraints, Error, Expression,
            Instance, Selector,
        },
        poly::Rotation,
    },
    AssignedValue, QuantumCell,
};
use halo2_base::{utils::PrimeField, Context};
use std::{marker::PhantomData, vec};

use crate::table::{map_bits_value_to_character, Base64Table, DUMMY_BITS_VAL, DUMMY_CHAR};
// use snark_verifier_sdk::CircuitExt;

// Checks a regex of string len
const SHAHASH_BASE64_STRING_LEN: usize = 44;
const BIT_DECOMPOSITION_ADVICE_COL_COUNT: usize = 12;

// #[derive(Debug, Clone)]
// pub struct AssignedBase64Result<'a, F: PrimeField> {
//     pub encoded: Vec<AssignedValue<'a, F>>,
//     pub decoded: Vec<AssignedValue<'a, F>>,
// }

// Here we decompose a transition into 3-value lookups.
#[derive(Debug, Clone)]
pub struct Base64Config<F: PrimeField> {
    encoded_byte_size: usize,
    decoded_byte_size: usize,
    num_zero_paddings: usize,
    num_equal_paddings: usize,
    encoded_chars: Column<Advice>, // This is the raw ASCII character value -- like 'a' would be 97
    // bit_decompositions: [Column<Advice>; BIT_DECOMPOSITION_ADVICE_COL_COUNT],
    // decoded_chars: Column<Advice>, // This has a 1 char gap between each group of 3 chars
    // decoded_chars_without_gap: Column<Advice>,
    // bit_decomposition_table: BitDecompositionTableConfig<F>,
    bits_vals: Column<Advice>,
    table: Base64Table<F>,
    sel: Selector,
}

impl<F: PrimeField> Base64Config<F> {
    // #[inline]
    // pub fn create_bit_lookup(
    //     &self,
    //     meta: &mut ConstraintSystem<F>,
    //     encoded_or_decoded_index_offset: usize,
    //     encoded_if_true_and_decoded_if_false: bool,
    //     bit_query_cols: Vec<usize>,
    //     bit_lookup_cols: Vec<usize>,
    //     selector_col: Selector,
    // ) -> Option<bool> {
    //     meta.lookup("lookup base64 encode/decode", |meta| {
    //         assert!(bit_query_cols.len() == bit_lookup_cols.len());
    //         let q = meta.query_selector(selector_col);

    //         // One minus q defaults to the 'a' value and '0' bit values
    //         let one_minus_q = Expression::Constant(F::from(1)) - q.clone();
    //         let zero = Expression::Constant(F::from(0));
    //         let zero_char = Expression::Constant(F::from(65));

    //         let mut lookup_vec = vec![];
    //         if encoded_if_true_and_decoded_if_false {
    //             let encoded_char = meta.query_advice(
    //                 self.encoded_chars,
    //                 Rotation(encoded_or_decoded_index_offset as i32),
    //             );
    //             lookup_vec.push((
    //                 q.clone() * encoded_char + one_minus_q.clone() * zero_char.clone(),
    //                 self.bit_decomposition_table.character,
    //             ));
    //         } else {
    //             let decoded_char = meta.query_advice(
    //                 self.decoded_chars,
    //                 Rotation(encoded_or_decoded_index_offset as i32),
    //             );
    //             // println!("decoded_char: {:?}", decoded_char);
    //             lookup_vec.push((
    //                 q.clone() * decoded_char + one_minus_q.clone() * zero.clone(),
    //                 self.bit_decomposition_table.value_decoded,
    //             ));
    //         }
    //         for i in 0..bit_query_cols.len() {
    //             let bit =
    //                 meta.query_advice(self.bit_decompositions[bit_query_cols[i]], Rotation::cur());
    //             // println!("bit: {:?}", bit);
    //             lookup_vec.push((
    //                 q.clone() * bit + one_minus_q.clone() * zero.clone(),
    //                 self.bit_decomposition_table.bit_decompositions[bit_lookup_cols[i]],
    //             ));
    //         }
    //         lookup_vec
    //     });
    //     None
    // }

    pub fn configure(meta: &mut ConstraintSystem<F>, decoded_byte_size: usize) -> Self {
        let encoded_chars = meta.advice_column();
        let bits_vals = meta.advice_column();
        meta.enable_equality(encoded_chars);
        meta.enable_equality(bits_vals);
        let sel = meta.complex_selector();
        let table = Base64Table::configure(meta);
        meta.lookup("lookup base64 encode/decode", |meta| {
            let q = meta.query_selector(sel);
            let one_minus_q = Expression::Constant(F::from(1)) - q.clone();
            let dummy_char = Expression::Constant(F::from(DUMMY_CHAR));
            let dummy_bits_val = Expression::Constant(F::from(DUMMY_BITS_VAL));
            let mut lookup_vec = vec![];
            let encoded_char = meta.query_advice(encoded_chars, Rotation::cur());
            lookup_vec.push((
                q.clone() * encoded_char + one_minus_q.clone() * dummy_char.clone(),
                table.character,
            ));
            let bits_val = meta.query_advice(bits_vals, Rotation::cur());
            lookup_vec.push((
                q.clone() * bits_val + one_minus_q.clone() * dummy_bits_val.clone(),
                table.bits_value,
            ));
            lookup_vec
        });

        let num_6bits_chunks = ((8 * decoded_byte_size) as f32 / 6.0).ceil() as usize;
        let num_zero_paddings = 6 * num_6bits_chunks - 8 * decoded_byte_size;
        let encoded_byte_size = 4 * (num_6bits_chunks as f32 / 4.0).ceil() as usize;
        debug_assert_eq!(4 * ((decoded_byte_size + 2) / 3), encoded_byte_size);
        let num_equal_paddings = encoded_byte_size - num_6bits_chunks;
        Self {
            encoded_byte_size,
            decoded_byte_size,
            num_zero_paddings,
            num_equal_paddings,
            encoded_chars,
            bits_vals,
            table,
            sel,
        }
    }

    pub fn encode<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'b, F>,
        gate: &FlexGateConfig<F>,
        assigned_decode_bytes: &[AssignedValue<'a, F>],
    ) -> Result<Vec<AssignedValue<'a, F>>, Error> {
        let mut assigned_decode_bytes = assigned_decode_bytes
            .into_iter()
            .flat_map(|assigned_v| {
                let mut bits = gate.num_to_bits(ctx, assigned_v, 8);
                bits.reverse();
                bits
            })
            .collect::<Vec<AssignedValue<F>>>();
        let mut zero = gate.load_zero(ctx);
        for _ in 0..self.num_zero_paddings {
            assigned_decode_bytes.push(zero.clone());
        }
        debug_assert_eq!(assigned_decode_bytes.len() % 6, 0);
        let mut assigned_encoded = vec![];
        for (idx, assigned_bits) in assigned_decode_bytes.chunks(6).enumerate() {
            let coeffs = vec![
                F::from(32),
                F::from(16),
                F::from(8),
                F::from(4),
                F::from(2),
                F::from(1),
            ]
            .into_iter()
            .map(|v| QuantumCell::Constant(v))
            .collect::<Vec<QuantumCell<F>>>();
            let composed = gate.inner_product(
                ctx,
                assigned_bits
                    .into_iter()
                    .map(|b| QuantumCell::Existing(b))
                    .collect::<Vec<QuantumCell<F>>>(),
                coeffs,
            );
            let encoded_char_val = composed
                .value()
                .map(|bits_val| map_bits_value_to_character(bits_val.get_lower_32() as u8))
                .map(|char| F::from(char as u64));
            let assigned_bits_val = ctx.region.assign_advice(
                || "assign bits val",
                self.bits_vals,
                idx,
                || composed.value().map(|v| *v),
            )?;
            ctx.region
                .constrain_equal(composed.cell(), assigned_bits_val.cell())?;
            let assigned_encoded_char = ctx.region.assign_advice(
                || "assign encoded char",
                self.encoded_chars,
                idx,
                || encoded_char_val,
            )?;
            let assigned_encoded_char_val =
                gate.load_witness(ctx, assigned_encoded_char.value().map(|v| *v));
            ctx.region.constrain_equal(
                assigned_encoded_char.cell(),
                assigned_encoded_char_val.cell(),
            )?;
            assigned_encoded.push(assigned_encoded_char_val);
            self.sel.enable(&mut ctx.region, idx)?;
        }
        let equal_char = gate.load_constant(ctx, F::from('=' as u64));
        for _ in 0..self.num_equal_paddings {
            assigned_encoded.push(equal_char.clone());
        }
        debug_assert_eq!(assigned_encoded.len(), self.encoded_byte_size);
        Ok(assigned_encoded)
        // let mut encoded =
        //     assigned_decode_bytes
        //         .chunks(6)
        //         .enumerate()
        //         .map(|(idx, assigned_bits)| {
        //             let coeffs = vec![
        //                 F::from(32),
        //                 F::from(16),
        //                 F::from(8),
        //                 F::from(4),
        //                 F::from(2),
        //                 F::from(1),
        //             ]
        //             .into_iter()
        //             .map(|v| QuantumCell::Constant(v))
        //             .collect();
        //             let composed = gate.inner_product(
        //                 ctx,
        //                 assigned_bits
        //                     .into_iter()
        //                     .map(|b| QuantumCell::Existing(b))
        //                     .collect(),
        //                 coeffs,
        //             );
        //             let encoded_char_val = composed
        //                 .value()
        //                 .map(|bits_val| map_bits_value_to_character(bits_val.get_lower_32() as u8))
        //                 .map(|char| F::from(char as u64));
        //             let assigned_bits_val = ctx.region.assign_advice(
        //                 || "assign bits val",
        //                 self.bits_vals,
        //                 idx,
        //                 || encoded_char_val.ok_or(Error::SynthesisError),
        //             )?;
        //         });

        // let mut assigned_encoded_values = Vec::new();
        // let mut assigned_decoded_values = Vec::new();

        // // Set the decoded values and enable permutation checks with offset
        // let decoded_chars: Vec<u8> = general_purpose::STANDARD
        //     .decode(characters)
        //     .expect(&format!(
        //         "{:?} is an invalid base64 string bytes",
        //         characters
        //     ));
        // for i in 0..decoded_chars.len() {
        //     let offset_value = region.assign_advice(
        //         || format!("decoded character"),
        //         self.decoded_chars_without_gap,
        //         i,
        //         || Value::known(F::from_u128(decoded_chars[i].into())),
        //     )?;
        //     offset_value.copy_advice(
        //         || "copying to add offset",
        //         region,
        //         self.decoded_chars,
        //         i + (i / 3),
        //     )?;
        //     assigned_decoded_values.push(offset_value);
        // }

        // // Set the character values as encoded chars
        // for i in 0..SHAHASH_BASE64_STRING_LEN {
        //     let bit_val: u8 = self
        //         .bit_decomposition_table
        //         .map_character_to_encoded_value(characters[i] as char);
        //     let assigned_encoded = region.assign_advice(
        //         || format!("encoded character"),
        //         self.encoded_chars,
        //         i,
        //         || Value::known(F::from(characters[i] as u64)),
        //     )?;
        //     assigned_encoded_values.push(assigned_encoded);

        //     // Set bit values by decomposing the encoded character
        //     for j in 0..3 {
        //         region.assign_advice(
        //             || format!("bit assignment"),
        //             self.bit_decompositions[(i % 4) * 3 + j],
        //             i - (i % 4),
        //             || Value::known(F::from_u128(((bit_val >> ((2 - j) * 2)) % 4) as u128)),
        //         )?;
        //     }
        // }

        // // Enable q_decomposed on every 4 rows
        // for i in (0..SHAHASH_BASE64_STRING_LEN).step_by(4) {
        //     self.q_decode_selector.enable(region, i)?;
        // }
        // let result = AssignedBase64Result {
        //     encoded: assigned_encoded_values,
        //     decoded: assigned_decoded_values,
        // };
        // Ok(result)
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.table.load(layouter)
    }
}

#[cfg(test)]
mod tests {
    use halo2_base::{
        halo2_proofs::{
            circuit::floor_planner::V1,
            dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
            halo2curves::bn256::{Fr, G1},
            plonk::{Any, Circuit},
        },
        ContextParams, SKIP_FIRST_PASS,
    };

    use super::*;
    use hex;

    const K: usize = 12;
    const DECODED_BYTE_SIZE: usize = 32;

    #[derive(Debug, Clone)]
    pub struct Base64TestConfig<F: PrimeField> {
        pub inner: Base64Config<F>,
        pub gate: FlexGateConfig<F>,
        pub instances: Column<Instance>,
    }

    #[derive(Debug, Default, Clone)]
    pub struct Base64TestCircuit<F: PrimeField> {
        pub decoded_bytes: Vec<u8>,
        _marker: PhantomData<F>,
    }

    impl<F: PrimeField> Circuit<F> for Base64TestCircuit<F> {
        type Config = Base64TestConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        // Circuit without witnesses, called only during key generation
        fn without_witnesses(&self) -> Self {
            Self {
                decoded_bytes: vec![],
                _marker: PhantomData,
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            // let encoded_chars = meta.advice_column();
            // TODO Set an offset to encoded_chars
            let inner = Base64Config::configure(meta, DECODED_BYTE_SIZE);
            let gate = FlexGateConfig::configure(
                meta,
                halo2_base::gates::flex_gate::GateStrategy::Vertical,
                &[1],
                1,
                0,
                K,
            );
            let instances = meta.instance_column();
            meta.enable_equality(instances);
            Self::Config {
                inner,
                gate,
                instances,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // println!("Assigning table in synthesize...");
            config.inner.load(&mut layouter)?;
            let mut first_pass = SKIP_FIRST_PASS;
            let mut public_cells = vec![];
            layouter.assign_region(
                || "base64 test",
                |mut region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let ctx = &mut {
                        Context::new(
                            region,
                            ContextParams {
                                max_rows: config.gate.max_rows,
                                num_context_ids: 1,
                                fixed_columns: config.gate.constants.clone(),
                            },
                        )
                    };
                    let assigned_inputs = self
                        .decoded_bytes
                        .iter()
                        .map(|byte| {
                            config
                                .gate
                                .load_witness(ctx, Value::known(F::from(*byte as u64)))
                        })
                        .collect::<Vec<_>>();
                    let assigned_encoded_chars =
                        config.inner.encode(ctx, &config.gate, &assigned_inputs)?;
                    public_cells = assigned_encoded_chars
                        .iter()
                        .map(|v| v.cell())
                        .collect::<Vec<_>>();
                    Ok(())
                },
            )?;
            for (idx, cell) in public_cells.into_iter().enumerate() {
                layouter.constrain_instance(cell, config.instances, idx)?;
            }
            // println!("Done assigning values in synthesize");
            Ok(())
        }
    }

    #[test]
    fn test_base64_decode_pass() {
        // Convert query string to u128s
        // "R0g=""
        let circuit = Base64TestCircuit {
            decoded_bytes: hex::decode(
                "188bbe841716b0718955bcc3a8f1fb56699921f173d6fea91cc671a95ddd4748",
            )
            .unwrap(),
            _marker: PhantomData,
        };
        let expected_base64 = "GIu+hBcWsHGJVbzDqPH7VmmZIfFz1v6pHMZxqV3dR0g=";
        let instances = expected_base64
            .as_bytes()
            .into_iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<_>>();

        let prover = match MockProver::run(K as u32, &circuit, vec![instances]) {
            Ok(prover) => prover,
            Err(e) => panic!("Error: {:?}", e),
        };
        prover.assert_satisfied();
        CircuitCost::<G1, Base64TestCircuit<Fr>>::measure(K, &circuit);
    }

    #[test]
    fn test_base64_decode_fail() {
        // Convert query string to u128s
        // "R0g=""
        let circuit = Base64TestCircuit {
            decoded_bytes: hex::decode(
                "188bbe841716b0718955bcc3a8f1fb56699921f173d6fea91cc671a95ddd4748",
            )
            .unwrap(),
            _marker: PhantomData,
        };
        let expected_base64 = "GIu+hBcWsHGJVbzDqPH7VmmZIfFz1v6pHMZxqV3dR0a=";
        let instances = expected_base64
            .as_bytes()
            .into_iter()
            .map(|byte| Fr::from(*byte as u64))
            .collect::<Vec<_>>();

        let prover = MockProver::run(K as u32, &circuit, vec![instances]).unwrap();
        match prover.verify() {
            Ok(_) => panic!("this test must fail!"),
            Err(e) => println!("returned error {:?}", e),
        };
    }

    // #[test]
    // fn test_base64_decode_fail() {
    //     let k = 10;

    //     // Convert query string to u128s
    //     let characters: Vec<u128> = "charcount+not+div+by+4"
    //         .chars()
    //         .map(|c| c as u32 as u128)
    //         .collect();

    //     assert_eq!(characters.len(), SHAHASH_BASE64_STRING_LEN);

    //     // Out-of-range `value = 8`
    //     let circuit = Base64Circuit::<Fp> {
    //         characters: characters,
    //         _marker: PhantomData,
    //     };
    //     let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    //     match prover.verify() {
    //         Err(e) => {
    //             println!("Error successfully achieved!");
    //         }
    //         _ => assert_eq!(1, 0),
    //     }
    // }
}
