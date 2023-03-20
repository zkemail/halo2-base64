// use halo2::halo2curves::bn256::G1Affine;
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use halo2_base::halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Assigned, Circuit, Column, ConstraintSystem, Constraints, Error, Expression,
        Instance, Selector,
    },
    poly::Rotation,
};
use halo2_base::utils::PrimeField;
use std::{marker::PhantomData, vec};

use crate::table::BitDecompositionTableConfig;

// Checks a regex of string len
const SHAHASH_BASE64_STRING_LEN: usize = 44;
const BIT_DECOMPOSITION_ADVICE_COL_COUNT: usize = 12;

// Here we decompose a transition into 3-value lookups.

#[derive(Debug, Clone)]
struct Base64Config<F: PrimeField> {
    encoded_chars: Column<Advice>, // This is the raw ASCII character value -- like 'a' would be 97
    bit_decompositions: [Column<Advice>; BIT_DECOMPOSITION_ADVICE_COL_COUNT],
    decoded_chars: Column<Advice>, // This has a 1 char gap between each group of 3 chars
    decoded_chars_without_gap: Column<Advice>,
    bit_decomposition_table: BitDecompositionTableConfig<F>,
    q_decode_selector: Selector,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Base64Config<F> {
    #[inline]
    pub fn create_bit_lookup(
        &self,
        meta: &mut ConstraintSystem<F>,
        encoded_or_decoded_index_offset: usize,
        encoded_if_true_and_decoded_if_false: bool,
        bit_query_cols: Vec<usize>,
        bit_lookup_cols: Vec<usize>,
        selector_col: Selector,
    ) -> Option<bool> {
        meta.lookup("lookup base64 encode/decode", |meta| {
            assert!(bit_query_cols.len() == bit_lookup_cols.len());
            let q = meta.query_selector(selector_col);

            // One minus q defaults to the 'a' value and '0' bit values
            let one_minus_q = Expression::Constant(F::from(1)) - q.clone();
            let zero = Expression::Constant(F::from(0));
            let zero_char = Expression::Constant(F::from(65));

            let mut lookup_vec = vec![];
            if encoded_if_true_and_decoded_if_false {
                let encoded_char = meta.query_advice(
                    self.encoded_chars,
                    Rotation(encoded_or_decoded_index_offset as i32),
                );
                lookup_vec.push((
                    q.clone() * encoded_char + one_minus_q.clone() * zero_char.clone(),
                    self.bit_decomposition_table.character,
                ));
            } else {
                let decoded_char = meta.query_advice(
                    self.decoded_chars,
                    Rotation(encoded_or_decoded_index_offset as i32),
                );
                println!("decoded_char: {:?}", decoded_char);
                lookup_vec.push((
                    q.clone() * decoded_char + one_minus_q.clone() * zero.clone(),
                    self.bit_decomposition_table.value_decoded,
                ));
            }
            for i in 0..bit_query_cols.len() {
                let bit =
                    meta.query_advice(self.bit_decompositions[bit_query_cols[i]], Rotation::cur());
                println!("bit: {:?}", bit);
                lookup_vec.push((
                    q.clone() * bit + one_minus_q.clone() * zero.clone(),
                    self.bit_decomposition_table.bit_decompositions[bit_lookup_cols[i]],
                ));
            }
            lookup_vec
        });
        None
    }

    pub fn configure(meta: &mut ConstraintSystem<F>, encoded_chars: Column<Advice>) -> Self {
        let mut bit_decompositions = vec![];
        for _ in 0..BIT_DECOMPOSITION_ADVICE_COL_COUNT {
            bit_decompositions.push(meta.advice_column());
        }
        let decoded_chars = meta.advice_column();
        // let characters = meta.advice_column();
        let decoded_chars_without_gap = meta.advice_column();
        let bit_decomposition_table = BitDecompositionTableConfig::configure(meta);
        let q_decode_selector = meta.complex_selector();

        meta.enable_equality(decoded_chars);
        meta.enable_equality(decoded_chars_without_gap);

        // Create bit lookup for each bit
        const ENCODED_LOOKUP_COLS: [usize; 4] = [0, 1, 2, 3];
        const ENCODED_BIT_LOOKUP_COLS: [[usize; 3]; 4] =
            [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9, 10, 11]];
        const DECODED_LOOKUP_COLS: [usize; 3] = [0, 1, 2];
        const DECODED_BIT_LOOKUP_COLS: [[usize; 4]; 3] =
            [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11]];

        let config = Self {
            encoded_chars,
            bit_decompositions: bit_decompositions.try_into().unwrap(),
            decoded_chars,
            decoded_chars_without_gap,
            bit_decomposition_table,
            q_decode_selector,
            _marker: PhantomData,
        };
        // Create bit lookup for each 6-bit encoded value
        for i in 0..ENCODED_LOOKUP_COLS.len() {
            config.create_bit_lookup(
                meta,
                i,
                true,
                ENCODED_BIT_LOOKUP_COLS[i].to_vec(),
                [2, 1, 0].to_vec(),
                config.q_decode_selector,
            );
        }
        // Create bit lookup for each 8-bit decoded value
        for i in 0..DECODED_LOOKUP_COLS.len() {
            config.create_bit_lookup(
                meta,
                i,
                false,
                DECODED_BIT_LOOKUP_COLS[i].to_vec(),
                [3, 2, 1, 0].to_vec(),
                config.q_decode_selector,
            );
        }
        config
    }

    // Note that the two types of region.assign_advice calls happen together so that it is the same region
    pub fn assign_values(
        &self,
        mut layouter: impl Layouter<F>,
        characters: &[u8],
    ) -> Result<bool, Error> {
        layouter.assign_region(
            || "Assign values",
            |mut region| {
                // Set the decoded values and enable permutation checks with offset
                let decoded_chars: Vec<u8> =
                    general_purpose::STANDARD
                        .decode(characters)
                        .expect(&format!(
                            "{:?} is an invalid base64 string bytes",
                            characters
                        ));
                for i in 0..decoded_chars.len() {
                    let offset_value = region.assign_advice(
                        || format!("decoded character"),
                        self.decoded_chars_without_gap,
                        i,
                        || Value::known(F::from_u128(decoded_chars[i].into())),
                    )?;
                    offset_value.copy_advice(
                        || "copying to add offset",
                        &mut region,
                        self.decoded_chars,
                        i + (i / 3),
                    )?;
                }

                // Set the character values as encoded chars
                for i in 0..SHAHASH_BASE64_STRING_LEN {
                    let bit_val: u8 = self
                        .bit_decomposition_table
                        .map_character_to_encoded_value(characters[i] as char);
                    region.assign_advice(
                        || format!("encoded character"),
                        self.encoded_chars,
                        i,
                        || Value::known(F::from(characters[i] as u64)),
                    )?;

                    // Set bit values by decomposing the encoded character
                    for j in 0..3 {
                        region.assign_advice(
                            || format!("bit assignment"),
                            self.bit_decompositions[(i % 4) * 3 + j],
                            i - (i % 4),
                            || Value::known(F::from_u128(((bit_val >> ((2 - j) * 2)) % 4) as u128)),
                        )?;
                    }
                }

                // Enable q_decomposed on every 4 rows
                for i in (0..SHAHASH_BASE64_STRING_LEN).step_by(4) {
                    self.q_decode_selector.enable(&mut region, i)?;
                }
                Ok(true)
            },
        )
    }
}
#[derive(Default, Clone)]
struct Base64Circuit<F: PrimeField> {
    // Since this is only relevant for the witness, we can opt to make this whatever convenient type we want
    pub base64_encoded_string: Vec<u8>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Circuit<F> for Base64Circuit<F> {
    type Config = Base64Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    // Circuit without witnesses, called only during key generation
    fn without_witnesses(&self) -> Self {
        Self {
            base64_encoded_string: vec![],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let encoded_chars = meta.advice_column();
        // TODO Set an offset to encoded_chars
        let config = Base64Config::configure(meta, encoded_chars);
        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        println!("Assigning table in synthesize...");
        match config.bit_decomposition_table.load(&mut layouter) {
            Ok(_) => (),
            Err(e) => {
                println!("Error loading bit decomposition table: {:?}", e);
                return Err(e);
            }
        };
        let mut value = config.assign_values(
            layouter.namespace(|| "Assign all values"),
            &self.base64_encoded_string,
        );
        println!("Done assigning values in synthesize");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_base::halo2_proofs::{
        circuit::floor_planner::V1,
        dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::{Fr, G1},
        plonk::{Any, Circuit},
    };

    use super::*;

    // TODO: set an offset in the email for the bh= and see what happens
    #[test]
    fn test_base64_decode_pass() {
        let k = 9; // 8, 128, etc

        // Convert query string to u128s
        // "R0g=""
        let characters: Vec<u8> = "GIu+hBcWsHGJVbzDqPH7VmmZIfFz1v6pHMZxqV3dR0g="
            .chars()
            .map(|c| c as u32 as u8)
            .collect();

        // Make a vector of the numbers 1...24
        assert_eq!(characters.len(), SHAHASH_BASE64_STRING_LEN);
        #[allow(deprecated)]
        let chars: Vec<char> = base64::decode(characters.clone())
            .unwrap()
            .iter()
            .map(|&b| b as char)
            .collect();
        print!("Decoded chars: {:?}", chars);
        // Successful cases
        let circuit = Base64Circuit::<Fr> {
            base64_encoded_string: characters,
            _marker: PhantomData,
        };

        let prover = match MockProver::run(k, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("Error: {:?}", e),
        };
        prover.assert_satisfied();
        CircuitCost::<G1, Base64Circuit<Fr>>::measure((k as u128).try_into().unwrap(), &circuit);
        // .proof_size(2);

        // Assert the 33rd pos is 0
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

    // $ cargo test --release --all-features print_circuit_1
    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_circuit_1() {
        use plotters::prelude::*;

        let root =
            BitMapBackend::new("base64-circuit-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Base64 Circuit Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = Base64Circuit::<Fp> {
            base64_encoded_string: vec![97, 98, 99, 100] as u128,
            _marker: PhantomData,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(3, &circuit, &root)
            .unwrap();
    }
}
