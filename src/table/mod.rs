use halo2_base::halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, TableColumn},
};
use halo2_base::utils::PrimeField;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::marker::PhantomData;
use std::str::FromStr;

// pub const BIT_COLUMN_COUNT: u8 = 4;

pub const DUMMY_CHAR: u64 = 256;
pub const DUMMY_BITS_VAL: u64 = 64;

/// A lookup table of values from 0..RANGE.
#[derive(Debug, Clone)]
pub(super) struct Base64Table<F: PrimeField> {
    pub(super) character: TableColumn, // This is the pre-mapped 6 bit character in ASCII (i.e. a-z, A-Z, 0-9, +, /)
    pub(super) bits_value: TableColumn, // This is the 6 bit value that each of the above character maps to from 0-64
    // pub(super) value_decoded: TableColumn, // This is the 8 bit value that you get after decoding the base64 values
    // pub(super) bit_decompositions: [TableColumn; BIT_COLUMN_COUNT as usize],
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Base64Table<F> {
    pub(super) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let character = meta.lookup_table_column();
        let bits_value = meta.lookup_table_column();
        // let value_decoded = meta.lookup_table_column();
        // let mut bit_decompositions = vec![];
        // for i in 0..BIT_COLUMN_COUNT {
        //     bit_decompositions.push(meta.lookup_table_column());
        // }

        Self {
            character,
            bits_value,
            // value_encoded,
            // value_decoded,
            // bit_decompositions: bit_decompositions.try_into().unwrap(),
            _marker: PhantomData,
        }
    }

    // pub(super) fn map_character_to_encoded_value(&self, character: char) -> u8 {
    //     match character {
    //         '=' => 0,
    //         'A'..='Z' => character as u8 - 65,
    //         'a'..='z' => character as u8 - 71,
    //         '0'..='9' => character as u8 + 4,
    //         '+' => 62,
    //         '/' => 63,
    //         _ => panic!("Invalid character"),
    //     }
    // }

    pub(super) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        const OFFSET: usize = 1; // How many dummy characters we add into rows at the top

        layouter.assign_table(
            || "load 64 bit table",
            |mut table| {
                // Assign dummy ASCII characters and corresponding value_encoded values
                table.assign_cell(
                    || "dummy bits_value",
                    self.bits_value,
                    0,
                    || Value::known(F::from(DUMMY_BITS_VAL)),
                )?;
                table.assign_cell(
                    || "dummy character",
                    self.character,
                    0,
                    || Value::known(F::from(DUMMY_CHAR)),
                )?;

                for v in 0..64 {
                    table.assign_cell(
                        || "bits_value",
                        self.bits_value,
                        v + OFFSET,
                        || Value::known(F::from(v as u64)),
                    )?;
                    // Assign each character value that corresponds to its base64 encoded value
                    let char = map_bits_value_to_character(v as u8);
                    table.assign_cell(
                        || "character",
                        self.character,
                        v + OFFSET,
                        || Value::known(F::from(char as u64)),
                    )?;
                }

                Ok(())
            },
        )?;
        Ok(())
        // layouter.assign_table(
        //     || "load 256 bit table",
        //     |mut table| {
        //         // Special case = to be 0 at the top row
        //         for col in 0..BIT_COLUMN_COUNT {
        //             table.assign_cell(
        //                 || "bit decompositions",
        //                 self.bit_decompositions[col as usize],
        //                 0,
        //                 || Value::known(F::from_u128(((0 >> (col * 2)) % 4) as u128)),
        //             )?;
        //         }

        //         table.assign_cell(
        //             || "value_decoded",
        //             self.value_decoded,
        //             0,
        //             || Value::known(F::from_u128(0 as u128)),
        //         )?;

        //         // Assign bit decompositions for each value_encoded and value_decoded value
        //         for i in 0..256 {
        //             for col in 0..BIT_COLUMN_COUNT {
        //                 table.assign_cell(
        //                     || "bit decompositions",
        //                     self.bit_decompositions[col as usize],
        //                     i + OFFSET,
        //                     || Value::known(F::from_u128(((i >> (col * 2)) % 4) as u128)),
        //                 )?;
        //             }
        //             // Assign each value_decoded value
        //             table.assign_cell(
        //                 || "value_decoded",
        //                 self.value_decoded,
        //                 i + OFFSET,
        //                 || Value::known(F::from_u128(i as u128)),
        //             )?;
        //         }
        //         Ok(())
        //     },
        // )
    }
}

pub(super) fn map_bits_value_to_character(bits_val: u8) -> char {
    match bits_val {
        0..=25 => (bits_val + 65) as char,
        26..=51 => (bits_val + 71) as char,
        52..=61 => (bits_val - 4) as char,
        62 => '+',
        63 => '/',
        _ => panic!("Invalid value_encoded value"),
    }
}
