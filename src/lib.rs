//! This library provides a RSA verification circuit compatible with the [halo2 library developed by privacy-scaling-explorations team](https://github.com/privacy-scaling-explorations/halo2).
//!
//! A chip in this library, [`RSAConfig`], defines constraints for verifying the RSA relations, specifically modular power `x^e mod n` and [pkcs1v15 signature](https://www.rfc-editor.org/rfc/rfc3447) verification.
//! Its circuit configuration differs depending on whether the exponent parameter `e` of the RSA public key is variable or fixed.
//! For example, since `e` is often fixed to `65537` in the case of pkcs1v15 signature verification, defining `e` as a fixed parameter [`RSAPubE::Fix`] can optimize the number of constraints.
//!
//! In addition to [`RSAConfig`], this library also provides a high-level circuit implementation to verify pkcs1v15 signatures, [`RSASignatureVerifier`].  
//! The verification function in [`RSAConfig`] requires as input a hashed message, whereas the function in [`RSASignatureVerifier`] computes a SHA256 hash of the given message and verifies the given signature for that hash.
#![feature(trait_alias)]
#![feature(more_qualified_paths)]

use std::time::Instant;
pub mod big_uint;
pub use big_uint::*;
use rsa::RsaPrivateKey;
use std::marker::PhantomData;

use halo2_base::{
    halo2_proofs::{
        circuit::{Cell, Layouter, SimpleFloorPlanner, Value},
        plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
    },
    utils::ScalarField,
};

use halo2_base::{gates::range::RangeStrategy::Vertical, QuantumCell, SKIP_FIRST_PASS};
use halo2_base::{
    gates::{range::RangeConfig, GateInstructions},
    AssignedValue, Context,
};
use num_bigint::BigUint;

use rsa::{
    pkcs1v15::SigningKey,
    signature::{SignatureEncoding, Signer},
    traits::PublicKeyParts,
    RsaPublicKey,
};

use halo2curves::ff::PrimeField as Halo2CurvesPrimeField;

pub(crate) trait PrimeField = Halo2CurvesPrimeField + ScalarField;

mod qr_data_extractor;
//pub mod poseidon;
//mod aadhaar_verifier_circuit;
pub mod timestamp;
//pub mod nullifier;
pub mod conditional_secrets;
pub mod signal;

use crate::conditional_secrets::IdentityCircuit;
use crate::signal::SquareCircuit;
use crate::timestamp::TimestampCircuit;
use poseidon::Poseidon;

mod chip;
mod instructions;
pub use chip::*;
pub mod sha256;
pub use instructions::*;
use sha256::Sha256DynamicConfig;

/// A parameter `e` in the RSA public key that is about to be assigned.
#[derive(Clone, Debug)]
pub enum RSAPubE {
    /// A variable parameter `e`.
    Var(Value<BigUint>),
    /// A fixed parameter `e`.
    Fix(BigUint),
}

/// A parameter `e` in the assigned RSA public key.
#[derive(Clone, Debug)]
pub enum AssignedRSAPubE<'v, F: PrimeField> {
    /// A variable parameter `e`.
    Var(AssignedValue<F>),
    /// A fixed parameter `e`.
    Fix(BigUint),
}

/// RSA public key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct RSAPublicKey<F: PrimeField> {
    /// a modulus parameter
    pub n: Value<BigUint>,
    /// an exponent parameter
    pub e: RSAPubE,
    _f: PhantomData<F>,
}

impl<F: PrimeField> RSAPublicKey<F> {
    /// Creates new [`RSAPublicKey`] from `n` and `e`.
    ///
    /// # Arguments
    /// * n - an integer of `n`.
    /// * e - a parameter `e`.
    ///
    /// # Return values
    /// Returns new [`RSAPublicKey`].
    pub fn new(n: Value<BigUint>, e: RSAPubE) -> Self {
        Self {
            n,
            e,
            _f: PhantomData,
        }
    }

    pub fn without_witness(fix_e: BigUint) -> Self {
        let n = Value::unknown();
        let e = RSAPubE::Fix(fix_e);
        Self {
            n,
            e,
            _f: PhantomData,
        }
    }
}

/// An assigned RSA public key.
#[derive(Clone, Debug)]
pub struct AssignedRSAPublicKey<'v, F: PrimeField> {
    /// a modulus parameter
    pub n: AssignedBigUint<'v, F, Fresh>,
    /// an exponent parameter
    pub e: AssignedRSAPubE<'v, F>,
}

impl<'v, F: PrimeField> AssignedRSAPublicKey<'v, F> {
    /// Creates new [`AssignedRSAPublicKey`] from assigned `n` and `e`.
    ///
    /// # Arguments
    /// * n - an assigned integer of `n`.
    /// * e - an assigned parameter `e`.
    ///
    /// # Return values
    /// Returns new [`AssignedRSAPublicKey`].
    pub fn new(n: AssignedBigUint<'v, F, Fresh>, e: AssignedRSAPubE<'v, F>) -> Self {
        Self { n, e }
    }
}

/// RSA signature that is about to be assigned.
#[derive(Clone, Debug)]
pub struct RSASignature<F: PrimeField> {
    /// an integer of the signature.
    pub c: Value<BigUint>,
    _f: PhantomData<F>,
}

impl<F: PrimeField> RSASignature<F> {
    /// Creates new [`RSASignature`] from its integer.
    ///
    /// # Arguments
    /// * c - an integer of the signature.
    ///
    /// # Return values
    /// Returns new [`RSASignature`].
    pub fn new(c: Value<BigUint>) -> Self {
        Self { c, _f: PhantomData }
    }

    pub fn without_witness() -> Self {
        let c = Value::unknown();
        Self { c, _f: PhantomData }
    }
}

/// An assigned RSA signature.
#[derive(Clone, Debug)]
pub struct AssignedRSASignature<'v, F: PrimeField> {
    /// an integer of the signature.
    pub c: AssignedBigUint<'v, F, Fresh>,
}

impl<'v, F: PrimeField> AssignedRSASignature<'v, F> {
    /// Creates new [`AssignedRSASignature`] from its assigned integer.
    ///
    /// # Arguments
    /// * c - an assigned integer of the signature.
    ///
    /// # Return values
    /// Returns new [`AssignedRSASignature`].
    pub fn new(c: AssignedBigUint<'v, F, Fresh>) -> Self {
        Self { c }
    }
}

/// A circuit implementation to verify pkcs1v15 signatures.
#[derive(Clone, Debug)]
pub struct RSASignatureVerifier<F: PrimeField> {
    rsa_config: RSAConfig<F>,
    sha256_config: Sha256DynamicConfig<F>,
}

impl<F: PrimeField> RSASignatureVerifier<F> {
    /// Creates new [`RSASignatureVerifier`] from [`RSAChip`] and [`Sha256BitChip`].
    ///
    /// # Arguments
    /// * rsa_config - a [`RSAConfig`].
    /// * sha256_config - a [`Sha256DynamicConfig`]
    ///
    /// # Return values
    /// Returns new [`RSASignatureVerifier`].
    pub fn new(rsa_config: RSAConfig<F>, sha256_config: Sha256DynamicConfig<F>) -> Self {
        Self {
            rsa_config,
            sha256_config,
        }
    }

    /// Given a RSA public key, signed message bytes, and a pkcs1v15 signature, verifies the signature with SHA256 hash function.
    ///
    /// # Arguments
    /// * public_key - an assigned public key used for the verification.
    /// * msg - signed message bytes.
    /// * signature - a pkcs1v15 signature to be verified.
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `signature` is valid for `public_key` and `msg`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    pub fn verify_pkcs1v15_signature<'a, 'b: 'a>(
        &'a mut self,
        ctx: &mut Context<'b, F>,
        public_key: &AssignedRSAPublicKey<'b, F>,
        msg: &'a [u8],
        signature: &AssignedRSASignature<'b, F>,
    ) -> Result<(AssignedValue<'b, F>, Vec<AssignedValue<'b, F>>), Error> {
        let sha256 = &mut self.sha256_config;
        let rsa = self.rsa_config.clone();
        let biguint = &rsa.biguint_config();
        let result = sha256.digest(ctx, msg, None)?;
        let mut hashed_bytes = result.output_bytes;
        hashed_bytes.reverse();
        let bytes_bits = hashed_bytes.len() * 8;
        let limb_bits = biguint.limb_bits();
        let limb_bytes = limb_bits / 8;
        let mut hashed_u64s = vec![];
        let bases = (0..limb_bytes)
            .map(|i| F::from((1u64 << (8 * i)) as u64))
            .map(QuantumCell::Constant)
            .collect::<Vec<QuantumCell<F>>>();
        for i in 0..(bytes_bits / limb_bits) {
            let left = hashed_bytes[limb_bytes * i..limb_bytes * (i + 1)]
                .iter()
                .map(QuantumCell::Existing)
                .collect::<Vec<QuantumCell<F>>>();
            let sum = biguint.gate().inner_product(ctx, left, bases.clone());
            hashed_u64s.push(sum);
        }
        let is_sign_valid =
            rsa.verify_pkcs1v15_signature(ctx, public_key, &hashed_u64s, signature)?;

        hashed_bytes.reverse();
        Ok((is_sign_valid, hashed_bytes))
    }
}

#[derive(Debug, Clone)]
struct TestRSASignatureWithHashConfig1<F: PrimeField> {
    rsa_config: RSAConfig<F>,
    sha256_config: Sha256DynamicConfig<F>,
    n_instance: Column<Instance>,
    hash_instance: Column<Instance>,
}
#[derive(Debug, Clone)]
struct TestRSASignatureWithHashCircuit1<F: PrimeField> {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
    msg: Vec<u8>,
    _f: PhantomData<F>,
}

impl<F: PrimeField> TestRSASignatureWithHashCircuit1<F> {
    const BITS_LEN: usize = 2048;
    const MSG_LEN: usize = 1024;
    const EXP_LIMB_BITS: usize = 5;
    const DEFAULT_E: u128 = 65537;
    const NUM_ADVICE: usize = 80;
    const NUM_FIXED: usize = 1;
    const NUM_LOOKUP_ADVICE: usize = 16;
    const LOOKUP_BITS: usize = 12;
    const SHA256_LOOKUP_BITS: usize = 8;
    const SHA256_LOOKUP_ADVICE: usize = 8;
}

impl<F: PrimeField> TestRSASignatureWithHashCircuit1<F> {
    pub fn new(private_key: RsaPrivateKey, public_key: RsaPublicKey, msg: Vec<u8>) -> Self {
        Self {
            private_key,
            public_key,
            msg,
            _f: PhantomData,
        }
    }
}

impl<F: PrimeField> Circuit<F> for TestRSASignatureWithHashCircuit1<F> {
    type Params = ();
    type Config = TestRSASignatureWithHashConfig1<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let range_config = RangeConfig::configure(
            meta,
            Vertical,
            &[Self::NUM_ADVICE],
            &[Self::NUM_LOOKUP_ADVICE],
            Self::NUM_FIXED,
            Self::LOOKUP_BITS,
            0,
            15,
        );
        let bigint_config = BigUintConfig::construct(range_config.clone(), 64);
        let rsa_config = RSAConfig::construct(bigint_config, Self::BITS_LEN, Self::EXP_LIMB_BITS);
        let sha256_config = Sha256DynamicConfig::configure(
            meta,
            vec![Self::MSG_LEN],
            range_config,
            Self::SHA256_LOOKUP_BITS,
            Self::SHA256_LOOKUP_ADVICE,
            true,
        );
        let n_instance = meta.instance_column();
        let hash_instance = meta.instance_column();
        meta.enable_equality(n_instance);
        meta.enable_equality(hash_instance);
        Self::Config {
            rsa_config,
            sha256_config,
            n_instance,
            hash_instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let biguint_config = config.rsa_config.biguint_config();
        config.sha256_config.load(&mut layouter)?;
        biguint_config.range().load_lookup_table(&mut layouter)?;
        let mut first_pass = SKIP_FIRST_PASS;
        let (public_key_cells, hashed_msg_cells) = layouter.assign_region(
            || "random rsa modpow test with 2048 bits public keys",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok((vec![], vec![]));
                }

                let mut aux = biguint_config.new_context(region);
                let ctx = &mut aux;
                let signing_key = SigningKey::<rsa::sha2::Sha256>::new(self.private_key.clone());
                let sign = signing_key.sign(&self.msg).to_vec();
                let sign_big = BigUint::from_bytes_be(&sign);
                let sign = config
                    .rsa_config
                    .assign_signature(ctx, RSASignature::new(Value::known(sign_big)))?;
                let n_big =
                    BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
                        .unwrap();
                let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                let public_key = config
                    .rsa_config
                    .assign_public_key(ctx, RSAPublicKey::new(Value::known(n_big), e_fix))?;
                let mut verifier = RSASignatureVerifier::new(
                    config.rsa_config.clone(),
                    config.sha256_config.clone(),
                );
                let (is_valid, hashed_msg) =
                    verifier.verify_pkcs1v15_signature(ctx, &public_key, &self.msg, &sign)?;
                biguint_config
                    .gate()
                    .assert_is_const(ctx, &is_valid, F::one());
                biguint_config.range().finalize(ctx);
                {
                    println!("total advice cells: {}", ctx.total_advice);
                    let const_rows = ctx.total_fixed + 1;
                    println!("maximum rows used by a fixed column: {const_rows}");
                    println!("lookup cells used: {}", ctx.cells_to_lookup.len());
                }
                let public_key_cells = public_key
                    .n
                    .limbs()
                    .into_iter()
                    .map(|v| v.cell())
                    .collect::<Vec<Cell>>();
                let hashed_msg_cells = hashed_msg
                    .into_iter()
                    .map(|v| v.cell())
                    .collect::<Vec<Cell>>();
                Ok((public_key_cells, hashed_msg_cells))
            },
        )?;
        for (i, cell) in public_key_cells.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.n_instance, i)?;
        }
        for (i, cell) in hashed_msg_cells.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.hash_instance, i)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::big_uint::decompose_biguint;
    use halo2_base::halo2_proofs::halo2curves::pasta::Fp;
    use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use halo2curves::bn256::Fr as FR;
    use rand::{thread_rng, Rng};
    use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
    use sha2::{Digest, Sha256};

    #[test]
    fn test_rsa_signature_with_hash_circuit1() {
        fn run<F: PrimeField>() {
            let mut rng = thread_rng();
            let private_key =
                RsaPrivateKey::new(&mut rng, TestRSASignatureWithHashCircuit1::<F>::BITS_LEN)
                    .expect("failed to generate a key");
            let public_key = RsaPublicKey::from(&private_key);
            let n = BigUint::from_radix_le(&public_key.n().to_radix_le(16), 16).unwrap();
            let mut msg: [u8; 128] = [0; 128];
            for i in 0..128 {
                msg[i] = rng.gen();
            }
            let hashed_msg = Sha256::digest(&msg);
            let circuit = TestRSASignatureWithHashCircuit1::<F> {
                private_key,
                public_key,
                msg: msg.to_vec(),
                _f: PhantomData,
            };
            let num_limbs = 2048 / 64;
            let limb_bits = 64;
            let n_fes = decompose_biguint::<F>(&n, num_limbs, limb_bits);
            let hash_fes = hashed_msg
                .iter()
                .map(|byte| F::from(*byte as u64))
                .collect::<Vec<F>>();
            let public_inputs = vec![n_fes, hash_fes];
            let k = 15;
            let prover = match MockProver::run(k, &circuit, public_inputs) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            prover.verify().unwrap();
        }
        run::<Fr>();
    }

    #[test]
    fn test_rsa_signature_with_hash_circuit2() {
        fn run<F: PrimeField>() {
            let mut rng = thread_rng();
            let private_key =
                RsaPrivateKey::new(&mut rng, TestRSASignatureWithHashCircuit1::<F>::BITS_LEN)
                    .expect("failed to generate a key");
            let public_key = RsaPublicKey::from(&private_key);
            let n = BigUint::from_radix_le(&public_key.n().to_radix_le(16), 16).unwrap();
            let var_name = [
                "86", "50", "255", "51", "255", "50", "54", "57", "55", "50", "48", "50", "52",
                "48", "55", "49", "56", "49", "50", "52", "53", "53", "55", "51", "56", "55",
                "255", "83", "117", "109", "105", "116", "32", "75", "117", "109", "97", "114",
                "255", "48", "49", "45", "48", "49", "45", "49", "57", "56", "52", "255", "77",
                "255", "67", "47", "79", "32", "73", "115", "104", "119", "97", "114", "32", "67",
                "104", "97", "110", "100", "255", "69", "97", "115", "116", "32", "68", "101",
                "108", "104", "105", "255", "255", "66", "45", "51", "49", "44", "32", "51", "114",
                "100", "32", "70", "108", "111", "111", "114", "255", "255", "49", "49", "48",
                "48", "53", "49", "255", "75", "114", "105", "115", "104", "110", "97", "32", "78",
                "97", "103", "97", "114", "255", "68", "101", "108", "104", "105", "255", "82",
                "97", "100", "104", "101", "121", "32", "83", "104", "121", "97", "109", "32",
                "80", "97", "114", "107", "32", "69", "120", "116", "101", "110", "115", "105",
                "111", "110", "255", "71", "97", "110", "100", "104", "105", "32", "78", "97",
                "103", "97", "114", "255", "75", "114", "105", "115", "104", "110", "97", "32",
                "78", "97", "103", "97", "114", "255", "49", "50", "51", "52", "255", "255", "79",
                "255", "81", "0", "47", "0", "0", "0", "0", "0", "60", "0", "0", "0", "60", "0",
                "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "60", "0", "0", "0", "60", "0",
                "0", "0", "0", "0", "0", "0", "0", "0", "3", "7", "1", "1", "7", "1", "1", "7",
                "1", "1", "255", "82", "0", "12", "2", "0", "0", "1", "1", "5", "4", "4", "0", "0",
                "255", "92", "0", "35", "66", "111", "24", "110", "234", "110", "234", "110",
                "188", "103", "0", "103", "0", "102", "226", "95", "76", "95", "76", "95", "100",
                "72", "3", "72", "3", "72", "69", "79", "210", "79", "210", "79", "97", "255",
                "100", "0", "34", "0", "1", "67", "114", "101", "97", "116", "101", "100", "32",
                "98", "121", "58", "32", "74", "74", "50", "48", "48", "48", "32", "118", "101",
                "114", "115", "105", "111", "110", "32", "52", "46", "49", "255", "144", "0", "10",
                "0", "0", "0", "0", "2", "236", "0", "1", "255", "82", "0", "12", "2", "0", "0",
                "1", "1", "5", "4", "4", "0", "0", "255", "147", "255", "145", "0", "4", "0", "0",
                "195", "235", "5", "4", "11", "128", "38", "166", "255", "145", "0", "4", "0", "1",
                "192", "249", "65", "128", "16", "124", "55", "255", "145", "0", "4", "0", "2",
                "192", "249", "65", "0", "14", "175", "255", "145", "0", "4", "0", "3", "195",
                "238", "4", "131", "237", "4", "131", "232", "8", "15", "61", "227", "128", "14",
                "78", "244", "198", "10", "190", "128", "74", "255", "145", "0", "4", "0", "4",
                "192", "30", "10", "3", "229", "7", "0", "240", "64", "15", "157", "12", "56",
                "206", "16", "124", "255", "145", "0", "4", "0", "5", "192", "120", "40", "7",
                "196", "14", "1", "224", "128", "16", "128", "16", "144", "102", "15", "55", "255",
                "145", "0", "4", "0", "6", "195", "235", "15", "131", "232", "29", "7", "202",
                "36", "35", "123", "119", "32", "21", "133", "220", "173", "123", "29", "124",
                "190", "51", "158", "143", "0", "4", "234", "216", "145", "15", "189", "91", "82",
                "210", "45", "90", "170", "52", "34", "209", "158", "13", "108", "213", "78",
                "158", "137", "255", "145", "0", "4", "0", "7", "192", "56", "56", "15", "132",
                "112", "35", "164", "155", "1", "61", "240", "240", "232", "42", "148", "255",
                "145", "0", "4", "0", "8", "192", "49", "32", "29", "20", "7", "59", "113", "163",
                "24", "138", "108", "156", "26", "255", "145", "0", "4", "0", "9", "193", "241",
                "27", "135", "206", "122", "15", "144", "184", "25", "25", "211", "9", "237",
                "209", "173", "196", "150", "111", "25", "246", "238", "110", "167", "245", "97",
                "24", "144", "213", "187", "170", "6", "133", "23", "21", "199", "31", "204", "1",
                "35", "171", "39", "5", "127", "48", "209", "141", "130", "143", "72", "200",
                "150", "233", "85", "241", "55", "128", "173", "216", "49", "52", "216", "139",
                "110", "91", "225", "30", "109", "204", "188", "146", "157", "214", "18", "87",
                "32", "89", "157", "101", "246", "187", "223", "117", "50", "62", "81", "65",
                "205", "126", "255", "145", "0", "4", "0", "10", "160", "28", "48", "34", "126",
                "189", "171", "105", "217", "255", "145", "0", "4", "0", "11", "160", "58", "48",
                "35", "137", "175", "61", "198", "184", "255", "145", "0", "4", "0", "12", "199",
                "200", "222", "62", "71", "240", "248", "106", "128", "111", "222", "255", "137",
                "22", "12", "202", "78", "23", "233", "116", "114", "125", "113", "100", "226",
                "16", "241", "69", "36", "122", "23", "17", "120", "240", "5", "127", "168", "109",
                "250", "155", "59", "7", "206", "127", "108", "18", "105", "216", "235", "32",
                "159", "93", "175", "208", "238", "70", "166", "172", "160", "62", "58", "51",
                "254", "8", "55", "97", "246", "138", "129", "137", "16", "33", "165", "205", "22",
                "186", "92", "163", "108", "70", "25", "168", "130", "96", "162", "13", "106",
                "78", "71", "254", "89", "108", "233", "225", "39", "97", "63", "17", "13", "42",
                "95", "0", "30", "0", "130", "28", "154", "5", "162", "1", "51", "178", "125",
                "65", "235", "47", "162", "24", "112", "152", "119", "13", "83", "212", "102",
                "84", "248", "36", "193", "63", "193", "101", "254", "213", "80", "59", "106",
                "79", "74", "170", "227", "110", "2", "204", "201", "182", "60", "114", "60", "65",
                "195", "148", "232", "145", "30", "46", "232", "19", "28", "159", "29", "153",
                "101", "206", "162", "28", "108", "80", "229", "255", "145", "0", "4", "0", "13",
                "128", "255", "145", "0", "4", "0", "14", "128", "255", "145", "0", "4", "0", "15",
                "195", "224", "188", "135", "193", "127", "15", "134", "196", "158", "62", "204",
                "245", "173", "53", "224", "68", "102", "215", "173", "58", "244", "81", "11",
                "131", "110", "245", "166", "156", "166", "215", "76", "158", "156", "10", "170",
                "148", "182", "60", "115", "173", "176", "16", "1", "15", "169", "187", "111",
                "38", "226", "185", "241", "97", "88", "34", "140", "218", "123", "203", "88",
                "112", "88", "143", "74", "108", "17", "106", "37", "69", "149", "69", "151",
                "215", "37", "209", "201", "125", "81", "117", "124", "102", "108", "252", "251",
                "26", "14", "104", "229", "35", "22", "219", "199", "180", "110", "24", "47",
                "126", "104", "141", "232", "237", "115", "47", "31", "176", "190", "111", "243",
                "116", "185", "32", "185", "121", "57", "59", "197", "65", "61", "233", "98", "18",
                "172", "235", "82", "146", "150", "241", "30", "186", "172", "161", "155", "148",
                "171", "212", "237", "170", "123", "85", "177", "76", "132", "230", "38", "114",
                "51", "254", "36", "37", "236", "202", "21", "44", "48", "203", "191", "154", "22",
                "219", "13", "67", "28", "214", "71", "72", "63", "173", "24", "137", "62", "141",
                "14", "123", "11", "237", "106", "219", "68", "40", "62", "29", "255", "145", "0",
                "4", "0", "16", "128", "255", "145", "0", "4", "0", "17", "128", "255", "217",
                "235", "89", "152", "53", "59", "33", "186", "193", "56", "29", "117", "14", "31",
                "162", "102", "65", "224", "150", "175", "57", "29", "17", "95", "173", "173",
                "212", "123", "244", "250", "47", "255", "139", "96", "54", "34", "219", "243",
                "92", "100", "240", "182", "255", "21", "167", "91", "244", "127", "53", "165",
                "180", "223", "131", "221", "184", "74", "53", "233", "255", "238", "30", "166",
                "5", "157", "243",
            ];
            let _msg = var_name;
            let mut byte_vec: Vec<u8> = Vec::new();
            for i in 0..1015 {
                byte_vec.push(var_name[i].parse::<u8>().unwrap());
            }
            let hashed_msg = Sha256::digest(&byte_vec);
            let mut byte_vec2: Vec<u8> = Vec::new();
            for i in 1015..1137 {
                byte_vec2.push(var_name[i].parse::<u8>().unwrap());
            }
            let hashed_msg2 = Sha256::digest(&byte_vec2);
            let circuit = TestRSASignatureWithHashCircuit1::<F> {
                private_key,
                public_key,
                msg: byte_vec,
                _f: PhantomData,
            };
            let num_limbs = 2048 / 64;
            let limb_bits = 64;
            let n_fes = decompose_biguint::<F>(&n, num_limbs, limb_bits);
            let hash_fes = hashed_msg
                .iter()
                .map(|byte| F::from(*byte as u64))
                .collect::<Vec<F>>();
            let public_inputs = vec![n_fes, hash_fes];
            let k = 15;
            let prover = match MockProver::run(k, &circuit, public_inputs) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            prover.verify().unwrap();

            let private_key2 =
                RsaPrivateKey::new(&mut rng, TestRSASignatureWithHashCircuit1::<F>::BITS_LEN)
                    .expect("failed to generate a key");
            let public_key2 = RsaPublicKey::from(&private_key2);
            let n2 = BigUint::from_radix_le(&public_key2.n().to_radix_le(16), 16).unwrap();
            let circuit2 = TestRSASignatureWithHashCircuit1::<F> {
                private_key: private_key2,
                public_key: public_key2,
                msg: byte_vec2,
                _f: PhantomData,
            };
            let hash_fes2 = hashed_msg2
                .iter()
                .map(|byte| F::from(*byte as u64))
                .collect::<Vec<F>>();
            let n_fes2 = decompose_biguint::<F>(&n2, num_limbs, limb_bits);
            let public_inputs2 = vec![n_fes2, hash_fes2];
            let prover = match MockProver::run(k, &circuit2, public_inputs2) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            prover.verify().unwrap();
        }
        run::<Fr>();
    }

    fn to_integer(unsigned_integer: u64) -> u64 {
        unsigned_integer - 48
    }

    fn to_integer_small(unsigned_integer: u32) -> u32 {
        unsigned_integer - 48
    }

    fn reference_id_position() -> usize {
        2
    }

    fn name_position() -> usize {
        3
    }

    fn dob_position() -> usize {
        4
    }

    fn gender_position() -> usize {
        5
    }

    fn pincode_position() -> usize {
        11
    }

    fn state_position() -> usize {
        13
    }

    fn photo_position() -> usize {
        18
    }

    #[test]
    fn test_aadhaar_qr_verifier_circuit() {
        fn run<F: PrimeField>() {
            let msg = [
                "86", "50", "255", "51", "255", "50", "54", "57", "55", "50", "48", "50", "52",
                "48", "55", "49", "56", "49", "50", "52", "53", "53", "55", "51", "56", "55",
                "255", "83", "117", "109", "105", "116", "32", "75", "117", "109", "97", "114",
                "255", "48", "49", "45", "48", "49", "45", "49", "57", "56", "52", "255", "77",
                "255", "67", "47", "79", "32", "73", "115", "104", "119", "97", "114", "32", "67",
                "104", "97", "110", "100", "255", "69", "97", "115", "116", "32", "68", "101",
                "108", "104", "105", "255", "255", "66", "45", "51", "49", "44", "32", "51", "114",
                "100", "32", "70", "108", "111", "111", "114", "255", "255", "49", "49", "48",
                "48", "53", "49", "255", "75", "114", "105", "115", "104", "110", "97", "32", "78",
                "97", "103", "97", "114", "255", "68", "101", "108", "104", "105", "255", "82",
                "97", "100", "104", "101", "121", "32", "83", "104", "121", "97", "109", "32",
                "80", "97", "114", "107", "32", "69", "120", "116", "101", "110", "115", "105",
                "111", "110", "255", "71", "97", "110", "100", "104", "105", "32", "78", "97",
                "103", "97", "114", "255", "75", "114", "105", "115", "104", "110", "97", "32",
                "78", "97", "103", "97", "114", "255", "49", "50", "51", "52", "255", "255", "79",
                "255", "81", "0", "47", "0", "0", "0", "0", "0", "60", "0", "0", "0", "60", "0",
                "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "60", "0", "0", "0", "60", "0",
                "0", "0", "0", "0", "0", "0", "0", "0", "3", "7", "1", "1", "7", "1", "1", "7",
                "1", "1", "255", "82", "0", "12", "2", "0", "0", "1", "1", "5", "4", "4", "0", "0",
                "255", "92", "0", "35", "66", "111", "24", "110", "234", "110", "234", "110",
                "188", "103", "0", "103", "0", "102", "226", "95", "76", "95", "76", "95", "100",
                "72", "3", "72", "3", "72", "69", "79", "210", "79", "210", "79", "97", "255",
                "100", "0", "34", "0", "1", "67", "114", "101", "97", "116", "101", "100", "32",
                "98", "121", "58", "32", "74", "74", "50", "48", "48", "48", "32", "118", "101",
                "114", "115", "105", "111", "110", "32", "52", "46", "49", "255", "144", "0", "10",
                "0", "0", "0", "0", "2", "236", "0", "1", "255", "82", "0", "12", "2", "0", "0",
                "1", "1", "5", "4", "4", "0", "0", "255", "147", "255", "145", "0", "4", "0", "0",
                "195", "235", "5", "4", "11", "128", "38", "166", "255", "145", "0", "4", "0", "1",
                "192", "249", "65", "128", "16", "124", "55", "255", "145", "0", "4", "0", "2",
                "192", "249", "65", "0", "14", "175", "255", "145", "0", "4", "0", "3", "195",
                "238", "4", "131", "237", "4", "131", "232", "8", "15", "61", "227", "128", "14",
                "78", "244", "198", "10", "190", "128", "74", "255", "145", "0", "4", "0", "4",
                "192", "30", "10", "3", "229", "7", "0", "240", "64", "15", "157", "12", "56",
                "206", "16", "124", "255", "145", "0", "4", "0", "5", "192", "120", "40", "7",
                "196", "14", "1", "224", "128", "16", "128", "16", "144", "102", "15", "55", "255",
                "145", "0", "4", "0", "6", "195", "235", "15", "131", "232", "29", "7", "202",
                "36", "35", "123", "119", "32", "21", "133", "220", "173", "123", "29", "124",
                "190", "51", "158", "143", "0", "4", "234", "216", "145", "15", "189", "91", "82",
                "210", "45", "90", "170", "52", "34", "209", "158", "13", "108", "213", "78",
                "158", "137", "255", "145", "0", "4", "0", "7", "192", "56", "56", "15", "132",
                "112", "35", "164", "155", "1", "61", "240", "240", "232", "42", "148", "255",
                "145", "0", "4", "0", "8", "192", "49", "32", "29", "20", "7", "59", "113", "163",
                "24", "138", "108", "156", "26", "255", "145", "0", "4", "0", "9", "193", "241",
                "27", "135", "206", "122", "15", "144", "184", "25", "25", "211", "9", "237",
                "209", "173", "196", "150", "111", "25", "246", "238", "110", "167", "245", "97",
                "24", "144", "213", "187", "170", "6", "133", "23", "21", "199", "31", "204", "1",
                "35", "171", "39", "5", "127", "48", "209", "141", "130", "143", "72", "200",
                "150", "233", "85", "241", "55", "128", "173", "216", "49", "52", "216", "139",
                "110", "91", "225", "30", "109", "204", "188", "146", "157", "214", "18", "87",
                "32", "89", "157", "101", "246", "187", "223", "117", "50", "62", "81", "65",
                "205", "126", "255", "145", "0", "4", "0", "10", "160", "28", "48", "34", "126",
                "189", "171", "105", "217", "255", "145", "0", "4", "0", "11", "160", "58", "48",
                "35", "137", "175", "61", "198", "184", "255", "145", "0", "4", "0", "12", "199",
                "200", "222", "62", "71", "240", "248", "106", "128", "111", "222", "255", "137",
                "22", "12", "202", "78", "23", "233", "116", "114", "125", "113", "100", "226",
                "16", "241", "69", "36", "122", "23", "17", "120", "240", "5", "127", "168", "109",
                "250", "155", "59", "7", "206", "127", "108", "18", "105", "216", "235", "32",
                "159", "93", "175", "208", "238", "70", "166", "172", "160", "62", "58", "51",
                "254", "8", "55", "97", "246", "138", "129", "137", "16", "33", "165", "205", "22",
                "186", "92", "163", "108", "70", "25", "168", "130", "96", "162", "13", "106",
                "78", "71", "254", "89", "108", "233", "225", "39", "97", "63", "17", "13", "42",
                "95", "0", "30", "0", "130", "28", "154", "5", "162", "1", "51", "178", "125",
                "65", "235", "47", "162", "24", "112", "152", "119", "13", "83", "212", "102",
                "84", "248", "36", "193", "63", "193", "101", "254", "213", "80", "59", "106",
                "79", "74", "170", "227", "110", "2", "204", "201", "182", "60", "114", "60", "65",
                "195", "148", "232", "145", "30", "46", "232", "19", "28", "159", "29", "153",
                "101", "206", "162", "28", "108", "80", "229", "255", "145", "0", "4", "0", "13",
                "128", "255", "145", "0", "4", "0", "14", "128", "255", "145", "0", "4", "0", "15",
                "195", "224", "188", "135", "193", "127", "15", "134", "196", "158", "62", "204",
                "245", "173", "53", "224", "68", "102", "215", "173", "58", "244", "81", "11",
                "131", "110", "245", "166", "156", "166", "215", "76", "158", "156", "10", "170",
                "148", "182", "60", "115", "173", "176", "16", "1", "15", "169", "187", "111",
                "38", "226", "185", "241", "97", "88", "34", "140", "218", "123", "203", "88",
                "112", "88", "143", "74", "108", "17", "106", "37", "69", "149", "69", "151",
                "215", "37", "209", "201", "125", "81", "117", "124", "102", "108", "252", "251",
                "26", "14", "104", "229", "35", "22", "219", "199", "180", "110", "24", "47",
                "126", "104", "141", "232", "237", "115", "47", "31", "176", "190", "111", "243",
                "116", "185", "32", "185", "121", "57", "59", "197", "65", "61", "233", "98", "18",
                "172", "235", "82", "146", "150", "241", "30", "186", "172", "161", "155", "148",
                "171", "212", "237", "170", "123", "85", "177", "76", "132", "230", "38", "114",
                "51", "254", "36", "37", "236", "202", "21", "44", "48", "203", "191", "154", "22",
                "219", "13", "67", "28", "214", "71", "72", "63", "173", "24", "137", "62", "141",
                "14", "123", "11", "237", "106", "219", "68", "40", "62", "29", "255", "145", "0",
                "4", "0", "16", "128", "255", "145", "0", "4", "0", "17", "128", "255", "217",
                "235", "89", "152", "53", "59", "33", "186", "193", "56", "29", "117", "14", "31",
                "162", "102", "65", "224", "150", "175", "57", "29", "17", "95", "173", "173",
                "212", "123", "244", "250", "47", "255", "139", "96", "54", "34", "219", "243",
                "92", "100", "240", "182", "255", "21", "167", "91", "244", "127", "53", "165",
                "180", "223", "131", "221", "184", "74", "53", "233", "255", "238", "30", "166",
                "5", "157", "243",
            ];

            let mut delimiter_indices = [
                2, 4, 26, 38, 49, 51, 68, 79, 80, 96, 97, 104, 118, 124, 152, 165, 179, 184,
            ];

            let timestamp_year_start_index = delimiter_indices[reference_id_position() - 1] + 5;
            let timestamp_year_end_index = timestamp_year_start_index.clone() + 3;
            let timestamp_month_start_index = timestamp_year_end_index.clone() + 1;
            let timestamp_month_end_index = timestamp_month_start_index.clone() + 1;
            let timestamp_day_start_index = timestamp_month_end_index.clone() + 1;
            let timestamp_day_end_index = timestamp_day_start_index.clone() + 1;
            let timestamp_hour_start_index = timestamp_day_end_index.clone() + 1;
            let timestamp_hour_end_index = timestamp_hour_start_index.clone() + 1;

            let mut year_vec: Vec<u64> = Vec::new();
            let mut month_vec: Vec<u64> = Vec::new();
            let mut day_vec: Vec<u64> = Vec::new();
            let mut hour_vec: Vec<u64> = Vec::new();
            let mut timestamp_vec: Vec<u64> = Vec::new();

            // Start time 1
            let start_time = Instant::now();

            for i in timestamp_year_start_index..timestamp_hour_end_index + 1 {
                timestamp_vec.push(msg[i].parse::<u64>().unwrap());
                if i >= timestamp_year_start_index && i <= timestamp_year_end_index {
                    year_vec.push(to_integer(msg[i].parse::<u64>().unwrap()));
                } else if i >= timestamp_month_start_index && i <= timestamp_month_end_index {
                    month_vec.push(to_integer(msg[i].parse::<u64>().unwrap()));
                } else if i >= timestamp_day_start_index && i <= timestamp_day_end_index {
                    day_vec.push(to_integer(msg[i].parse::<u64>().unwrap()));
                } else if i >= timestamp_hour_start_index && i <= timestamp_hour_end_index {
                    hour_vec.push(to_integer(msg[i].parse::<u64>().unwrap()));
                }
            }

            let year_data: u64 =
                year_vec[0] * 1000 + year_vec[1] * 100 + year_vec[2] * 10 + year_vec[3];
            let month_data: u64 = month_vec[0] * 10 + month_vec[1];
            let day_data: u64 = day_vec[0] * 10 + day_vec[1];
            let hour_data: u64 = hour_vec[0] * 10 + hour_vec[1];

            let birth_day_start_index = delimiter_indices[dob_position() - 1] + 1;
            let birth_day_end_index = birth_day_start_index.clone() + 1;
            let birth_month_start_index = birth_day_end_index.clone() + 2;
            let birth_month_end_index = birth_month_start_index.clone() + 1;
            let birth_year_start_index = birth_month_end_index.clone() + 2;
            let birth_year_end_index = birth_year_start_index.clone() + 3;

            let mut birth_year_vec: Vec<u64> = Vec::new();
            let mut birth_month_vec: Vec<u64> = Vec::new();
            let mut birth_date_vec: Vec<u64> = Vec::new();
            let mut dob_vec: Vec<u64> = Vec::new();
            for i in birth_day_start_index..birth_year_end_index + 1 {
                dob_vec.push(msg[i].parse::<u64>().unwrap());
                if i >= birth_day_start_index && i <= birth_day_end_index {
                    birth_date_vec.push(to_integer(msg[i].parse::<u64>().unwrap()));
                } else if i >= birth_month_start_index && i <= birth_month_end_index {
                    birth_month_vec.push(to_integer(msg[i].parse::<u64>().unwrap()));
                } else if i >= birth_year_start_index && i <= birth_year_end_index {
                    birth_year_vec.push(to_integer(msg[i].parse::<u64>().unwrap()));
                }
            }

            let birth_date_data = birth_date_vec[0] * 10 + birth_date_vec[1];
            let birth_month_data = birth_month_vec[0] * 10 + birth_month_vec[1];
            let birth_year_data = birth_year_vec[0] * 1000
                + birth_year_vec[1] * 100
                + birth_year_vec[2] * 10
                + birth_year_vec[3];
            println!("Birth year data : {birth_year_data}");
            println!("Year data: {year_data}");
            let age_by_year: u64 = year_data - birth_year_data - 1;
            let mut age: u64 = age_by_year;
            if birth_month_data > month_data {
                age += 1;
            } else if birth_month_data == month_data {
                if birth_date_data > day_data {
                    age += 1;
                }
            }

            let gender_index = delimiter_indices[gender_position() - 1] + 1;
            let gender_data = msg[gender_index].parse::<u8>().unwrap();

            let pincode_start_index = delimiter_indices[pincode_position() - 1] + 1;
            let pincode_end_index = delimiter_indices[pincode_position()];
            let mut pincode_vec: Vec<u32> = Vec::new();
            for i in pincode_start_index..pincode_end_index {
                pincode_vec.push(to_integer_small(msg[i].parse::<u32>().unwrap()));
            }

            let mut pincode_data = 0;
            for i in pincode_vec {
                pincode_data = pincode_data * 10 + i;
            }

            let state_start_index = delimiter_indices[state_position() - 1] + 1;
            let state_end_index = delimiter_indices[state_position()];
            let mut state_vec: Vec<u8> = Vec::new();
            for i in state_start_index..state_end_index {
                state_vec.push(msg[i].parse::<u8>().unwrap());
            }

            // RSA-SHA256 Subcircuit
            let mut rng = thread_rng();
            let private_key =
                RsaPrivateKey::new(&mut rng, TestRSASignatureWithHashCircuit1::<F>::BITS_LEN)
                    .expect("failed to generate a key");
            let public_key = RsaPublicKey::from(&private_key);
            let n = BigUint::from_radix_le(&public_key.n().to_radix_le(16), 16).unwrap();
            let mut byte_vec: Vec<u8> = Vec::new();
            for i in 0..700 {
                byte_vec.push(msg[i].parse::<u8>().unwrap());
            }
            let hashed_msg = Sha256::digest(&byte_vec);
            let hash_and_sign_circuit =
                TestRSASignatureWithHashCircuit1::<F>::new(private_key, public_key, byte_vec);

            // Conditional Secrets Subcircuit
            let cond_secrets_circuit = IdentityCircuit::new(
                Some(true),
                Some(age),
                Some(age),
                Some(true),
                Some(gender_data),
                Some(gender_data),
                Some(true),
                Some(pincode_data),
                Some(pincode_data),
                Some(true),
                Some(state_vec.clone()),
                Some(state_vec),
            );

            // Nullifier subcircuit
            let nullifier_proof_generation_duration = start_time.elapsed();
            println!(
                "Nullifier Proof Generation Time elapsed: {:?}",
                nullifier_proof_generation_duration
            );

            const R_F: usize = 8;
            const R_P: usize = 57;
            const T: usize = 5;
            const RATE: usize = 4;

            let mut poseidon = Poseidon::<FR, T, RATE>::new(R_F, R_P);
            let nullifier_seed = "12345678";
            let mut photo_vec: Vec<u64> = Vec::new();

            let photo_start_index = delimiter_indices[photo_position() - 1] + 1;
            let photo_end_index = 1137;
            let null_fr = nullifier_seed.parse::<u64>().unwrap();
            photo_vec.push(null_fr);
            for i in photo_start_index..photo_end_index {
                photo_vec.push(msg[i].parse::<u64>().unwrap());
            }

            let fr_vector: Vec<FR> = photo_vec.iter().map(|s| FR::from(*s)).collect();

            let inputs = fr_vector;
            poseidon.update(&inputs[..]);
            let nullifier = poseidon.squeeze();
            println!("Poseidon Output: {:?}", nullifier);

            let nullifier_proof_verification_duration = start_time.elapsed();
            println!(
                "Nullifier Proof Verification Time elapsed: {:?}",
                nullifier_proof_verification_duration
            );

            // Timestamp Subcircuit
            let timestamp_circuit = TimestampCircuit::<F>::new(
                Some(F::from(year_data)),
                Some(F::from(month_data)),
                Some(F::from(day_data)),
                Some(F::from(hour_data)),
                Some(F::from(00u64)),
                Some(F::from(00u64)),
            );

            // Signal Hash Subcircuit
            //Maximum value of signal_hash * signal_hash = "18446744073709551615"
            let signal_hash = "4294967295";
            let signal_val: u64 = signal_hash.parse().unwrap();
            let signal_circuit = SquareCircuit::<F>::new(F::from(signal_val));

            // Verifying the RSA-SHA256 subcircuit
            let num_limbs = 2048 / 64;
            let limb_bits = 64;
            let n_fes = decompose_biguint::<F>(&n, num_limbs, limb_bits);
            let hash_fes = hashed_msg
                .iter()
                .map(|byte| F::from(*byte as u64))
                .collect::<Vec<F>>();
            let public_inputs = vec![n_fes, hash_fes];
            let k = 15;

            let extraction_duration = start_time.elapsed();
            println!("Extraction of Data Time elapsed: {:?}", extraction_duration);

            let prover = match MockProver::run(k, &hash_and_sign_circuit.clone(), public_inputs) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };

            let sha_proof_generation_duration = start_time.elapsed();
            println!(
                "RSA-SHA256 Proof Generation Time elapsed: {:?}",
                sha_proof_generation_duration
            );

            prover.verify().unwrap();

            let sha_proof_verification_duration = start_time.elapsed();
            println!(
                "RSA-SHA256 Proof Verification Time elapsed: {:?}",
                sha_proof_verification_duration
            );

            // Verifying the conditional secrets subcircuit
            let prover: MockProver<Fp> =
                MockProver::run(k, &cond_secrets_circuit.clone(), vec![]).unwrap();

            let cs_proof_generation_duration = start_time.elapsed();
            println!(
                "Conditional Secrets Proof Generation Time elapsed: {:?}",
                cs_proof_generation_duration
            );

            assert!(prover.verify().is_ok());

            let cs_proof_verification_duration = start_time.elapsed();
            println!(
                "Conditional Secrets Proof Verification Time elapsed: {:?}",
                cs_proof_verification_duration
            );

            // Verifying the timestamp subcircuit
            let public_inputs = vec![];
            let prover = MockProver::run(k, &timestamp_circuit.clone(), public_inputs).unwrap();

            let timestamp_proof_generation_duration = start_time.elapsed();
            println!(
                "Timestamp Proof Generation Time elapsed: {:?}",
                timestamp_proof_generation_duration
            );

            assert_eq!(prover.verify(), Ok(()));

            let timestamp_proof_verification_duration = start_time.elapsed();
            println!(
                "Timestamp Proof  Verification Time elapsed: {:?}",
                timestamp_proof_verification_duration
            );

            // Verifying the signal hash subcircuit
            let public_inputs = vec![F::from(signal_val * signal_val)];

            let prover = MockProver::run(k, &signal_circuit.clone(), vec![public_inputs]).unwrap();

            let signal_proof_generation_duration = start_time.elapsed();
            println!(
                "Signal Proof Generation Time elapsed: {:?}",
                signal_proof_generation_duration
            );

            prover.assert_satisfied();

            let signal_proof_verification_duration = start_time.elapsed();
            println!(
                "Signal Proof Verification Time elapsed: {:?}",
                signal_proof_verification_duration
            );

            // Benchmarks
            println!("##### Benchmarks #####");
            let sha_prove_time = sha_proof_generation_duration - extraction_duration;
            let sha_ver_time = sha_proof_verification_duration - sha_proof_generation_duration;
            println!("RSA-SHA256 proving time: {:?}", sha_prove_time);
            println!("RSA-SHA256 verification time: {:?}", sha_ver_time);
            let nullifier_prove_time =
                nullifier_proof_verification_duration - nullifier_proof_generation_duration;
            let nullifier_ver_time = extraction_duration - nullifier_proof_verification_duration;
            println!("Nullifier proving time: {:?}", nullifier_prove_time);
            println!("Nullifier verification time: {:?}", nullifier_ver_time);
            let cs_prove_time = cs_proof_generation_duration - sha_proof_verification_duration;
            let cs_ver_time = cs_proof_verification_duration - cs_proof_generation_duration;
            println!("Conditional Secrets proving time: {:?}", cs_prove_time);
            println!("Conditional Secrets verification time: {:?}", cs_ver_time);
            let timestamp_prove_time =
                timestamp_proof_generation_duration - cs_proof_verification_duration;
            let timestamp_ver_time =
                timestamp_proof_verification_duration - timestamp_proof_generation_duration;
            println!("Timestamp proving time: {:?}", timestamp_prove_time);
            println!("Timestamp verification time: {:?}", timestamp_ver_time);
            let signal_prove_time =
                signal_proof_generation_duration - timestamp_proof_verification_duration;
            let signal_ver_time =
                signal_proof_verification_duration - signal_proof_generation_duration;
            println!("Signal proving time: {:?}", signal_prove_time);
            println!("Signal verification time: {:?}", signal_ver_time);
        }
        run::<Fr>();
    }
}
