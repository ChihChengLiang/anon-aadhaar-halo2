//! This library provides a RSA verification circuit compatible with the [halo2 library developed by privacy-scaling-explorations team](https://github.com/privacy-scaling-explorations/halo2).
//!
//! A chip in this library, [`RSAConfig`], defines constraints for verifying the RSA relations, specifically modular power `x^e mod n` and [pkcs1v15 signature](https://www.rfc-editor.org/rfc/rfc3447) verification.
//! Its circuit configuration differs depending on whether the exponent parameter `e` of the RSA public key is variable or fixed.
//! For example, since `e` is often fixed to `65537` in the case of pkcs1v15 signature verification, defining `e` as a fixed parameter [`RSAPubE::Fix`] can optimize the number of constraints.
//!
//! In addition to [`RSAConfig`], this library also provides a high-level circuit implementation to verify pkcs1v15 signatures, [`RSASignatureVerifier`].  
//! The verification function in [`RSAConfig`] requires as input a hashed message, whereas the function in [`RSASignatureVerifier`] computes a SHA256 hash of the given message and verifies the given signature for that hash.

pub mod big_uint;
pub use big_uint::*;
use rsa::RsaPrivateKey;
use std::marker::PhantomData;

use halo2_base::halo2_proofs::{
    circuit::{Cell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};

use halo2_base::{gates::range::RangeStrategy::Vertical, QuantumCell, SKIP_FIRST_PASS};
use halo2_base::{
    gates::{range::RangeConfig, GateInstructions},
    utils::PrimeField,
    AssignedValue, Context,
};
use num_bigint::BigUint;

use rsa::{
    pkcs1v15::SigningKey,
    signature::{SignatureEncoding, Signer},
    traits::PublicKeyParts,
    RsaPublicKey,
};

mod extractors{
    pub mod extractor;
    pub mod timstamp_extractor;
    pub mod age_extractor;
    pub mod gender_extractor;
    pub mod pincode_extractor;
    pub mod photo_extractor;
    pub mod qrdata_extractor;
}

mod chip;
mod instructions;
pub use chip::*;
#[cfg(feature = "sha256")]
pub use halo2_dynamic_sha256;
#[cfg(feature = "sha256")]
use halo2_dynamic_sha256::Sha256DynamicConfig;
pub use instructions::*;
#[cfg(feature = "sha256")]

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
    Var(AssignedValue<'v, F>),
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

#[cfg(feature = "sha256")]
/// A circuit implementation to verify pkcs1v15 signatures.
#[derive(Clone, Debug)]
pub struct RSASignatureVerifier<F: PrimeField> {
    rsa_config: RSAConfig<F>,
    sha256_config: Sha256DynamicConfig<F>,
}

#[cfg(feature = "sha256")]
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

impl<F: PrimeField> Circuit<F> for TestRSASignatureWithHashCircuit1<F> {
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

#[cfg(feature = "sha256")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::big_uint::decompose_biguint;
    use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
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
}
