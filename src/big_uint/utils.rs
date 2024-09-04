use halo2_base::utils::decompose_biguint as _decompose_biguint;
use halo2curves::ff::PrimeField;
use num_bigint::{BigInt, BigUint};
use num_traits::Signed;

pub fn decompose_bigint<F: PrimeField>(
    e: &BigInt,
    number_of_limbs: usize,
    limb_bits_len: usize,
) -> Vec<F> {
    if e.is_negative() {
        decompose_biguint::<F>(e.magnitude(), number_of_limbs, limb_bits_len)
            .into_iter()
            .map(|x| -x)
            .collect()
    } else {
        decompose_biguint(e.magnitude(), number_of_limbs, limb_bits_len)
    }
}

pub fn decompose_biguint<F: PrimeField>(
    e: &BigUint,
    number_of_limbs: usize,
    limb_bits_len: usize,
) -> Vec<F> {
    assert!(limb_bits_len < 128);
    if limb_bits_len <= 64 {
        decompose_u64_digits_to_limbs(e.to_u64_digits(), number_of_limbs, limb_bits_len)
            .into_iter()
            .map(|v| F::from(v))
            .collect()
    } else {
        _decompose_biguint(e, number_of_limbs, limb_bits_len)
    }
}

pub(crate) fn decompose_u64_digits_to_limbs(
    e: impl IntoIterator<Item = u64>,
    number_of_limbs: usize,
    bit_len: usize,
) -> Vec<u64> {
    let mut e = e.into_iter();
    let mask: u64 = ((1u128 << bit_len) - 1u128) as u64;
    let mut u64_digit = e.next().unwrap_or(0);
    let mut rem = 64;
    (0..number_of_limbs)
        .map(|_| match rem.cmp(&bit_len) {
            core::cmp::Ordering::Greater => {
                let limb = u64_digit & mask;
                u64_digit >>= bit_len;
                rem -= bit_len;
                limb
            }
            core::cmp::Ordering::Equal => {
                let limb = u64_digit & mask;
                u64_digit = e.next().unwrap_or(0);
                rem = 64;
                limb
            }
            core::cmp::Ordering::Less => {
                let mut limb = u64_digit;
                u64_digit = e.next().unwrap_or(0);
                limb |= (u64_digit & ((1 << (bit_len - rem)) - 1)) << rem;
                u64_digit >>= bit_len - rem;
                rem += 64 - bit_len;
                limb
            }
        })
        .collect()
}
