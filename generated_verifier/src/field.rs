#![cfg_attr(not(feature = "std"), no_std)]

use primitive_types::U256;

// BN254 scalar field modulus
pub const MODULUS: U256 = U256([
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
]);

pub type Fr = U256;

/// Add two field elements modulo p
pub fn add_mod(a: Fr, b: Fr) -> Fr {
    let (sum, overflow) = a.overflowing_add(b);
    if overflow || sum >= MODULUS {
        sum.overflowing_sub(MODULUS).0
    } else {
        sum
    }
}

/// Subtract two field elements modulus p
pub fn sub_mod(a: Fr, b: Fr) -> Fr {
    if a >= b {
        a - b
    } else {
        MODULUS - (b - a)
    }
}

/// Multiply two field elements modulo p
pub fn mul_mod(a: Fr, b: Fr) -> Fr {
    // Extended multiplication using U512
    let a_full = U256::from(a);
    let b_full = U256::from(b);

    // Compute full product (requires U512 logic) - simple approach for now
    let mut result = U256::zero();
    let mut temp_a = a;
    let mut temp_b = b;

    while temp_b > U256::zero() {
        if temp_b & U256::one() == U256::one() {
            result = add_mod(result, temp_a);
        }
        temp_a = add_mod(temp_a, temp_a);
        temp_b = temp_b >> 1;
    }

    result
}

/// Compute modular inverse using Fermat's little theorem: a^(p-2) mod p
pub fn inv_mod(a: Fr) -> Fr {
    // a^(p-2) mod p
    let exponent = sub_mod(MODULUS, U256::from(2));
    pow_mod(a, exponent)
}

/// Compute a^exp mod p
pub fn pow_mod(base: Fr, mut exp: Fr) -> Fr {
    let mut result = U256::one();
    let mut b = base;

    while exp > U256::zero() {
        if exp & U256::one() == U256::one() {
            result = mul_mod(result, b);
        }
        b = mul_mod(b, b);
        exp = exp >> 1;
    }

    result
}

/// Negate a field element
pub fn neg_mod(a: Fr) -> Fr {
    if a == U256::zero() {
        U256::zero()
    } else {
        MODULUS - a
    }
}

/// Square a field element
pub fn sqr_mod(a: Fr) -> Fr {
    mul_mod(a, a)
}

/// Divide two field elements (a / b = a * b^-1)
pub fn div_mod(a: Fr, b: Fr) -> Fr {
    mul_mod(a, inv_mod(b))
}

/// Convert from bytes (big-endian)
pub fn from_bytes_be(bytes: &[u8; 32]) -> Fr {
    U256::from_big_endian(bytes)
}

/// Convert to bytes (big-endian)
pub fn to_bytes_be(value: Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_mod() {
        let a = U256::from(5);
        let b = U256::from(10);
        let result = add_mod(a, b);
        assert_eq!(result, U256::from(15));
    }

    #[test]
    fn test_mul_mod() {
        let a = U256::from(5);
        let b = U256::from(10);
        let result = mul_mod(a, b);
        assert_eq!(result, U256::from(50));
    }
}
