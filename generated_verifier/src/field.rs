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

/// Subtract two field elements modulo p
pub fn sub_mod(a: Fr, b: Fr) -> Fr {
    if a >= b {
        a - b
    } else {
        MODULUS - (b - a)
    }
}

/// Multiply two field elements modulo p
/// TODO: Consider optimizing with Montgomery or Barrett reduction
pub fn mul_mod(a: Fr, b: Fr) -> Fr {
    // Handle zero cases early
    if a.is_zero() || b.is_zero() {
        return U256::zero();
    }

    // Handle one cases
    if a == U256::one() {
        return b;
    }
    if b == U256::one() {
        return a;
    }

    // Use repeated addition for correctness
    // For values that fit in 128 bits, we can use a more efficient method
    let bits_a = 256 - a.leading_zeros();
    let bits_b = 256 - b.leading_zeros();

    if bits_a + bits_b <= 256 {
        // Product won't overflow U256, can do direct multiplication and reduction
        let product = a.saturating_mul(b);
        return reduce_mod(product);
    }

    // For large values, use double-and-add
    let mut result = U256::zero();
    let mut temp = a;
    let mut exp = b;

    while !exp.is_zero() {
        if exp & U256::one() == U256::one() {
            result = add_mod(result, temp);
        }
        temp = add_mod(temp, temp);
        exp = exp >> 1;
    }

    result
}

/// Reduce a U256 value modulo MODULUS using simple subtraction
fn reduce_mod(mut value: U256) -> Fr {
    while value >= MODULUS {
        value = value - MODULUS;
    }
    value
}

/// Compute modular inverse using Fermat's little theorem: a^(p-2) mod p
/// Returns None if a is zero
pub fn inv_mod(a: Fr) -> Fr {
    assert!(!a.is_zero(), "Cannot invert zero");

    // a^(p-2) mod p using Fermat's little theorem
    // For BN254, p - 2 is computed directly
    let exponent = MODULUS - U256::from(2);
    pow_mod(a, exponent)
}

/// Safe version of inv_mod that returns Option
pub fn try_inv_mod(a: Fr) -> Option<Fr> {
    if a.is_zero() {
        return None;
    }
    Some(inv_mod(a))
}

/// Compute a^exp mod p using binary exponentiation
pub fn pow_mod(base: Fr, mut exp: Fr) -> Fr {
    if exp.is_zero() {
        return U256::one();
    }

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
    if a.is_zero() {
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
/// Panics if b is zero
pub fn div_mod(a: Fr, b: Fr) -> Fr {
    assert!(!b.is_zero(), "Division by zero");
    mul_mod(a, inv_mod(b))
}

/// Safe version of div_mod that returns Option
pub fn try_div_mod(a: Fr, b: Fr) -> Option<Fr> {
    if b.is_zero() {
        return None;
    }
    Some(mul_mod(a, inv_mod(b)))
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

        // Test overflow case
        let max_minus_5 = MODULUS - U256::from(5);
        let result = add_mod(max_minus_5, U256::from(10));
        assert_eq!(result, U256::from(5));
    }

    #[test]
    fn test_sub_mod() {
        let a = U256::from(10);
        let b = U256::from(5);
        let result = sub_mod(a, b);
        assert_eq!(result, U256::from(5));
        
        // Test underflow case
        let result = sub_mod(U256::from(5), U256::from(10));
        assert_eq!(result, MODULUS - U256::from(5));
    }

    #[test]
    fn test_mul_mod_small() {
        let a = U256::from(5);
        let b = U256::from(10);
        let result = mul_mod(a, b);
        assert_eq!(result, U256::from(50));
    }

    #[test]
    fn test_mul_mod_zero() {
        let a = U256::from(12345);
        let result = mul_mod(a, U256::zero());
        assert_eq!(result, U256::zero());
        
        let result = mul_mod(U256::zero(), a);
        assert_eq!(result, U256::zero());
    }

    #[test]
    fn test_mul_mod_one() {
        let a = U256::from(12345);
        let result = mul_mod(a, U256::one());
        assert_eq!(result, a);
    }

    #[test]
    fn test_mul_mod_large() {
        // Test with large values
        let a = MODULUS - U256::from(1);
        let b = U256::from(2);
        let result = mul_mod(a, b);
        // (p-1) * 2 = 2p - 2 ≡ -2 ≡ p - 2 (mod p)
        assert_eq!(result, MODULUS - U256::from(2));
    }

    #[test]
    fn test_neg_mod() {
        let a = U256::from(5);
        let result = neg_mod(a);
        assert_eq!(result, MODULUS - U256::from(5));
        
        // Double negation should give original
        let double_neg = neg_mod(result);
        assert_eq!(double_neg, a);
        
        // Negation of zero is zero
        assert_eq!(neg_mod(U256::zero()), U256::zero());
    }

    #[test]
    fn test_sqr_mod() {
        let a = U256::from(5);
        let result = sqr_mod(a);
        assert_eq!(result, U256::from(25));
    }

    #[test]
    fn test_pow_mod() {
        let base = U256::from(2);
        let exp = U256::from(10);
        let result = pow_mod(base, exp);
        assert_eq!(result, U256::from(1024));
        
        // Test power of zero
        let result = pow_mod(base, U256::zero());
        assert_eq!(result, U256::one());
        
        // Test zero to any power
        let result = pow_mod(U256::zero(), U256::from(5));
        assert_eq!(result, U256::zero());
    }

    #[test]
    fn test_inv_mod() {
        // Test with small values
        let a = U256::from(5);
        let inv = inv_mod(a);
        // a * inv(a) = 1 (mod p)
        let product = mul_mod(a, inv);
        assert_eq!(product, U256::one(), "5 * inv(5) should equal 1 mod p");
        
        // Test with another value
        let a = U256::from(123);
        let inv = inv_mod(a);
        let product = mul_mod(a, inv);
        assert_eq!(product, U256::one(), "123 * inv(123) should equal 1 mod p");
        
        // Test with a large value
        let a = MODULUS - U256::from(1);
        let inv = inv_mod(a);
        let product = mul_mod(a, inv);
        assert_eq!(product, U256::one(), "(p-1) * inv(p-1) should equal 1 mod p");
    }

    #[test]
    #[should_panic(expected = "Cannot invert zero")]
    fn test_inv_mod_zero_panics() {
        inv_mod(U256::zero());
    }

    #[test]
    fn test_div_mod() {
        let a = U256::from(20);
        let b = U256::from(5);
        let result = div_mod(a, b);
        assert_eq!(result, U256::from(4), "20 / 5 should equal 4");
        
        // Test that a / b * b = a
        let product = mul_mod(result, b);
        assert_eq!(product, a, "(a / b) * b should equal a");
        
        // Test with larger values
        let a = U256::from(1000);
        let b = U256::from(7);
        let result = div_mod(a, b);
        let product = mul_mod(result, b);
        assert_eq!(product, a, "(1000 / 7) * 7 should equal 1000");
    }

    #[test]
    #[should_panic(expected = "Division by zero")]
    fn test_div_mod_zero_panics() {
        div_mod(U256::from(5), U256::zero());
    }

    #[test]
    fn test_bytes_conversion() {
        let value = U256::from(12345);
        let bytes = to_bytes_be(value);
        let recovered = from_bytes_be(&bytes);
        assert_eq!(recovered, value);
    }

    #[test]
    fn test_field_properties() {
        let a = U256::from(123);
        let b = U256::from(456);
        let c = U256::from(789);
        
        // Test associativity: (a + b) + c = a + (b + c)
        let left = add_mod(add_mod(a, b), c);
        let right = add_mod(a, add_mod(b, c));
        assert_eq!(left, right);
        
        // Test commutativity: a + b = b + a
        assert_eq!(add_mod(a, b), add_mod(b, a));
        assert_eq!(mul_mod(a, b), mul_mod(b, a));
        
        // Test distributivity: a * (b + c) = a*b + a*c
        let left = mul_mod(a, add_mod(b, c));
        let right = add_mod(mul_mod(a, b), mul_mod(a, c));
        assert_eq!(left, right);
        
        // Test additive identity
        assert_eq!(add_mod(a, U256::zero()), a);
        
        // Test multiplicative identity
        assert_eq!(mul_mod(a, U256::one()), a);
        
        // Test additive inverse
        let neg_a = neg_mod(a);
        assert_eq!(add_mod(a, neg_a), U256::zero());
    }

    #[test]
    fn test_modulus_boundary() {
        // Test operations at the modulus boundary
        let almost_mod = MODULUS - U256::one();
        
        // Adding 1 should wrap to 0
        assert_eq!(add_mod(almost_mod, U256::one()), U256::zero());
        
        // Subtracting from 0 should wrap to p-1
        assert_eq!(sub_mod(U256::zero(), U256::one()), almost_mod);
    }
}
