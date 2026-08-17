use crate::math::field::{element::FieldElement, mul::field_mul_ct, square::field_square_ct};

#[inline(always)]
fn square_n(mut x: FieldElement, n: usize) -> FieldElement {
    for _ in 0..n {
        x = field_square_ct(x);
    }

    x
}

/// Computes the multiplicative inverse of a field element modulo `2^255 - 19`
/// in constant time.
///
/// Computes:
///
/// `a^(p - 2) mod p`
///
/// where `p = 2^255 - 19`.
///
/// The inversion is performed using a fixed addition chain based on repeated
/// squaring and multiplication. This avoids variable-time algorithms such as
/// the extended Euclidean algorithm.
///
/// # Arguments
///
/// * `a` - The field element to invert.
///
/// # Returns
///
/// The field element `a⁻¹` satisfying:
///
/// `a * a⁻¹ ≡ 1 (mod p)`
///
/// for every non-zero field element `a`.
///
/// For `a = 0`, the function returns `0`.
///
/// # Constant-time
///
/// This operation uses a fixed sequence of field squarings and
/// multiplications. Its execution does not depend on the value of the
/// field element.
///
/// # Zero
///
/// Zero has no multiplicative inverse. For compatibility with the field
/// arithmetic used by X25519, this function returns zero when given zero.
#[inline(always)]
pub fn field_invert_ct(a: FieldElement) -> FieldElement {
    let z2 = field_square_ct(a);
    let z4 = field_square_ct(z2);
    let z8 = field_square_ct(z4);

    let z9 = field_mul_ct(z8, a);
    let z11 = field_mul_ct(z9, z2);

    let z22 = field_square_ct(z11);
    let z_2_5_minus_1 = field_mul_ct(z22, z9);

    let z_2_10_minus_1 = {
        let x = square_n(z_2_5_minus_1, 5);
        field_mul_ct(x, z_2_5_minus_1)
    };

    let z_2_20_minus_1 = {
        let x = square_n(z_2_10_minus_1, 10);
        field_mul_ct(x, z_2_10_minus_1)
    };

    let z_2_40_minus_1 = {
        let x = square_n(z_2_20_minus_1, 20);
        field_mul_ct(x, z_2_20_minus_1)
    };

    let z_2_50_minus_1 = {
        let x = square_n(z_2_40_minus_1, 10);
        field_mul_ct(x, z_2_10_minus_1)
    };

    let z_2_100_minus_1 = {
        let x = square_n(z_2_50_minus_1, 50);
        field_mul_ct(x, z_2_50_minus_1)
    };

    let z_2_200_minus_1 = {
        let x = square_n(z_2_100_minus_1, 100);
        field_mul_ct(x, z_2_100_minus_1)
    };

    let z_2_250_minus_1 = {
        let x = square_n(z_2_200_minus_1, 50);
        field_mul_ct(x, z_2_50_minus_1)
    };

    let x = square_n(z_2_250_minus_1, 5);
    field_mul_ct(x, z11)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::math::constants::P;
    use crypto_bigint::U256;

    #[test]
    fn invert_one() {
        assert_eq!(field_invert_ct(U256::ONE), U256::ONE);
    }

    #[test]
    fn invert_two() {
        let a = U256::from_u8(2);
        let inverse = field_invert_ct(a);

        assert_eq!(field_mul_ct(a, inverse), U256::ONE);
    }

    #[test]
    fn invert_large_value() {
        let a = P - U256::from_u8(2);
        let inverse = field_invert_ct(a);

        assert_eq!(field_mul_ct(a, inverse), U256::ONE);
    }

    #[test]
    fn invert_multiplicative_identity() {
        let a = U256::from_u8(123);
        let inverse = field_invert_ct(a);

        assert_eq!(field_mul_ct(a, inverse), U256::ONE);
    }

    #[test]
    fn invert_zero() {
        assert_eq!(field_invert_ct(U256::ZERO), U256::ZERO);
    }
}
