use crate::math::field::element::FieldElement;
use crate::math::field::mul::field_mul_ct;

/// Squares a field element modulo `2^255 - 19` in constant time.
///
/// Computes:
///
/// `a² mod p`
///
/// where `p = 2^255 - 19`.
///
/// This operation is implemented as a field multiplication of the element
/// by itself and therefore uses the same constant-time arithmetic and
/// reduction as [`field_mul_ct`].
///
/// # Arguments
///
/// * `a` - The field element to square.
///
/// # Returns
///
/// The canonical field element representing `a² (mod p)`.
///
/// # Constant-time
///
/// This operation uses the constant-time field multiplication primitive
/// and does not branch on the value of the field element.
#[inline(always)]
pub fn field_square_ct(a: FieldElement) -> FieldElement {
    field_mul_ct(a, a)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::math::constants::P;
    use crypto_bigint::U256;

    #[test]
    fn square_zero() {
        assert_eq!(field_square_ct(U256::ZERO), U256::ZERO);
    }

    #[test]
    fn square_one() {
        assert_eq!(field_square_ct(U256::ONE), U256::ONE);
    }

    #[test]
    fn square_small_value() {
        let a = U256::from_u8(12);

        assert_eq!(field_square_ct(a), U256::from_u8(144));
    }

    #[test]
    fn square_p_minus_one() {
        let a = P - U256::ONE;

        assert_eq!(field_square_ct(a), U256::ONE);
    }
}
