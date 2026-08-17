use crate::math::{constants::P, field::element::FieldElement};
use crypto_bigint::{CtSelect, Limb, U256, U512};

/// Multiplies two field elements modulo `2^255 - 19` in constant time.
///
/// Computes:
///
/// `a * b mod p`
///
/// where `p = 2^255 - 19`.
///
/// The multiplication is performed using a 512-bit intermediate value.
/// Because the Curve25519 modulus satisfies `2^255 ≡ 19 (mod p)`, the
/// intermediate product is reduced by repeatedly folding the upper bits
/// back into the lower 255 bits.
///
/// # Arguments
///
/// * `a` - The first field element.
/// * `b` - The second field element.
///
/// # Returns
///
/// The canonical field element representing `a * b (mod p)`.
///
/// # Constant-time
///
/// This operation uses fixed-width arithmetic and constant-time conditional
/// selection. It does not branch on the values of the field elements.
///
/// # Reduction
///
/// The Curve25519 prime is:
///
/// `p = 2^255 - 19`
///
/// Therefore:
///
/// `2^255 ≡ 19 (mod p)`
///
/// which allows the high portion of a 512-bit product to be folded back
/// into the lower portion using multiplication by `19`.
#[inline(always)]
pub fn field_mul_ct(a: FieldElement, b: FieldElement) -> FieldElement {
    let a: U512 = a.resize();
    let b: U512 = b.resize();
    let product = a * b;

    let folded = fold_255(fold_255(product));
    let result: U256 = folded.resize();

    let (reduced, borrow) = result.borrowing_sub(&P, Limb::ZERO);

    FieldElement::ct_select(&result, &reduced, borrow.lsb_to_choice().not())
}

/// Folds the upper bits of a value above bit `254` back into the lower
/// portion using the Curve25519 relation `2^255 ≡ 19 (mod p)`.
#[inline(always)]
fn fold_255(x: U512) -> U512 {
    let mask = (U512::ONE << 255) - U512::ONE;
    let low = x & mask;
    let high = x >> 255;

    low + U512::from_u8(19) * high
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::math::constants::P;
    use crypto_bigint::U256;

    #[test]
    fn mul_zero() {
        let a = U256::from_u8(123);

        assert_eq!(field_mul_ct(a, U256::ZERO), U256::ZERO);
    }

    #[test]
    fn mul_one() {
        let a = U256::from_u8(123);

        assert_eq!(field_mul_ct(a, U256::ONE), a);
    }

    #[test]
    fn mul_without_reduction() {
        let a = U256::from_u8(10);
        let b = U256::from_u8(20);

        assert_eq!(field_mul_ct(a, b), U256::from_u8(200));
    }

    #[test]
    fn mul_with_reduction() {
        let a = P - U256::from_u8(10);
        let b = U256::from_u8(20);

        assert_eq!(field_mul_ct(a, b), P - U256::from_u8(200));
    }

    #[test]
    fn fold_without_high_bits() {
        let x = U512::from_u8(123);

        assert_eq!(fold_255(x), x);
    }

    #[test]
    fn fold_high_bits() {
        let x = (U512::ONE << 255) + U512::from_u8(10);

        assert_eq!(fold_255(x), U512::from_u8(29));
    }
}
