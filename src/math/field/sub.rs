use crate::math::{constants::P, field::element::FieldElement};
use crypto_bigint::{CtSelect, Limb};

/// Subtracts two field elements modulo `2^255 - 19` in constant time.
///
/// Computes:
///
/// `a - b mod p`
///
/// where `p = 2^255 - 19`.
///
/// If the subtraction underflows, the field modulus is added back to obtain
/// the corresponding canonical field element.
///
/// # Arguments
///
/// * `a` - The field element to subtract from.
/// * `b` - The field element to subtract.
///
/// # Returns
///
/// The canonical field element representing `a - b (mod p)`.
///
/// # Constant-time
///
/// This operation uses constant-time arithmetic and conditional selection.
/// It does not branch on the values of the field elements.
#[inline(always)]
pub fn field_sub_ct(a: FieldElement, b: FieldElement) -> FieldElement {
    let (sub, borrow) = a.borrowing_sub(&b, Limb::ZERO);
    let (reduced, _carry) = sub.carrying_add(&P, Limb::ZERO);

    let borrow_choice = borrow.lsb_to_choice();
    FieldElement::ct_select(&sub, &reduced, borrow_choice)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::math::constants::P;
    use crypto_bigint::U256;

    #[test]
    fn sub_without_underflow() {
        let a = U256::from_u8(20);
        let b = U256::from_u8(10);

        assert_eq!(field_sub_ct(a, b), U256::from_u8(10));
    }

    #[test]
    fn sub_with_underflow() {
        let a = U256::from_u8(10);
        let b = U256::from_u8(20);

        assert_eq!(field_sub_ct(a, b), P - U256::from_u8(10));
    }

    #[test]
    fn sub_zero() {
        let a = U256::from_u8(123);

        assert_eq!(field_sub_ct(a, U256::ZERO), a);
    }

    #[test]
    fn sub_equal() {
        let a = U256::from_u8(42);

        assert_eq!(field_sub_ct(a, a), U256::ZERO);
    }
}
