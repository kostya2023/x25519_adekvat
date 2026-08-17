use crate::math::{constants::P, field::element::FieldElement};
use crypto_bigint::{CtSelect, Limb};

/// Adds two field elements modulo `2^255 - 19` in constant time.
///
/// Computes:
///
/// `a + b mod p`
///
/// where `p = 2^255 - 19`.
///
/// The reduction is performed without secret-dependent branches by using
/// constant-time conditional selection.
///
/// # Arguments
///
/// * `a` - The first field element.
/// * `b` - The second field element.
///
/// # Returns
///
/// The canonical field element representing `a + b (mod p)`.
///
/// # Constant-time
///
/// This operation uses constant-time arithmetic and conditional selection.
/// It does not branch on the values of the field elements.
#[inline(always)]
pub fn field_add_ct(a: FieldElement, b: FieldElement) -> FieldElement {
    let (sum, _carry) = a.carrying_add(&b, Limb::ZERO);
    let (reduced, borrow) = sum.borrowing_sub(&P, Limb::ZERO);

    let borrow_choice = !borrow.lsb_to_choice();
    FieldElement::ct_select(&sum, &reduced, borrow_choice)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::math::constants::P;
    use crypto_bigint::U256;

    #[test]
    fn add_without_reduction() {
        let a = U256::from_u8(10);
        let b = U256::from_u8(20);

        assert_eq!(field_add_ct(a, b), U256::from_u8(30));
    }

    #[test]
    fn add_exactly_p() {
        let a = P - U256::from_u8(1);
        let b = U256::from_u8(1);

        assert_eq!(field_add_ct(a, b), U256::ZERO);
    }

    #[test]
    fn add_with_reduction() {
        let a = P - U256::from_u8(10);
        let b = U256::from_u8(20);

        assert_eq!(field_add_ct(a, b), U256::from_u8(10));
    }

    #[test]
    fn add_zero() {
        let a = U256::from_u8(123);

        assert_eq!(field_add_ct(a, U256::ZERO), a);
    }
}
