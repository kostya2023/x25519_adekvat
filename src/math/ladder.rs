use crate::math::{
    constants::A24,
    field::{
        add::field_add_ct, element::FieldElement, invert::field_invert_ct, mul::field_mul_ct,
        square::field_square_ct, sub::field_sub_ct,
    },
};
use crypto_bigint::{Choice, CtSelect};

/// Computes a conditional swap of two field elements in constant time.
///
/// If `choice` is `1`, the values of `a` and `b` are exchanged. If `choice`
/// is `0`, they remain unchanged.
///
/// This operation is used by the Montgomery ladder to prevent secret scalar
/// bits from affecting control flow.
///
/// # Arguments
///
/// * `a` - The first field element.
/// * `b` - The second field element.
/// * `choice` - The constant-time condition controlling the swap.
///
/// # Constant-time
///
/// The swap is performed using [`CtSelect`] and does not branch on the
/// value of `choice`.
#[inline(always)]
fn cswap(a: &mut FieldElement, b: &mut FieldElement, choice: Choice) {
    let x = FieldElement::ct_select(a, b, choice);
    let y = FieldElement::ct_select(b, a, choice);

    *a = x;
    *b = y;
}

/// Performs one differential addition and doubling step of the Montgomery
/// ladder.
///
/// Given the projective coordinates `(x2, z2)` and `(x3, z3)`, and the
/// original `u`-coordinate `x1`, this function computes the next ladder
/// state using the Curve25519 Montgomery differential addition and doubling
/// formulas.
///
/// The formulas are:
///
/// `A = X2 + Z2`
///
/// `AA = A²`
///
/// `B = X2 - Z2`
///
/// `BB = B²`
///
/// `E = AA - BB`
///
/// `C = X3 + Z3`
///
/// `D = X3 - Z3`
///
/// `DA = D × A`
///
/// `CB = C × B`
///
/// `X3 = (DA + CB)²`
///
/// `Z3 = X1 × (DA - CB)²`
///
/// `X2 = AA × BB`
///
/// `Z2 = E × (AA + A24 × E)`
///
/// where `A24 = 121665` for Curve25519.
///
/// # Arguments
///
/// * `x1` - The input `u`-coordinate of the Montgomery curve point.
/// * `x2` - The projective `X` coordinate of the doubling point.
/// * `z2` - The projective `Z` coordinate of the doubling point.
/// * `x3` - The projective `X` coordinate of the differential addition point.
/// * `z3` - The projective `Z` coordinate of the differential addition point.
///
/// # Constant-time
///
/// All field operations are constant-time, and this function contains no
/// secret-dependent branches.
///
/// This operation is used internally by [`montgomery_ladder`].
#[inline(always)]
fn ladder_step(
    x1: FieldElement,
    x2: &mut FieldElement,
    z2: &mut FieldElement,
    x3: &mut FieldElement,
    z3: &mut FieldElement,
) {
    let x2_value = *x2;
    let z2_value = *z2;
    let x3_value = *x3;
    let z3_value = *z3;

    // A = x2 + z2
    let a = field_add_ct(x2_value, z2_value);

    // AA = A²
    let aa = field_square_ct(a);

    // B = x2 - z2
    let b = field_sub_ct(x2_value, z2_value);

    // BB = B²
    let bb = field_square_ct(b);

    // E = AA - BB
    let e = field_sub_ct(aa, bb);

    // C = x3 + z3
    let c = field_add_ct(x3_value, z3_value);

    // D = x3 - z3
    let d = field_sub_ct(x3_value, z3_value);

    // DA = D × A
    let da = field_mul_ct(d, a);

    // CB = C × B
    let cb = field_mul_ct(c, b);

    // x3 = (DA + CB)²
    let da_plus_cb = field_add_ct(da, cb);
    *x3 = field_square_ct(da_plus_cb);

    // z3 = x1 × (DA - CB)²
    let da_minus_cb = field_sub_ct(da, cb);
    let da_minus_cb_square = field_square_ct(da_minus_cb);
    *z3 = field_mul_ct(x1, da_minus_cb_square);

    // x2 = AA × BB
    *x2 = field_mul_ct(aa, bb);

    // z2 = E × (AA + a24 × E)
    let a24_times_e = field_mul_ct(A24, e);
    let aa_plus_a24_times_e = field_add_ct(aa, a24_times_e);
    *z2 = field_mul_ct(e, aa_plus_a24_times_e);
}

/// Computes scalar multiplication on Curve25519 using the Montgomery ladder.
///
/// Computes the `u`-coordinate of:
///
/// `scalar × u`
///
/// using the Montgomery ladder specified by RFC 7748.
///
/// The scalar is expected to already be decoded and clamped according to the
/// X25519 scalar decoding rules. The ladder processes exactly 255 scalar bits
/// from the most significant bit to the least significant bit.
///
/// # Arguments
///
/// * `scalar` - A clamped 32-byte X25519 scalar in little-endian representation.
/// * `u` - The input Montgomery `u`-coordinate.
///
/// # Returns
///
/// The resulting Montgomery `u`-coordinate as a [`FieldElement`].
///
/// # Constant-time
///
/// The ladder uses constant-time conditional swaps and constant-time field
/// arithmetic. The scalar bits are never used for secret-dependent branching.
///
/// # RFC 7748
///
/// This function implements the Montgomery ladder used by X25519. Scalar
/// clamping and `u`-coordinate decoding are performed separately by the
/// X25519 encoding layer before calling this function.
#[inline(always)]
pub fn montgomery_ladder(scalar: &[u8; 32], u: FieldElement) -> FieldElement {
    let x1 = u;

    let mut x2 = FieldElement::ONE;
    let mut z2 = FieldElement::ZERO;

    let mut x3 = x1;
    let mut z3 = FieldElement::ONE;

    let mut swap = Choice::from(0u8);

    for t in (0..255).rev() {
        let k_t = Choice::from((scalar[t / 8] >> (t & 7)) & 1);

        swap ^= k_t;

        cswap(&mut x2, &mut x3, swap);
        cswap(&mut z2, &mut z3, swap);

        swap = k_t;

        ladder_step(x1, &mut x2, &mut z2, &mut x3, &mut z3);
    }

    cswap(&mut x2, &mut x3, swap);
    cswap(&mut z2, &mut z3, swap);

    let z2_inv = field_invert_ct(z2);
    field_mul_ct(x2, z2_inv)
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto_bigint::U256;

    #[test]
    fn cswap_false() {
        let mut a = U256::from_u8(10);
        let mut b = U256::from_u8(20);

        cswap(&mut a, &mut b, Choice::from(0));

        assert_eq!(a, U256::from_u8(10));
        assert_eq!(b, U256::from_u8(20));
    }

    #[test]
    fn cswap_true() {
        let mut a = U256::from_u8(10);
        let mut b = U256::from_u8(20);

        cswap(&mut a, &mut b, Choice::from(1));

        assert_eq!(a, U256::from_u8(20));
        assert_eq!(b, U256::from_u8(10));
    }

    #[test]
    fn ladder_zero_scalar() {
        let scalar = [0u8; 32];
        let result = montgomery_ladder(&scalar, U256::from_u8(9));

        assert_eq!(result, U256::ZERO);
    }

    #[test]
    fn ladder_zero_u() {
        let scalar = [0u8; 32];
        let result = montgomery_ladder(&scalar, U256::ZERO);

        assert_eq!(result, U256::ZERO);
    }

    #[test]
    fn ladder_one_scalar() {
        let mut scalar = [0u8; 32];
        scalar[0] = 1;

        let result = montgomery_ladder(&scalar, U256::from_u8(9));

        assert_eq!(result, U256::from_u8(9));
    }

    #[test]
    fn ladder_rfc7748() {
        let mut scalar = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
            0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
            0xba, 0x44, 0x9a, 0xc4,
        ];

        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        let u =
            U256::from_le_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");

        let expected =
            U256::from_le_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        assert_eq!(montgomery_ladder(&scalar, u), expected);
    }
}
