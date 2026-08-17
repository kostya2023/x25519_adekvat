use crypto_bigint::U256;

/// The standard X25519 Montgomery curve base point.
///
/// The canonical Curve25519 base point has the `u`-coordinate `9`.
pub const BASEPOINT: U256 = U256::from_u8(9);

/// The prime modulus of the Curve25519 finite field.
///
/// `p = 2^255 - 19`.
pub const P: U256 =
    U256::from_be_hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED");

/// The Montgomery ladder constant `a24`.
///
/// For Curve25519:
///
/// `a24 = (486662 - 2) / 4 = 121665`.
///
/// This constant is used during the differential addition and doubling
/// formulas of the Montgomery ladder.
pub const A24: U256 = U256::from_u32(121665);
