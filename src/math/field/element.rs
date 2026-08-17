use crypto_bigint::U256;

/// An element of the Curve25519 prime field.
///
/// `FieldElement` represents an unsigned 256-bit integer used for arithmetic
/// in the finite field defined by the prime:
///
/// `p = 2^255 - 19`.
///
/// This type is an alias for [`U256`] from `crypto_bigint`.
pub type FieldElement = U256;
