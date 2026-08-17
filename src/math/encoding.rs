use crate::math::field::{
    element::FieldElement,
    encoding::{field_decode, field_encode},
};

/// Decodes and clamps a 32-byte X25519 scalar.
///
/// The scalar is decoded according to RFC 7748 by applying the X25519
/// clamping operation:
///
/// * Clears the three least significant bits of the first byte.
/// * Clears the most significant bit of the last byte.
/// * Sets the second most significant bit of the last byte.
///
/// This ensures that the scalar has the required form for the X25519
/// Montgomery ladder.
///
/// # Arguments
///
/// * `scalar` - A 32-byte scalar in little-endian representation.
///
/// # Returns
///
/// The clamped 32-byte scalar in little-endian representation.
#[inline(always)]
pub fn decode_scalar(mut scalar: [u8; 32]) -> [u8; 32] {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    scalar
}

/// Decodes a 32-byte X25519 `u`-coordinate.
///
/// The input is interpreted as a little-endian field element. The most
/// significant bit is ignored as required by RFC 7748 for X25519 inputs.
///
/// # Arguments
///
/// * `u` - A 32-byte `u`-coordinate in little-endian representation.
///
/// # Returns
///
/// The decoded [`FieldElement`] representing the `u`-coordinate.
#[inline(always)]
pub fn decode_u(mut u: [u8; 32]) -> FieldElement {
    u[31] &= 127;

    field_decode(&u)
}

/// Encodes an X25519 `u`-coordinate into its 32-byte representation.
///
/// The field element is serialized in little-endian byte order as required
/// by RFC 7748.
///
/// # Arguments
///
/// * `u` - The field element to encode.
///
/// # Returns
///
/// A 32-byte little-endian representation of the `u`-coordinate.
#[inline(always)]
pub fn encode_u(u: FieldElement) -> [u8; 32] {
    field_encode(u)
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto_bigint::U256;

    #[test]
    fn decode_scalar_clamps_low_bits() {
        let scalar = [0xff; 32];
        let scalar = decode_scalar(scalar);

        assert_eq!(scalar[0], 0xf8);
    }

    #[test]
    fn decode_scalar_clamps_high_bits() {
        let scalar = [0xff; 32];
        let scalar = decode_scalar(scalar);

        assert_eq!(scalar[31], 0x7f);
    }

    #[test]
    fn decode_u_clears_high_bit() {
        let mut bytes = [0xff; 32];
        bytes[31] &= 127;

        assert_eq!(decode_u([0xff; 32]), U256::from_le_slice(&bytes));
    }

    #[test]
    fn encode_decode_u_roundtrip() {
        let value =
            U256::from_be_hex("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");

        assert_eq!(decode_u(encode_u(value)), value);
    }
}
