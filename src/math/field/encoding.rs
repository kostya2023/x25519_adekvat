use crate::math::field::element::FieldElement;

/// Encodes a field element into its canonical 32-byte little-endian representation.
///
/// The field element is serialized as a fixed-size 32-byte array using
/// little-endian byte order.
///
/// # Arguments
///
/// * `x` - The field element to encode.
///
/// # Returns
///
/// A 32-byte little-endian representation of the field element.
///
/// # Endianness
///
/// The output uses little-endian byte order, with the least significant byte
/// stored at index `0`.
#[inline(always)]
pub fn field_encode(x: FieldElement) -> [u8; 32] {
    x.to_le_bytes().into()
}

/// Decodes a 32-byte little-endian representation into a field element.
///
/// The input is interpreted as an unsigned 256-bit integer in little-endian
/// byte order.
///
/// # Arguments
///
/// * `bytes` - A 32-byte little-endian representation of a field element.
///
/// # Returns
///
/// The decoded [`FieldElement`].
///
/// # Endianness
///
/// The input is interpreted using little-endian byte order, with the least
/// significant byte stored at index `0`.
#[inline(always)]
pub fn field_decode(bytes: &[u8; 32]) -> FieldElement {
    FieldElement::from_le_slice(bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto_bigint::U256;

    #[test]
    fn encode_zero() {
        assert_eq!(field_encode(U256::ZERO), [0u8; 32]);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let value =
            U256::from_be_hex("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");

        assert_eq!(field_decode(&field_encode(value)), value);
    }

    #[test]
    fn little_endian() {
        let value = U256::from_u8(1);
        let encoded = field_encode(value);

        assert_eq!(encoded[0], 1);
        assert!(encoded[1..].iter().all(|&byte| byte == 0));
    }
}
