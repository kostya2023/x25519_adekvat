use crate::math::{
    encoding::{decode_scalar, decode_u, encode_u},
    ladder::montgomery_ladder,
};

/// Computes the X25519 function as specified by RFC 7748.
///
/// X25519 performs scalar multiplication of a Montgomery curve point using
/// the supplied scalar and `u`-coordinate.
///
/// Before the Montgomery ladder is executed, the scalar is decoded and
/// clamped according to the X25519 rules, and the input `u`-coordinate is
/// decoded according to RFC 7748.
///
/// # Arguments
///
/// * `scalar` - A 32-byte scalar in little-endian representation.
/// * `u` - A 32-byte Montgomery `u`-coordinate in little-endian
///   representation.
///
/// # Returns
///
/// The 32-byte little-endian encoding of the resulting Montgomery
/// `u`-coordinate.
///
/// # Constant-time
///
/// The underlying scalar multiplication uses the constant-time Montgomery
/// ladder and constant-time field arithmetic. No secret-dependent branches
/// are used.
///
/// # RFC 7748
///
/// This function implements the X25519 primitive defined in RFC 7748,
/// including scalar clamping, `u`-coordinate decoding, Montgomery ladder
/// scalar multiplication, and result encoding.
pub fn x25519(scalar: [u8; 32], u: [u8; 32]) -> [u8; 32] {
    let scalar = decode_scalar(scalar);
    let u = decode_u(u);

    let result = montgomery_ladder(&scalar, u);

    encode_u(result)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn x25519_rfc7748() {
        let scalar = [
            0xa0, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
            0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
            0xba, 0x44, 0x9a, 0xc4,
        ];

        let u = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1,
            0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6,
            0xd0, 0xab, 0x1c, 0x4c,
        ];

        let expected = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
            0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
            0x77, 0xa2, 0x85, 0x52,
        ];

        assert_eq!(x25519(scalar, u), expected);
    }

    #[test]
    fn x25519_basepoint() {
        let scalar = [
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];

        let mut basepoint = [0u8; 32];
        basepoint[0] = 9;

        let result = x25519(scalar, basepoint);

        // После clamping scalar = 2^254.
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn x25519_diffie_hellman() {
        let alice_private = [0x11u8; 32];
        let bob_private = [0x22u8; 32];

        let mut basepoint = [0u8; 32];
        basepoint[0] = 9;

        let alice_public = x25519(alice_private, basepoint);
        let bob_public = x25519(bob_private, basepoint);

        let alice_shared = x25519(alice_private, bob_public);
        let bob_shared = x25519(bob_private, alice_public);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn x25519_zero_u() {
        let scalar = [0x42u8; 32];
        let u = [0u8; 32];

        let result = x25519(scalar, u);

        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn x25519_accepts_non_canonical_u() {
        let scalar = [0x42u8; 32];

        let mut u = [0xffu8; 32];
        u[31] = 0x7f;

        let result = x25519(scalar, u);

        assert_eq!(result.len(), 32);
    }

    #[test]
    fn x25519_rfc7748_1000_iterations() {
        let mut k = [0u8; 32];
        k[0] = 9;

        let mut u = k;

        for _ in 0..1000 {
            let old_k = k;

            k = x25519(k, u);
            u = old_k;
        }

        assert_eq!(
            k,
            [
                0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55, 0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f,
                0x4d, 0x3c, 0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87, 0x5f, 0x2e, 0xb9, 0x4d,
                0x99, 0x53, 0x2c, 0x51,
            ]
        );
    }
}
