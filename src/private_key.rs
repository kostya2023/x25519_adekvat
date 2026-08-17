use crate::PublicKey;
use crate::math::constants::BASEPOINT;
use crate::math::x25519::x25519;

#[cfg(feature = "random")]
use rand::TryRng;

#[cfg(feature = "random")]
use crate::X25519Error;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrivateKey {
    pub key: [u8; 32],
}

impl PrivateKey {
    /// Creates a private X25519 key from a 32-byte scalar.
    ///
    /// The scalar is stored exactly as provided. Scalar clamping is performed
    /// internally by x25519 when the key is used for scalar
    /// multiplication.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte private scalar.
    #[inline]
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Returns the raw 32-byte private key.
    ///
    /// The returned value is a copy of the internal key material.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key
    }

    /// Generates a new private X25519 key using the supplied random number
    /// generator.
    ///
    /// The generator must implement [`rand::TryRng`].
    ///
    /// # Errors
    ///
    /// Returns [`X25519Error::GenRandomError`] if the random number generator
    /// fails to produce the required 32 bytes.
    #[cfg(feature = "random")]
    #[inline]
    pub fn new_with_random<Rng: TryRng>(rng: &mut Rng) -> Result<Self, X25519Error> {
        let mut key = [0u8; 32];
        rng.try_fill_bytes(&mut key)
            .map_err(|_| X25519Error::GenRandomError)?;
        Ok(Self { key })
    }

    /// Derives the X25519 public key corresponding to this private key.
    ///
    /// This performs scalar multiplication of the Curve25519 base point
    /// using this private scalar.
    ///
    /// # Returns
    ///
    /// The corresponding [`PublicKey`].
    ///
    /// # Constant-time
    ///
    /// The underlying X25519 operation uses constant-time scalar
    /// multiplication and field arithmetic.
    #[inline]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            key: x25519(self.key, BASEPOINT.to_le_bytes().into()),
        }
    }

    /// Derives a shared X25519 secret from this private key and another
    /// party's public key.
    ///
    /// Computes:
    ///
    /// `X25519(private_key, another_public_key)`
    ///
    /// Both parties obtain the same shared secret when using their own
    /// private key and the other party's public key.
    ///
    /// # Arguments
    ///
    /// * `another_public_key` - The other party's X25519 public key.
    ///
    /// # Returns
    ///
    /// A 32-byte shared secret.
    ///
    /// # Constant-time
    ///
    /// The underlying X25519 operation uses constant-time scalar
    /// multiplication and field arithmetic.
    ///
    /// # Security
    ///
    /// The returned secret is raw X25519 output. Applications should normally
    /// pass it through an appropriate key derivation function before using it
    /// as a symmetric encryption key.
    #[inline]
    pub fn derive_shared_secret(&self, another_public_key: &PublicKey) -> [u8; 32] {
        x25519(self.key, another_public_key.key)
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for PrivateKey {
    /// Clears the private key material from memory.
    ///
    /// After this call, the stored key is replaced with zeroes.
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_preserves_key() {
        let bytes = [0x42u8; 32];
        let key = PrivateKey::new(bytes);

        assert_eq!(key.key, bytes);
    }

    #[test]
    fn to_bytes_returns_key() {
        let bytes = [0xABu8; 32];
        let key = PrivateKey::new(bytes);

        assert_eq!(key.to_bytes(), bytes);
    }

    #[test]
    fn public_key_is_deterministic() {
        let private_key = PrivateKey::new([0x42u8; 32]);

        assert_eq!(private_key.public_key(), private_key.public_key());
    }

    #[test]
    fn public_key_matches_x25519() {
        let private_bytes = [0x42u8; 32];
        let private_key = PrivateKey::new(private_bytes);

        let expected = x25519(private_bytes, BASEPOINT.to_le_bytes().into());

        assert_eq!(private_key.public_key().key, expected);
    }

    #[test]
    fn shared_secret_is_symmetric() {
        let alice = PrivateKey::new([0x11u8; 32]);
        let bob = PrivateKey::new([0x22u8; 32]);

        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        let alice_secret = alice.derive_shared_secret(&bob_public);
        let bob_secret = bob.derive_shared_secret(&alice_public);

        assert_eq!(alice_secret, bob_secret);
    }

    #[cfg(feature = "zeroize")]
    #[test]
    fn zeroize_clears_key() {
        let mut key = PrivateKey::new([0xFFu8; 32]);

        key.zeroize();

        assert_eq!(key.key, [0u8; 32]);
    }
}
