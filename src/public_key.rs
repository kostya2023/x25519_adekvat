/// An X25519 public key.
///
/// An X25519 public key is the 32-byte encoded Montgomery `u`-coordinate
/// produced by scalar multiplication of the Curve25519 base point.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey {
    pub key: [u8; 32],
}

impl PublicKey {
    /// Creates a public key from its 32-byte encoded representation.
    ///
    /// The bytes are stored exactly as provided and are not modified or
    /// validated.
    ///
    /// # Arguments
    ///
    /// * `key` - The 32-byte encoded X25519 public key.
    #[inline]
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Returns the 32-byte encoded representation of the public key.
    ///
    /// The returned value is a copy of the stored key.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_preserves_key() {
        let bytes = [0x42u8; 32];
        let key = PublicKey::new(bytes);

        assert_eq!(key.key, bytes);
    }

    #[test]
    fn to_bytes_returns_key() {
        let bytes = [0xABu8; 32];
        let key = PublicKey::new(bytes);

        assert_eq!(key.to_bytes(), bytes);
    }
}
