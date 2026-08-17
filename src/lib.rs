#![no_std]
#![doc = include_str!("../README.md")]

#[cfg(test)]
extern crate std;

pub(crate) mod math;
pub(crate) mod private_key;
pub(crate) mod public_key;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum X25519Error {
    #[cfg(feature = "random")]
    #[error("random number generation failed")]
    GenRandomError,
}

pub use private_key::PrivateKey;
pub use public_key::PublicKey;
