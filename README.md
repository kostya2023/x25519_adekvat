# x25519_adekvat

A small, constant-time and `no_std`-friendly implementation of **X25519** in Rust.

Designed to provide a simple API for public-key generation and Diffie–Hellman shared-secret derivation.

## Features

* 🔐 X25519 / RFC 7748
* ⚡ Constant-time implementation
* 🦀 Pure Rust
* `no_std` support
* 🎲 Optional random private-key generation
* 🧹 Optional private-key zeroization
* 🧪 RFC 7748 test vectors
* 📦 Small public API

## Installation

```toml
[dependencies]
x25519_adekvat = "0.1"
```

## Quick Start

```rust
use x25519_adekvat::PrivateKey;

let alice = PrivateKey::new([0x11; 32]);
let bob = PrivateKey::new([0x22; 32]);

let alice_public = alice.public_key();
let bob_public = bob.public_key();

let alice_secret = alice.derive_shared_secret(&bob_public);
let bob_secret = bob.derive_shared_secret(&alice_public);

assert_eq!(alice_secret, bob_secret);
```

Both parties now have the same 32-byte shared secret.

## Random Keys

With the `random` feature:

```rust
use x25519_adekvat::PrivateKey;

let mut rng = rand::rngs::SysRng::new();

let private_key = PrivateKey::new_with_random(&mut rng)?;
```

The RNG is provided by the caller.

## Zeroization

Enable the `zeroize` feature to clear private-key material:

```rust
use zeroize::Zeroize;

let mut key = PrivateKey::new([0xFF; 32]);

key.zeroize();
```

## API

### `PrivateKey`

```rust
PrivateKey::new([u8; 32]) -> PrivateKey
PrivateKey::to_bytes() -> [u8; 32]
PrivateKey::public_key() -> PublicKey
PrivateKey::derive_shared_secret(&PublicKey) -> [u8; 32]
```

With the `random` feature:

```rust
PrivateKey::new_with_random(...)
```

### `PublicKey`

```rust
PublicKey::new([u8; 32]) -> PublicKey
PublicKey::to_bytes() -> [u8; 32]
```

## Security

X25519 provides **key agreement**, not authentication.

A real protocol should authenticate public keys and derive encryption keys from the shared secret using a suitable KDF such as HKDF.

Private keys should never be logged, transmitted, or exposed unnecessarily.

The core implementation uses constant-time arithmetic and conditional operations for secret-dependent computations.

## Testing

The implementation is tested against RFC 7748 vectors, including the 1000-iteration test.

Run the full test suite:

```bash
cargo test
```

## MSRV
Rust 1.85+

## License

Licensed under the MIT License.
