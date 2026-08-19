# x25519_adekvat

A small, constant-time-oriented and fully `no_std` implementation of
**X25519** in Rust.

Designed to provide a simple API for public-key generation and
Diffie–Hellman shared-secret derivation.

## Features

* 🔐 X25519 / RFC 7748
* ⚡ Constant-time-oriented implementation
* 🦀 Pure Rust
* `no_std` support
* 🎲 Optional random private-key generation
* 🧹 Optional private-key zeroization
* 🧪 RFC 7748 test vectors
* 📦 Small public API

## Installation

```toml
[dependencies]
x25519_adekvat = "1.0.0-beta.1"
````

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

## Benches

Yeah, `x25519_adekvat` is slower. A lot slower. :D

| Operation     | x25519_adekvat | x25519-dalek |
| ------------- | -------------: | -----------: |
| Public key    |        ~355 µs |       ~25 µs |
| Shared secret |        ~355 µs |       ~41 µs |

So why is it slower?

`x25519_adekvat` currently uses a straightforward Montgomery ladder
implementation in pure Rust without precomputed tables or
architecture-specific assembly.

The goal is not to win the benchmark. The goal is to keep the
implementation simple, portable, and constant-time-oriented by design.

> "Yeah, we're slower. At least we know exactly what we're doing." :D

The implementation is additionally tested with `dudect` for timing
leakage and manually inspected at the generated assembly level.

**Note:** These benchmarks are not a security comparison between the
two libraries. They only compare performance under the tested
configuration.

## Constant-Time Analysis

`x25519_adekvat` is designed to avoid secret-dependent control flow,
memory accesses, and table lookups.

The implementation is tested using
[`dudect`](https://github.com/oreparaz/dudect)
and the generated optimized assembly is manually inspected.

### Dudect

Latest test results:

| Operation       | Samples |      max t |    max tau | Result                |
| --------------- | ------: | ---------: | ---------: | --------------------- |
| `public_key`    |    ~72K | `-2.01710` | `-0.00749` | ✅ No leakage detected |
| `shared_secret` |    ~98K | `+2.72872` | `+0.00872` | ✅ No leakage detected |

Both tests produced an absolute `t` statistic below the commonly used
`|t| = 5` threshold.

```text
public_key
    n == +0.072M
    max t = -2.01710
    max tau = -0.00749

shared_secret
    n == +0.098M
    max t = +2.72872
    max tau = +0.00872
```

These results mean that `dudect` did not detect a statistically
significant timing difference between the tested secret-input
distributions.

### Assembly Analysis

The optimized assembly was manually inspected for:

* ❌ Secret-dependent conditional branches
* ❌ Secret-dependent memory accesses
* ❌ Secret-indexed lookup tables
* ❌ Variable-iteration loops
* ✅ Branchless conditional operations (`CMOV` / bitwise masking)
* ✅ Fixed 255-iteration Montgomery ladder

The X25519 implementation does not use precomputed tables for the
Montgomery ladder.

> **Note:** Neither `dudect` nor manual assembly inspection constitutes
> a formal proof of constant-time execution. These results apply to the
> tested build, compiler, target, and hardware.

## Security

X25519 provides **key agreement**, not authentication.

A real protocol should authenticate public keys and derive encryption
keys from the shared secret using a suitable KDF such as HKDF.

Private keys should never be logged, transmitted, or exposed
unnecessarily.

The core implementation is designed around constant-time arithmetic
and branchless conditional operations for secret-dependent
computations.

## Testing

The implementation is tested against RFC 7748 vectors, including the
1000-iteration test.

Run the full test suite:

```bash
cargo test
```

Run benchmarks:

```bash
cargo bench
```

Run the constant-time analysis:

```bash
cargo run --release --example constant_time
```

## MSRV

Rust 1.85+

## License

Licensed under the MIT License.

