use std::hint::black_box;
use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand_core::Rng;
use x25519_adekvat::PrivateKey;

/// Generate a random 32-byte secret scalar.
fn random_key(rng: &mut BenchRng) -> [u8; 32] {
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    key
}

/// Test X25519 public-key generation.
///
/// Left distribution:
///     fixed all-zero secret
///
/// Right distribution:
///     random secret
///
/// Both classes execute exactly the same public_key() operation.
/// Dudect checks whether their timing distributions are distinguishable.
fn public_key(runner: &mut CtRunner, rng: &mut BenchRng) {
    const SAMPLES: usize = 100_000;

    let mut inputs = Vec::with_capacity(SAMPLES);
    let mut classes = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            inputs.push([0u8; 32]);
            classes.push(Class::Left);
        } else {
            inputs.push(random_key(rng));
            classes.push(Class::Right);
        }
    }

    for (class, key) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            let private_key = PrivateKey::new(key);

            black_box(private_key.public_key());
        });
    }
}

/// Test X25519 shared-secret derivation.
///
/// The peer public key is identical for both classes.
/// Only the secret private scalar changes.
///
/// Left distribution:
///     fixed all-zero secret
///
/// Right distribution:
///     random secret
fn shared_secret(runner: &mut CtRunner, rng: &mut BenchRng) {
    const SAMPLES: usize = 100_000;

    // Fixed peer key.
    let peer_private = PrivateKey::new([0x42u8; 32]);
    let peer_public = peer_private.public_key();

    let mut inputs = Vec::with_capacity(SAMPLES);
    let mut classes = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            inputs.push([0u8; 32]);
            classes.push(Class::Left);
        } else {
            inputs.push(random_key(rng));
            classes.push(Class::Right);
        }
    }

    for (class, key) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            let private_key = PrivateKey::new(key);

            black_box(
                private_key.derive_shared_secret(&peer_public),
            );
        });
    }
}

ctbench_main!(
    public_key,
    shared_secret
);