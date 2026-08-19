use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};

use x25519_adekvat::PrivateKey as AdekvatPrivateKey;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};

const ALICE_KEY: [u8; 32] = [0x42; 32];
const BOB_KEY: [u8; 32] = [0x69; 32];

fn benchmark_public_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("X25519/public_key");

    let adekvat_private = AdekvatPrivateKey::new(ALICE_KEY);
    let dalek_private = StaticSecret::from(ALICE_KEY);

    group.bench_function("x25519_adekvat", |b| {
        b.iter(|| {
            black_box(adekvat_private.public_key());
        });
    });

    group.bench_function("x25519_dalek", |b| {
        b.iter(|| {
            black_box(DalekPublicKey::from(&dalek_private));
        });
    });

    group.finish();
}

fn benchmark_shared_secret(c: &mut Criterion) {
    let mut group = c.benchmark_group("X25519/shared_secret");

    let adekvat_alice = AdekvatPrivateKey::new(ALICE_KEY);
    let adekvat_bob = AdekvatPrivateKey::new(BOB_KEY);

    let adekvat_bob_public = adekvat_bob.public_key();

    let dalek_alice = StaticSecret::from(ALICE_KEY);
    let dalek_bob = StaticSecret::from(BOB_KEY);

    let dalek_bob_public = DalekPublicKey::from(&dalek_bob);

    group.bench_function("x25519_adekvat", |b| {
        b.iter(|| {
            black_box(
                adekvat_alice
                    .derive_shared_secret(black_box(&adekvat_bob_public)),
            );
        });
    });

    group.bench_function("x25519_dalek", |b| {
        b.iter(|| {
            black_box(
                dalek_alice
                    .diffie_hellman(black_box(&dalek_bob_public)),
            );
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_public_key,
    benchmark_shared_secret
);

criterion_main!(benches);