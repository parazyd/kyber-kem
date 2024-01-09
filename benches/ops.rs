/* This file is part of Kyber-KEM (https://github.com/parazyd/kyber-kem)
 *
 * Copyright (C) 2023-2024 Dyne.org foundation
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

use kyber_kem::{kem_decrypt_1024, kem_decrypt_512, kem_decrypt_768};
use kyber_kem::{kem_encrypt_1024, kem_encrypt_512, kem_encrypt_768};
use kyber_kem::{kem_keypair_1024, kem_keypair_512, kem_keypair_768};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("kem_keypair_512", |b| {
        b.iter(|| kem_keypair_512(&mut OsRng))
    });

    c.bench_function("kem_keypair_768", |b| {
        b.iter(|| kem_keypair_768(&mut OsRng))
    });

    c.bench_function("kem_keypair_1024", |b| {
        b.iter(|| kem_keypair_1024(&mut OsRng))
    });

    c.bench_function("kem_encrypt_512", |b| {
        let (_, pk) = kem_keypair_512(&mut OsRng);
        b.iter(|| kem_encrypt_512(pk, &mut OsRng))
    });

    c.bench_function("kem_encrypt_768", |b| {
        let (_, pk) = kem_keypair_768(&mut OsRng);
        b.iter(|| kem_encrypt_768(pk, &mut OsRng))
    });

    c.bench_function("kem_encrypt_1024", |b| {
        let (_, pk) = kem_keypair_1024(&mut OsRng);
        b.iter(|| kem_encrypt_1024(pk, &mut OsRng))
    });

    c.bench_function("kem_decrypt_512", |b| {
        let (sk, pk) = kem_keypair_512(&mut OsRng);
        let (ct, _) = kem_encrypt_512(pk, &mut OsRng);
        b.iter(|| kem_decrypt_512(ct, sk));
    });

    c.bench_function("kem_decrypt_768", |b| {
        let (sk, pk) = kem_keypair_768(&mut OsRng);
        let (ct, _) = kem_encrypt_768(pk, &mut OsRng);
        b.iter(|| kem_decrypt_768(ct, sk));
    });

    c.bench_function("kem_decrypt_1024", |b| {
        let (sk, pk) = kem_keypair_1024(&mut OsRng);
        let (ct, _) = kem_encrypt_1024(pk, &mut OsRng);
        b.iter(|| kem_decrypt_1024(ct, sk));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
