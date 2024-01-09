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

use rand::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Reset, Update, XofReader};
use sha3::{Digest, Sha3_512, Shake128, Shake256};

use crate::params::*;
use crate::poly::{Poly, PolyVec};

/// Serializes the public key as a concatenation of the serialized vector
/// of polynomials of the public key, and the public seed used to generate
/// the matrix `A`.
fn pack_public_key<const K: usize>(public_key: PolyVec<K>, seed: &[u8]) -> Vec<u8> {
    let mut r = vec![];
    r.extend_from_slice(&PolyVec::to_bytes(public_key));
    r.extend_from_slice(seed);
    r
}

/// Deserializes the public key from a byte array and represents the
/// approximate inverse of `pack_public_key`.
fn unpack_public_key<const K: usize>(packed_pk: &[u8]) -> (PolyVec<K>, Vec<u8>) {
    match K {
        2 => {
            let pk_polyvec = PolyVec::from_bytes(&packed_pk[..POLYVEC_BYTES_K512]);
            let seed = packed_pk[POLYVEC_BYTES_K512..].to_vec();
            (pk_polyvec, seed)
        }

        3 => {
            let pk_polyvec = PolyVec::from_bytes(&packed_pk[..POLYVEC_BYTES_K768]);
            let seed = packed_pk[POLYVEC_BYTES_K768..].to_vec();
            (pk_polyvec, seed)
        }

        _ => {
            let pk_polyvec = PolyVec::from_bytes(&packed_pk[..POLYVEC_BYTES_K1024]);
            let seed = packed_pk[POLYVEC_BYTES_K1024..].to_vec();
            (pk_polyvec, seed)
        }
    }
}

/// Serializes the secret key
fn pack_secret_key<const K: usize>(secret_key: PolyVec<K>) -> Vec<u8> {
    PolyVec::to_bytes(secret_key)
}

/// Deserializes the secret key and represents the inverse of `pack_secret_key`.
fn unpack_secret_key<const K: usize>(packed_sk: &[u8]) -> PolyVec<K> {
    PolyVec::from_bytes(packed_sk)
}

/// Serializes the ciphertext as a concatenation of the compressed and
/// serialized vector of polynomials `b` and the compressed and serialized
/// polynomial `v`.
fn pack_ciphertext<const K: usize>(b: PolyVec<K>, v: Poly) -> Vec<u8> {
    let mut b = b;
    let mut buf = vec![];
    buf.extend_from_slice(&PolyVec::compress(&mut b));
    buf.extend_from_slice(&Poly::compress::<K>(v));
    buf
}

/// Deserializes and decompresses the ciphertext from a byte array, and
/// represents the approximate inverse of `pack_ciphertext`.
fn unpack_ciphertext<const K: usize>(c: &[u8]) -> (PolyVec<K>, Poly) {
    match K {
        2 => {
            let b = PolyVec::decompress(&c[..POLYVEC_COMPRESSED_BYTES_K512]);
            let v = Poly::decompress::<K>(&c[POLYVEC_COMPRESSED_BYTES_K512..]);
            (b, v)
        }

        3 => {
            let b = PolyVec::decompress(&c[..POLYVEC_COMPRESSED_BYTES_K768]);
            let v = Poly::decompress::<K>(&c[POLYVEC_COMPRESSED_BYTES_K768..]);
            (b, v)
        }

        _ => {
            let b = PolyVec::decompress(&c[..POLYVEC_COMPRESSED_BYTES_K1024]);
            let v = Poly::decompress::<K>(&c[POLYVEC_COMPRESSED_BYTES_K1024..]);
            (b, v)
        }
    }
}

/// Runs rejection sampling on uniform random bytres to generate uniform
/// random integers modulo `Q`.
fn rej_uniform(buf: &[u8], bufl: usize, l: usize) -> (Poly, usize) {
    let mut r = Poly::new();

    let mut i = 0;
    let mut j = 0;

    while i < l && j + 3 <= bufl {
        let d1 = ((buf[j] as u16) | ((buf[j + 1] as u16) << 8)) & 0xFFF;
        let d2 = (((buf[j + 1] >> 4) as u16) | ((buf[j + 2] as u16) << 4)) & 0xFFF;

        j += 3;

        if d1 < (Q as u16) {
            r[i] = d1 as i16;
            i += 1;
        }

        if i < l && d2 < (Q as u16) {
            r[i] = d2 as i16;
            i += 1;
        }
    }

    (r, i)
}

/// Deterministically generates a matrix `A` (or the transpose of `A`)
/// from a seed. Entries of the matrix are polynomials that look uniformly
/// random. Performs rejection sampling on the output of an extendable-output
/// function (XOF).
fn gen_matrix<const K: usize>(seed: &[u8], transposed: bool) -> [PolyVec<K>; K] {
    let mut r = [PolyVec::new(); K];
    let mut buf = [0u8; 672];
    let mut xof = Shake128::default();
    let mut ctr;

    #[allow(clippy::needless_range_loop)]
    for i in 0..K {
        r[i] = PolyVec::new();
        for j in 0..K {
            xof.reset();

            if transposed {
                xof.update(&[seed, &[i as u8, j as u8]].concat());
            } else {
                xof.update(&[seed, &[j as u8, i as u8]].concat());
            }

            let mut reader = xof.clone().finalize_xof();
            reader.read(&mut buf);

            (r[i][j], ctr) = rej_uniform(&buf[..504], 504, N);
            while ctr < N {
                let (missing, ctrn) = rej_uniform(&buf[504..672], 168, N - ctr);
                let mut k = ctr;
                while k < N {
                    r[i][j][k] = missing[k - ctr];
                    k += 1;
                }
                ctr += ctrn
            }
        }
    }

    r
}

/// Provides a pseudo-random function (PRF) which returns a byte array of
/// length `l`, using the provided key and nonce to instantiate the PRF's
/// underlying hash function.
pub(crate) fn prf(l: usize, key: &[u8], nonce: u8) -> Vec<u8> {
    let mut hash = vec![0u8; l];

    let mut concat = vec![];
    concat.extend_from_slice(key);
    concat.push(nonce);

    let mut hasher = Shake256::default();
    hasher.update(&concat);

    let mut reader = hasher.finalize_xof();
    reader.read(&mut hash);
    hash
}

/// Generates public and secret keys for the CPA-secure puiblic-key
/// encryption scheme underlying Kyber.
pub(crate) fn keypair<const K: usize>(rng: &mut (impl RngCore + CryptoRng)) -> (Vec<u8>, Vec<u8>) {
    let mut skpv: PolyVec<K> = PolyVec::new();
    let mut pkpv: PolyVec<K> = PolyVec::new();
    let mut e: PolyVec<K> = PolyVec::new();
    let mut buf = [0u8; 2 * SYM_BYTES];

    let mut h = Sha3_512::new();
    rng.fill_bytes(&mut buf[..SYM_BYTES]);
    sha3::Digest::update(&mut h, &buf[..SYM_BYTES]);

    buf = h.finalize().into();
    let public_seed = &buf[..SYM_BYTES];
    let noise_seed = &buf[SYM_BYTES..];

    let a = gen_matrix::<K>(public_seed, false);

    let mut nonce = 0u8;
    for i in 0..K {
        skpv[i] = Poly::get_noise::<K>(noise_seed, nonce);
        nonce += 1;
    }

    for i in 0..K {
        e[i] = Poly::get_noise::<K>(noise_seed, nonce);
        nonce += 1;
    }

    PolyVec::ntt(&mut skpv);
    PolyVec::reduce(&mut skpv);
    PolyVec::ntt(&mut e);

    for i in 0..K {
        pkpv[i] = Poly::to_mont(PolyVec::pointwise_acc_montgomery(a[i], skpv));
    }

    PolyVec::add(&mut pkpv, e);
    PolyVec::reduce(&mut pkpv);

    (pack_secret_key(skpv), pack_public_key(pkpv, public_seed))
}

/// Encryption function of the CPA-secure public-key encryption
/// scheme underlying Kyber.
pub(crate) fn encrypt<const K: usize>(m: &[u8], public_key: &[u8], coins: &[u8]) -> Vec<u8> {
    let mut sp: PolyVec<K> = PolyVec::new();
    let mut ep: PolyVec<K> = PolyVec::new();
    let mut bp: PolyVec<K> = PolyVec::new();

    let (pkpv, seed) = unpack_public_key::<K>(public_key);

    let k = Poly::from_msg(m);

    let at = gen_matrix::<K>(&seed[..SYM_BYTES], true);

    for i in 0..K {
        sp[i] = Poly::get_noise::<K>(coins, i as u8);
        ep[i] = Poly::get_noise::<3>(coins, (i + K) as u8);
    }

    let epp = Poly::get_noise::<3>(coins, (K * 2) as u8);

    PolyVec::ntt(&mut sp);
    PolyVec::reduce(&mut sp);

    for i in 0..K {
        bp[i] = PolyVec::pointwise_acc_montgomery(at[i], sp);
    }

    let mut v = PolyVec::pointwise_acc_montgomery(pkpv, sp);
    PolyVec::inv_ntt_to_mont(&mut bp);
    v = Poly::inv_ntt_to_mont(v);

    PolyVec::add(&mut bp, ep);
    v = Poly::add(Poly::add(v, epp), k);

    PolyVec::reduce(&mut bp);

    pack_ciphertext(bp, Poly::reduce(v))
}

/// Decryption function of the CPA-secure public-key
/// encryption scheme underlying Kyber.
pub(crate) fn decrypt<const K: usize>(c: &[u8], secret_key: &[u8]) -> [u8; 32] {
    let (mut bp, v) = unpack_ciphertext::<K>(c);
    let skpv = unpack_secret_key::<K>(secret_key);

    PolyVec::ntt(&mut bp);

    let mut mp = PolyVec::pointwise_acc_montgomery(skpv, bp);
    mp = Poly::inv_ntt_to_mont(mp);
    mp = Poly::sub(v, mp);
    mp = Poly::reduce(mp);
    Poly::to_msg(mp)
}
