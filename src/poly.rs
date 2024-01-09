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

use core::ops::{Index, IndexMut};

use crate::byteops;
use crate::indcpa;
use crate::ntt::{self, NTT_ZETAS};
use crate::params::*;

#[derive(Copy, Clone, Debug)]
/// Polynomial representation
pub(crate) struct Poly([i16; POLY_BYTES]);

impl Index<usize> for Poly {
    type Output = i16;

    fn index(&self, idx: usize) -> &Self::Output {
        &self.0[idx]
    }
}

impl IndexMut<usize> for Poly {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        &mut self.0[idx]
    }
}

impl Poly {
    /// Create a new `Poly` instance
    pub(crate) fn new() -> Poly {
        Self([0_i16; POLY_BYTES])
    }

    /// Lossily compress and subsequently serialize a polynomial
    pub(crate) fn compress<const K: usize>(a: Poly) -> Vec<u8> {
        let mut t = [0u8; 8];
        let a = Poly::c_sub_q(a);
        let mut rr = 0;

        match K {
            2 | 3 => {
                let mut r = [0u8; POLY_COMPRESSED_BYTES_K768]; // 128
                for i in 0..N / 8 {
                    for j in 0..8 {
                        t[j] = (((((a[8 * i + j] as u16) << 4) + ((Q / 2) as u16)) / Q as u16)
                            & 15u16) as u8;
                    }

                    r[rr] = t[0] | (t[1] << 4);
                    r[rr + 1] = t[2] | (t[3] << 4);
                    r[rr + 2] = t[4] | (t[5] << 4);
                    r[rr + 3] = t[6] | (t[7] << 4);
                    rr += 4;
                }

                r.to_vec()
            }

            _ => {
                let mut r = [0u8; POLY_COMPRESSED_BYTES_K1024]; // 160
                for i in 0..N / 8 {
                    for j in 0..8 {
                        t[j] = (((((a[8 * i + j] as u32) << 5) + ((Q / 2) as u32)) / Q as u32)
                            & 31u32) as u8;
                    }

                    r[rr] = (t[0]) | (t[1] << 5);
                    r[rr + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
                    r[rr + 2] = (t[3] >> 1) | (t[4] << 4);
                    r[rr + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
                    r[rr + 4] = (t[6] >> 2) | (t[7] << 3);
                    rr += 5;
                }

                r.to_vec()
            }
        }
    }

    /// Deserialize and subsequently decompress a polynomial, representing the
    /// approximate inverse of `Poly::compress`.
    /// Note that compression is lossy, and thus decompression will not match
    /// the original input.
    pub(crate) fn decompress<const K: usize>(a: &[u8]) -> Poly {
        let mut r = Poly::new();
        let mut t = [0u8; 8];
        let mut aa = 0;

        match K {
            2 | 3 => {
                for i in 0..N / 2 {
                    r[2 * i] = (((((a[aa] & 15) as u16) * (Q as u16)) + 8) >> 4) as i16;
                    r[2 * i + 1] = (((((a[aa] >> 4) as u16) * (Q as u16)) + 8) >> 4) as i16;
                    aa += 1;
                }
            }

            4 => {
                for i in 0..N / 8 {
                    t[0] = a[aa];
                    t[1] = (a[aa] >> 5) | (a[aa + 1] << 3);
                    t[2] = a[aa + 1] >> 2;
                    t[3] = (a[aa + 1] >> 7) | (a[aa + 2] << 1);
                    t[4] = (a[aa + 2] >> 4) | (a[aa + 3] << 4);
                    t[5] = a[aa + 3] >> 1;
                    t[6] = (a[aa + 3] >> 6) | (a[aa + 4] << 2);
                    t[7] = a[aa + 4] >> 3;
                    aa += 5;
                    for j in 0..8 {
                        r[8 * i + j] = (((((t[j] & 31) as u32) * (Q as u32)) + 16) >> 5) as i16;
                    }
                }
            }

            _ => {}
        }

        r
    }

    /// Serializes a polynomial into an array of bytes.
    pub(crate) fn to_bytes(a: Poly) -> [u8; POLY_BYTES] {
        let mut r = [0u8; POLY_BYTES];
        let a = Poly::c_sub_q(a);

        for i in 0..N / 2 {
            let t0 = a[2 * i] as u16;
            let t1 = a[2 * i + 1] as u16;
            r[3 * i] = t0 as u8;
            r[3 * i + 1] = (t0 >> 8) as u8 | (t1 << 4) as u8;
            r[3 * i + 2] = (t1 >> 4) as u8;
        }

        r
    }

    /// Deserializes an array of bytes into a polynomial, and represents
    /// the inverse of `Poly::to_bytes`.
    pub(crate) fn from_bytes(a: &[u8]) -> Poly {
        let mut r = Poly::new();

        for i in 0..N / 2 {
            r[2 * i] = (((a[3 * i] as u16) | ((a[3 * i + 1] as u16) << 8)) & 0xFFF) as i16;

            r[2 * i + 1] =
                ((((a[3 * i + 1] as u16) >> 4) | ((a[3 * i + 2] as u16) << 4)) & 0xFFF) as i16;
        }

        r
    }

    /// Converts a 32-byte message to a polynomial.
    pub(crate) fn from_msg(msg: &[u8]) -> Poly {
        let mut r = Poly::new();

        for i in 0..N / 8 {
            for j in 0..8 {
                let mask = -(((msg[i] >> j) & 1) as i16);
                r[8 * i + j] = mask & ((Q + 1) / 2) as i16;
            }
        }

        r
    }

    /// Converts a polynomial to a 32-byte message and represents
    /// the inverse of `Poly::from_msg`.
    pub(crate) fn to_msg(a: Poly) -> [u8; SYM_BYTES] {
        let mut msg = [0u8; SYM_BYTES];
        let a = Poly::c_sub_q(a);

        for i in 0..N / 8 {
            msg[i] = 0;
            for j in 0..8 {
                let mut t = (((a[8 * i + j]) as u32) << 1) + Q_DIV_BY_2_CEIL;
                t = ((t * Q_POLY_TO_MSG) >> 28) & 1;
                msg[i] |= (t << j) as u8;
            }
        }

        msg
    }

    /// Samples a polynomial deterministically from a seed and nonce, with
    /// the output polkynomial being close to a centered binomial distribution.
    pub(crate) fn get_noise<const K: usize>(seed: &[u8], nonce: u8) -> Poly {
        match K {
            2 => {
                let l = ETA_K512 * N / 4;
                let p = indcpa::prf(l, seed, nonce);
                byteops::cbd::<K>(&p)
            }

            _ => {
                let l = ETA_K768_K1024 * N / 4;
                let p = indcpa::prf(l, seed, nonce);
                byteops::cbd::<K>(&p)
            }
        }
    }

    /// Computes a negacyclic number-theoretic transform (NTT) of a polynomial
    /// in-place. The input is assumed to be in normal order, while the output
    /// is in bit-reversed order.
    /// XXX:
    fn ntt(r: Poly) -> Poly {
        ntt::ntt(r)
    }

    /// Computes the inverse of a negacyclic number-theoretic transform (NTT) of
    /// a polynomial in-place; the input is assumed to be in bit-reversed order,
    /// while the output is in normal order.
    /// XXX:
    pub(crate) fn inv_ntt_to_mont(r: Poly) -> Poly {
        ntt::ntt_inv(r)
    }

    /// Performs the multiplication of two polynomials in the number-theoretic
    /// transform (NTT) domain.
    fn base_mul_montgomery(a: Poly, b: Poly) -> Poly {
        let mut a = a;

        for i in 0..N / 4 {
            let rx = ntt::base_mul(
                a[4 * i],
                a[4 * i + 1],
                b[4 * i],
                b[4 * i + 1],
                NTT_ZETAS[64 + i],
            );

            let ry = ntt::base_mul(
                a[4 * i + 2],
                a[4 * i + 3],
                b[4 * i + 2],
                b[4 * i + 3],
                -NTT_ZETAS[64 + i],
            );

            a[4 * i] = rx[0];
            a[4 * i + 1] = rx[1];
            a[4 * i + 2] = ry[0];
            a[4 * i + 3] = ry[1];
        }

        a
    }

    /// Performs the in-place conversion of all coefficients of a polynomial
    /// from the normal domain to the Montgomery domain.
    pub(crate) fn to_mont(r: Poly) -> Poly {
        let mut r = r;
        let f = ((1_u64 << 32) % Q as u64) as i16;
        for i in 0..N {
            r[i] = byteops::montgomery_reduce(r[i] as i32 * f as i32);
        }
        r
    }

    /// Applies Barrett reduction to all coefficients of a polynomial.
    pub(crate) fn reduce(r: Poly) -> Poly {
        let mut r = r;
        for i in 0..N {
            r[i] = byteops::barrett_reduce(r[i]);
        }
        r
    }

    /// Applies the conditional subtraction of `Q` to each coefficient
    /// of a polynomial
    fn c_sub_q(r: Poly) -> Poly {
        let mut r = r;
        for i in 0..N {
            r[i] = byteops::c_sub_q(r[i]);
        }
        r
    }

    /// Adds two polynomials
    pub(crate) fn add(a: Poly, b: Poly) -> Poly {
        let mut a = a;
        for i in 0..N {
            a[i] += b[i];
        }
        a
    }

    /// Subtracts two polynomials
    pub(crate) fn sub(a: Poly, b: Poly) -> Poly {
        let mut a = a;
        for i in 0..N {
            a[i] -= b[i];
        }
        a
    }
}

#[derive(Copy, Clone, Debug)]
/// Polynomial vector representation
pub(crate) struct PolyVec<const K: usize>([Poly; K]);

impl<const K: usize> Index<usize> for PolyVec<K> {
    type Output = Poly;

    fn index(&self, idx: usize) -> &Self::Output {
        &self.0[idx]
    }
}

impl<const K: usize> IndexMut<usize> for PolyVec<K> {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        &mut self.0[idx]
    }
}

impl<const K: usize> PolyVec<K> {
    /// Create a new `PolyVec` instance
    pub fn new() -> PolyVec<K> {
        PolyVec([Poly::new(); K])
    }

    /// Lossily compress and serialize a vector of polynomials
    pub(crate) fn compress(a: &mut PolyVec<K>) -> Vec<u8> {
        PolyVec::c_sub_q(a);
        let mut rr = 0;

        let mut r = match K {
            2 => vec![0u8; POLYVEC_COMPRESSED_BYTES_K512],
            3 => vec![0u8; POLYVEC_COMPRESSED_BYTES_K768],
            4 => vec![0u8; POLYVEC_COMPRESSED_BYTES_K1024],
            _ => unimplemented!(),
        };

        match K {
            2 | 3 => {
                let mut t = [0u16; 4];
                for i in 0..K {
                    for j in 0..N / 4 {
                        #[allow(clippy::needless_range_loop)]
                        for k in 0..4 {
                            t[k] = (((((a[i][4 * j + k] as u32) << 10) + ((Q / 2) as u32))
                                / Q as u32)
                                & 0x3FF) as u16
                        }

                        r[rr] = t[0] as u8;
                        r[rr + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                        r[rr + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                        r[rr + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                        r[rr + 4] = (t[3] >> 2) as u8;
                        rr += 5
                    }
                }

                r
            }

            _ => {
                let mut t = [0u16; 8];
                for i in 0..K {
                    for j in 0..N / 8 {
                        #[allow(clippy::needless_range_loop)]
                        for k in 0..8 {
                            t[k] = (((((a[i][8 * j + k] as u32) << 11) + ((Q / 2) as u32))
                                / Q as u32)
                                & 0x7FF) as u16
                        }

                        r[rr] = t[0] as u8;
                        r[rr + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
                        r[rr + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
                        r[rr + 3] = (t[2] >> 2) as u8;
                        r[rr + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
                        r[rr + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
                        r[rr + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
                        r[rr + 7] = (t[5] >> 1) as u8;
                        r[rr + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
                        r[rr + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
                        r[rr + 10] = (t[7] >> 3) as u8;
                        rr += 11;
                    }
                }

                r
            }
        }
    }

    /// Deserializes and decompresses a vector of polynomials and represents
    /// the approximate inverse of `PolyVec::compress`. Since compression is
    /// lossy, the results of decompression will not match the original vector
    /// of polynomials.
    pub(crate) fn decompress(a: &[u8]) -> PolyVec<K> {
        let mut r = PolyVec::new();
        let mut aa = 0;

        match K {
            2 | 3 => {
                let mut t = [0u16; 4];
                for i in 0..K {
                    for j in 0..N / 4 {
                        t[0] = (a[aa] as u16) | ((a[aa + 1] as u16) << 8);
                        t[1] = ((a[aa + 1] as u16) >> 2) | ((a[aa + 2] as u16) << 6);
                        t[2] = ((a[aa + 2] as u16) >> 4) | ((a[aa + 3] as u16) << 4);
                        t[3] = ((a[aa + 3] as u16) >> 6) | ((a[aa + 4] as u16) << 2);
                        aa += 5;
                        #[allow(clippy::needless_range_loop)]
                        for k in 0..4 {
                            r[i][4 * j + k] =
                                ((((t[k] & 0x3FF) as u32) * (Q as u32) + 512) >> 10) as i16;
                        }
                    }
                }
            }

            4 => {
                let mut t = [0u16; 8];
                for i in 0..K {
                    for j in 0..N / 8 {
                        t[0] = (a[aa] as u16) | ((a[aa + 1] as u16) << 8);
                        t[1] = ((a[aa + 1] as u16) >> 3) | ((a[aa + 2] as u16) << 5);
                        t[2] = ((a[aa + 2] as u16) >> 6)
                            | ((a[aa + 3] as u16) << 2)
                            | ((a[aa + 4] as u16) << 10);
                        t[3] = ((a[aa + 4] as u16) >> 1) | ((a[aa + 5] as u16) << 7);
                        t[4] = ((a[aa + 5] as u16) >> 4) | ((a[aa + 6] as u16) << 4);
                        t[5] = ((a[aa + 6] as u16) >> 7)
                            | ((a[aa + 7] as u16) << 1)
                            | ((a[aa + 8] as u16) << 9);
                        t[6] = ((a[aa + 8] as u16) >> 2) | ((a[aa + 9] as u16) << 6);
                        t[7] = ((a[aa + 9] as u16) >> 5) | ((a[aa + 10] as u16) << 3);
                        aa += 11;
                        #[allow(clippy::needless_range_loop)]
                        for k in 0..8 {
                            r[i][8 * j + k] =
                                ((((t[k] & 0x7FF) as u32) * (Q as u32) + 1024) >> 11) as i16;
                        }
                    }
                }
            }

            _ => {}
        }

        r
    }

    /// Serializes a vector of polynomials
    pub(crate) fn to_bytes(a: PolyVec<K>) -> Vec<u8> {
        let mut r = vec![];
        for i in 0..K {
            r.extend_from_slice(&Poly::to_bytes(a[i]));
        }

        r
    }

    /// Deserializes a vector of polynomials.
    pub(crate) fn from_bytes(a: &[u8]) -> PolyVec<K> {
        let mut r = PolyVec::new();
        for i in 0..K {
            let start = i * POLY_BYTES;
            let end = (i + 1) * POLY_BYTES;
            r[i] = Poly::from_bytes(&a[start..end])
        }

        r
    }

    /// Applies forward number-theoretic transforms (NTT) to all
    /// elements of a vector of polynomials.
    pub(crate) fn ntt(r: &mut PolyVec<K>) {
        for i in 0..K {
            r[i] = Poly::ntt(r[i]);
        }
    }

    /// Applies the inverse number-theoretic transform (NTT) to all
    /// elements of a vector of polynomials and multiplies by Montgomery
    /// factor `2^16`.
    pub(crate) fn inv_ntt_to_mont(r: &mut PolyVec<K>) {
        for i in 0..K {
            r[i] = Poly::inv_ntt_to_mont(r[i]);
        }
    }

    /// Pointwise-multiplies elements of polynomial-vectors `a` and `b`,
    /// accumulates the results into `r`, and then multiplies by `2^-16`.
    pub(crate) fn pointwise_acc_montgomery(a: PolyVec<K>, b: PolyVec<K>) -> Poly {
        let mut r = Poly::base_mul_montgomery(a[0], b[0]);
        for i in 1..K {
            let t = Poly::base_mul_montgomery(a[i], b[i]);
            r = Poly::add(r, t);
        }

        Poly::reduce(r)
    }

    /// Applies Barrett reduction to each coefficient of each element of
    /// a vector of polynomials.
    pub(crate) fn reduce(r: &mut PolyVec<K>) {
        for i in 0..K {
            r[i] = Poly::reduce(r[i]);
        }
    }

    /// Applies the conditional subtraction of `Q` to each coefficient of
    /// each element of a vector of polynomials
    fn c_sub_q(r: &mut PolyVec<K>) {
        for i in 0..K {
            r[i] = Poly::c_sub_q(r[i]);
        }
    }

    /// Adds two vectors of polynomials
    pub(crate) fn add(a: &mut PolyVec<K>, b: PolyVec<K>) {
        for i in 0..K {
            a[i] = Poly::add(a[i], b[i]);
        }
    }
}
