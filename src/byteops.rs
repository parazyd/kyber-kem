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

use crate::params::*;
use crate::poly::Poly;

/// Returns a 32-bit unsigned integer loaded from `x`.
fn load32(x: &[u8]) -> u32 {
    let mut r = x[0] as u32;
    r |= (x[1] as u32) << 8;
    r |= (x[2] as u32) << 16;
    r |= (x[3] as u32) << 24;
    r
}

/// Returns a 32-bit unsigned integer loaded from `x`.
fn load24(x: &[u8]) -> u32 {
    let mut r = x[0] as u32;
    r |= (x[1] as u32) << 8;
    r |= (x[2] as u32) << 16;
    r
}

/// Computes a polynomial with coefficients distributed according
/// to a centered binomial distribution with parameter eta, given
/// an array of uniformly random bytes.
pub(crate) fn cbd<const K: usize>(buf: &[u8]) -> Poly {
    let mut r = Poly::new();

    match K {
        2 => {
            for i in 0..N / 4 {
                let t = load24(&buf[3 * i..]);
                let mut d = t & 0x00249249;
                d += (t >> 1) & 0x00249249;
                d += (t >> 2) & 0x00249249;
                for j in 0..4 {
                    let a = ((d >> (6 * j)) & 0x7) as i16;
                    let b = ((d >> (6 * j + ETA_K512)) & 0x07) as i16;
                    r[4 * i + j] = a - b;
                }
            }
        }

        _ => {
            for i in 0..N / 8 {
                let t = load32(&buf[4 * i..]);
                let mut d = t & 0x55555555;
                d += (t >> 1) & 0x55555555;
                for j in 0..8 {
                    let a = ((d >> (4 * j)) & 0x03) as i16;
                    let b = ((d >> (4 * j + ETA_K768_K1024)) & 0x03) as i16;
                    r[8 * i + j] = a - b;
                }
            }
        }
    }

    r
}

/// Computes a Montgomery reduction; give a 32-bit integer `a`,
/// returns `a * R^-1 mod Q` where `R=2^16`.
pub(crate) fn montgomery_reduce(a: i32) -> i16 {
    let u = (a as i64 * (Q_INV as i64)) as i16;
    let mut t = u as i32 * Q as i32;
    t = a - t;
    t >>= 16;
    t as i16
}

/// Computes a Barrett reduction; given a 16-bit integer `a`,
/// returns a 16-bit integer congruent to `a mod Q` in {0,...Q}.
pub(crate) fn barrett_reduce(a: i16) -> i16 {
    let v = (((1_u32 << 26) + ((Q / 2) as u32)) / Q as u32) as i16;
    let mut t = ((v as i32 * a as i32) >> 26) as i16;
    t *= Q as i16;
    a - t
}

/// Conditionally suibtracts Q from a
pub(crate) fn c_sub_q(a: i16) -> i16 {
    let mut a = a - Q as i16;
    a = a + ((a >> 15) & Q as i16);
    a
}
