/* This file is part of Kyber-KEM (https://github.com/parazyd/kyber-kem)
 *
 * Copyright (C) 2023 Dyne.org foundation
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

use crate::byteops;
use crate::poly::Poly;

pub(crate) const NTT_ZETAS: [i16; 128] = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855, 1468, 573,
    2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017, 732, 608, 1787, 411, 3124, 1758, 1223, 652,
    2777, 1015, 2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239,
    3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226, 430, 555,
    843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 778, 1159, 3182,
    2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254, 817, 1097, 603, 610, 1322,
    2044, 1864, 384, 2114, 3193, 1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819,
    2475, 2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
];

pub(crate) const NTT_ZETAS_INV: [i16; 128] = [
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535, 1278, 1530, 1185,
    1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
    75, 156, 3000, 2911, 2980, 872, 2685, 1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676,
    1755, 460, 291, 235, 3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275,
    2652, 1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853, 1860, 3203,
    1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552, 2677, 2106, 1571, 205, 2918,
    1542, 2721, 2597, 2312, 681, 130, 1602, 1871, 829, 2946, 3065, 1325, 2756, 1861, 1474, 1202,
    2367, 3147, 1752, 2707, 171, 3127, 3042, 1907, 1836, 1517, 359, 758, 1441,
];

/// Performs multiplication followed by Montgomery reduction
/// and returns a 16-bit integer congruent to `a*b*R^{-1} mod Q`.
fn ntt_fq_mul(a: i16, b: i16) -> i16 {
    byteops::montgomery_reduce(a as i32 * b as i32)
}

/// Performs an in-place number-theoretic transform (NTT) in `Rq`.
/// The input is in standard order, the output is in bit-reversed order.
pub(crate) fn ntt(r: Poly) -> Poly {
    let mut r = r;
    let mut k = 1;
    let mut l = 128;

    while l >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = NTT_ZETAS[k];
            k += 1;

            let mut j = start;
            while j < start + l {
                let t = ntt_fq_mul(zeta, r[j + l]);
                r[j + l] = r[j] - t;
                r[j] += t;

                j += 1;
            }

            start = j + l;
        }

        l >>= 1;
    }

    r
}

/// Performs an in-place inverse number-theoretic transform (NTT)
/// in `Rq` and multiplication by Montgomery factor 2^16.
/// The input is in bit-reversed order, the output is in standard order.
pub(crate) fn ntt_inv(r: Poly) -> Poly {
    let mut r = r;

    let mut k = 0;
    let mut l = 2;

    while l <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = NTT_ZETAS_INV[k];
            k += 1;
            let mut j = start;
            while j < start + l {
                let t = r[j];
                r[j] = byteops::barrett_reduce(t + r[j + l]);
                r[j + l] = t - r[j + l];
                r[j + l] = ntt_fq_mul(zeta, r[j + l]);

                j += 1;
            }

            start = j + l;
        }

        l <<= 1;
    }

    for j in 0..256 {
        r[j] = ntt_fq_mul(r[j], NTT_ZETAS_INV[127]);
    }

    r
}

/// Performs the multiplication of polynomials in `Zq[X]/(X^2-zeta)`. Used for
/// multiplication of elements in `Rq` in the number-theoretic transform domain.
pub(crate) fn base_mul(a0: i16, a1: i16, b0: i16, b1: i16, zeta: i16) -> [i16; 2] {
    let mut r = [0; 2];

    r[0] = ntt_fq_mul(a1, b1);
    r[0] = ntt_fq_mul(r[0], zeta);
    r[0] += ntt_fq_mul(a0, b0);
    r[1] = ntt_fq_mul(a0, b1);
    r[1] += ntt_fq_mul(a1, b0);
    r
}
