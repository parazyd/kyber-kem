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

pub(crate) const N: usize = 256;
pub(crate) const Q: usize = 3329;
pub(crate) const Q_INV: usize = 62209;
pub(crate) const SYM_BYTES: usize = 32;
pub(crate) const POLY_BYTES: usize = 384;
pub(crate) const ETA_K512: usize = 3;
pub(crate) const ETA_K768_K1024: usize = 2;
pub(crate) const POLYVEC_BYTES_K512: usize = 2 * POLY_BYTES;
pub(crate) const POLYVEC_BYTES_K768: usize = 3 * POLY_BYTES;
pub(crate) const POLYVEC_BYTES_K1024: usize = 4 * POLY_BYTES;
pub(crate) const POLY_COMPRESSED_BYTES_K512: usize = 128;
pub(crate) const POLY_COMPRESSED_BYTES_K768: usize = 128;
pub(crate) const POLY_COMPRESSED_BYTES_K1024: usize = 160;
pub(crate) const POLYVEC_COMPRESSED_BYTES_K512: usize = 2 * 320;
pub(crate) const POLYVEC_COMPRESSED_BYTES_K768: usize = 3 * 320;
pub(crate) const POLYVEC_COMPRESSED_BYTES_K1024: usize = 4 * 352;
pub(crate) const INDCPA_PUBLICKEY_BYTES_K512: usize = POLYVEC_BYTES_K512 + SYM_BYTES;
pub(crate) const INDCPA_PUBLICKEY_BYTES_K768: usize = POLYVEC_BYTES_K768 + SYM_BYTES;
pub(crate) const INDCPA_PUBLICKEY_BYTES_K1024: usize = POLYVEC_BYTES_K1024 + SYM_BYTES;
pub(crate) const INDCPA_SECRETKEY_BYTES_K512: usize = 2 * POLY_BYTES;
pub(crate) const INDCPA_SECRETKEY_BYTES_K768: usize = 3 * POLY_BYTES;
pub(crate) const INDCPA_SECRETKEY_BYTES_K1024: usize = 4 * POLY_BYTES;

/// Byte length of secret keys in Kyber-512.
pub const KYBER512_SK_BYTES: usize =
    POLYVEC_BYTES_K512 + ((POLYVEC_BYTES_K512 + SYM_BYTES) + 2 * SYM_BYTES);

/// Byte length of secret keys in Kyber-768.
pub const KYBER768_SK_BYTES: usize =
    POLYVEC_BYTES_K768 + ((POLYVEC_BYTES_K768 + SYM_BYTES) + 2 * SYM_BYTES);

/// Byte length of secret keys in Kyber-1024.
pub const KYBER1024_SK_BYTES: usize =
    POLYVEC_BYTES_K1024 + ((POLYVEC_BYTES_K1024 + SYM_BYTES) + 2 * SYM_BYTES);

/// Byte length of public keys in Kyber-512.
pub const KYBER512_PK_BYTES: usize = POLYVEC_BYTES_K512 + SYM_BYTES;

/// Byte length of public keys in Kyber-768.
pub const KYBER768_PK_BYTES: usize = POLYVEC_BYTES_K768 + SYM_BYTES;

/// Byte length of public keys in Kyber-1024.
pub const KYBER1024_PK_BYTES: usize = POLYVEC_BYTES_K1024 + SYM_BYTES;

/// Byte length of ciphertexts in Kyber-512.
pub const KYBER512_CT_BYTES: usize = POLYVEC_COMPRESSED_BYTES_K512 + POLY_COMPRESSED_BYTES_K512;

/// Byte length of ciphertexts in Kyber-768.
pub const KYBER768_CT_BYTES: usize = POLYVEC_COMPRESSED_BYTES_K768 + POLY_COMPRESSED_BYTES_K768;

/// Byte length of ciphertexts in Kyber-1024.
pub const KYBER1024_CT_BYTES: usize = POLYVEC_COMPRESSED_BYTES_K1024 + POLY_COMPRESSED_BYTES_K1024;

/// Byte length of shared secrets in Kyber.
pub const KYBER_SS_BYTES: usize = 32;
