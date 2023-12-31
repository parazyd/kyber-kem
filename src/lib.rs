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

//! Implementation of the [Kyber](https://pq-crystals.org/kyber) IND-CCA2
//! secure key encapsulation mechanism (KEM)
//!
//! **Example usage:**
//~
//! ```rust
//! use rand::rngs::OsRng;
//! use kyber_kem::{kem_keypair_1024, kem_encrypt_1024, kem_decrypt_1024};
//!
//! let (secret_key, public_key) = kem_keypair_1024(&mut OsRng);
//! let (ciphertext, shared_secret) = kem_encrypt_1024(public_key, &mut OsRng);
//! let dec_shared_secret = kem_decrypt_1024(ciphertext, secret_key);
//! assert_eq!(shared_secret, dec_shared_secret);
//! ```

/// Library constants
pub mod params;

/// Byte operations
mod byteops;

/// IND-CPA operations
mod indcpa;

/// Number-theoretic transforms
mod ntt;

/// Polynomial operations
mod poly;

/// Kyber IND-CCA2-secure key encapsulation mechanism (KEM)
mod kem;
pub use kem::{kem_decrypt_1024, kem_decrypt_512, kem_decrypt_768};
pub use kem::{kem_encrypt_1024, kem_encrypt_512, kem_encrypt_768};
pub use kem::{kem_keypair_1024, kem_keypair_512, kem_keypair_768};

#[cfg(test)]
mod tests;
