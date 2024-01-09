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
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake256};
use subtle::ConstantTimeEq;

use crate::indcpa;
use crate::params::*;

/// Returns a Kyber-512 secret key and a corresponding Kyber-512 public key.
pub fn kem_keypair_512(
    rng: &mut (impl RngCore + CryptoRng),
) -> ([u8; KYBER512_SK_BYTES], [u8; KYBER512_PK_BYTES]) {
    const K: usize = 2;

    let mut sk_ret = [0u8; KYBER512_SK_BYTES];
    let mut pk_ret = [0u8; KYBER512_PK_BYTES];

    let (indcpa_sk, indcpa_pk) = indcpa::keypair::<K>(rng);

    let mut pk_hasher = Sha3_256::new();
    sha3::Digest::update(&mut pk_hasher, &indcpa_pk);
    let pkh = pk_hasher.finalize();

    let mut rnd = [0u8; SYM_BYTES];
    rng.fill_bytes(&mut rnd);

    let mut sk = vec![];
    sk.extend_from_slice(&indcpa_sk);
    sk.extend_from_slice(&indcpa_pk);
    sk.extend_from_slice(&pkh);
    sk.extend_from_slice(&rnd);

    sk_ret.copy_from_slice(&sk);
    pk_ret.copy_from_slice(&indcpa_pk);

    (sk_ret, pk_ret)
}

/// Returns a Kyber-768 secret key and a corresponding Kyber-768 public key.
pub fn kem_keypair_768(
    rng: &mut (impl RngCore + CryptoRng),
) -> ([u8; KYBER768_SK_BYTES], [u8; KYBER768_PK_BYTES]) {
    const K: usize = 3;

    let mut sk_ret = [0u8; KYBER768_SK_BYTES];
    let mut pk_ret = [0u8; KYBER768_PK_BYTES];

    let (indcpa_sk, indcpa_pk) = indcpa::keypair::<K>(rng);

    let mut pk_hasher = Sha3_256::new();
    sha3::Digest::update(&mut pk_hasher, &indcpa_pk);
    let pkh = pk_hasher.finalize();

    let mut rnd = [0u8; SYM_BYTES];
    rng.fill_bytes(&mut rnd);

    let mut sk = vec![];
    sk.extend_from_slice(&indcpa_sk);
    sk.extend_from_slice(&indcpa_pk);
    sk.extend_from_slice(&pkh);
    sk.extend_from_slice(&rnd);

    sk_ret.copy_from_slice(&sk);
    pk_ret.copy_from_slice(&indcpa_pk);

    (sk_ret, pk_ret)
}

/// Returns a Kyber-1024 secret key and a corresponding Kyber-1024 public key.
pub fn kem_keypair_1024(
    rng: &mut (impl RngCore + CryptoRng),
) -> ([u8; KYBER1024_SK_BYTES], [u8; KYBER1024_PK_BYTES]) {
    const K: usize = 4;

    let mut sk_ret = [0u8; KYBER1024_SK_BYTES];
    let mut pk_ret = [0u8; KYBER1024_PK_BYTES];

    let (indcpa_sk, indcpa_pk) = indcpa::keypair::<K>(rng);

    let mut pk_hasher = Sha3_256::new();
    sha3::Digest::update(&mut pk_hasher, &indcpa_pk);
    let pkh = pk_hasher.finalize();

    let mut rnd = [0u8; SYM_BYTES];
    rng.fill_bytes(&mut rnd);

    let mut sk = vec![];
    sk.extend_from_slice(&indcpa_sk);
    sk.extend_from_slice(&indcpa_pk);
    sk.extend_from_slice(&pkh);
    sk.extend_from_slice(&rnd);

    sk_ret.copy_from_slice(&sk);
    pk_ret.copy_from_slice(&indcpa_pk);

    (sk_ret, pk_ret)
}

/// Takes a Kyber-512 public key as input and returns a ciphertext and
/// a 32-byte shared secret.
pub fn kem_encrypt_512(
    public_key: [u8; KYBER512_PK_BYTES],
    rng: &mut (impl RngCore + CryptoRng),
) -> ([u8; KYBER512_CT_BYTES], [u8; KYBER_SS_BYTES]) {
    const K: usize = 2;

    let mut ct_ret = [0u8; KYBER512_CT_BYTES];
    let mut ss_ret = [0u8; KYBER_SS_BYTES];

    let mut shared_secret = [0u8; SYM_BYTES];

    let mut buf = [0u8; 2 * SYM_BYTES];
    rng.fill_bytes(&mut buf[..SYM_BYTES]);

    let mut hasher1 = Sha3_256::new();
    sha3::Digest::update(&mut hasher1, &buf[..SYM_BYTES]);
    let buf1 = hasher1.finalize();

    let mut hasher2 = Sha3_256::new();
    sha3::Digest::update(&mut hasher2, public_key);
    let buf2 = hasher2.finalize();

    let mut kr_hasher = Sha3_512::new();
    let mut kr_buf = vec![];
    kr_buf.extend_from_slice(&buf1);
    kr_buf.extend_from_slice(&buf2);
    sha3::Digest::update(&mut kr_hasher, &kr_buf);
    let kr = kr_hasher.finalize();

    let ciphertext = indcpa::encrypt::<K>(&buf1, &public_key, &kr[SYM_BYTES..]);

    let mut krc_hasher = Sha3_256::new();
    sha3::Digest::update(&mut krc_hasher, &ciphertext);
    let krc = krc_hasher.finalize();

    let mut ss_hasher = Shake256::default();
    let mut ss_buf = vec![];
    ss_buf.extend_from_slice(&kr[..SYM_BYTES]);
    ss_buf.extend_from_slice(&krc);
    ss_hasher.update(&ss_buf);

    let mut reader = ss_hasher.finalize_xof();
    reader.read(&mut shared_secret);

    ct_ret.copy_from_slice(&ciphertext);
    ss_ret.copy_from_slice(&shared_secret);

    (ct_ret, ss_ret)
}

/// Takes a Kyber-768 public key as input and returns a ciphertext and
/// a 32-byte shared secret.
pub fn kem_encrypt_768(
    public_key: [u8; KYBER768_PK_BYTES],
    rng: &mut (impl RngCore + CryptoRng),
) -> ([u8; KYBER768_CT_BYTES], [u8; KYBER_SS_BYTES]) {
    const K: usize = 3;

    let mut ct_ret = [0u8; KYBER768_CT_BYTES];
    let mut ss_ret = [0u8; KYBER_SS_BYTES];

    let mut shared_secret = [0u8; SYM_BYTES];

    let mut buf = [0u8; 2 * SYM_BYTES];
    rng.fill_bytes(&mut buf[..SYM_BYTES]);

    let mut hasher1 = Sha3_256::new();
    sha3::Digest::update(&mut hasher1, &buf[..SYM_BYTES]);
    let buf1 = hasher1.finalize();

    let mut hasher2 = Sha3_256::new();
    sha3::Digest::update(&mut hasher2, public_key);
    let buf2 = hasher2.finalize();

    let mut kr_hasher = Sha3_512::new();
    let mut kr_buf = vec![];
    kr_buf.extend_from_slice(&buf1);
    kr_buf.extend_from_slice(&buf2);
    sha3::Digest::update(&mut kr_hasher, &kr_buf);
    let kr = kr_hasher.finalize();

    let ciphertext = indcpa::encrypt::<K>(&buf1, &public_key, &kr[SYM_BYTES..]);

    let mut krc_hasher = Sha3_256::new();
    sha3::Digest::update(&mut krc_hasher, &ciphertext);
    let krc = krc_hasher.finalize();

    let mut ss_hasher = Shake256::default();
    let mut ss_buf = vec![];
    ss_buf.extend_from_slice(&kr[..SYM_BYTES]);
    ss_buf.extend_from_slice(&krc);
    ss_hasher.update(&ss_buf);

    let mut reader = ss_hasher.finalize_xof();
    reader.read(&mut shared_secret);

    ct_ret.copy_from_slice(&ciphertext);
    ss_ret.copy_from_slice(&shared_secret);

    (ct_ret, ss_ret)
}

/// Takes a Kyber-1024 public key as input and returns a ciphertext and
/// a 32-byte shared secret.
pub fn kem_encrypt_1024(
    public_key: [u8; KYBER1024_PK_BYTES],
    rng: &mut (impl RngCore + CryptoRng),
) -> ([u8; KYBER1024_CT_BYTES], [u8; KYBER_SS_BYTES]) {
    const K: usize = 4;

    let mut ct_ret = [0u8; KYBER1024_CT_BYTES];
    let mut ss_ret = [0u8; KYBER_SS_BYTES];

    let mut shared_secret = [0u8; SYM_BYTES];

    let mut buf = [0u8; 2 * SYM_BYTES];
    rng.fill_bytes(&mut buf[..SYM_BYTES]);

    let mut hasher1 = Sha3_256::new();
    sha3::Digest::update(&mut hasher1, &buf[..SYM_BYTES]);
    let buf1 = hasher1.finalize();

    let mut hasher2 = Sha3_256::new();
    sha3::Digest::update(&mut hasher2, public_key);
    let buf2 = hasher2.finalize();

    let mut kr_hasher = Sha3_512::new();
    let mut kr_buf = vec![];
    kr_buf.extend_from_slice(&buf1);
    kr_buf.extend_from_slice(&buf2);
    sha3::Digest::update(&mut kr_hasher, &kr_buf);
    let kr = kr_hasher.finalize();

    let ciphertext = indcpa::encrypt::<K>(&buf1, &public_key, &kr[SYM_BYTES..]);

    let mut krc_hasher = Sha3_256::new();
    sha3::Digest::update(&mut krc_hasher, &ciphertext);
    let krc = krc_hasher.finalize();

    let mut ss_hasher = Shake256::default();
    let mut ss_buf = vec![];
    ss_buf.extend_from_slice(&kr[..SYM_BYTES]);
    ss_buf.extend_from_slice(&krc);
    ss_hasher.update(&ss_buf);

    let mut reader = ss_hasher.finalize_xof();
    reader.read(&mut shared_secret);

    ct_ret.copy_from_slice(&ciphertext);
    ss_ret.copy_from_slice(&shared_secret);

    (ct_ret, ss_ret)
}

/// Takes a Kyber-512 ciphertext and a Kyber-512 secret key and returns
/// a 32-byte shared secret.
pub fn kem_decrypt_512(
    ciphertext: [u8; KYBER512_CT_BYTES],
    secret_key: [u8; KYBER512_SK_BYTES],
) -> [u8; KYBER_SS_BYTES] {
    const K: usize = 2;

    let mut ss_ret = [0u8; KYBER_SS_BYTES];

    let indcpa_sk = &secret_key[..INDCPA_SECRETKEY_BYTES_K512];
    let pki = INDCPA_SECRETKEY_BYTES_K512 + INDCPA_PUBLICKEY_BYTES_K512;
    let public_key = &secret_key[INDCPA_SECRETKEY_BYTES_K512..pki];

    let buf = indcpa::decrypt::<K>(&ciphertext, indcpa_sk);
    let ski = KYBER512_SK_BYTES - 2 * SYM_BYTES;

    let mut kr_hasher = Sha3_512::new();
    let mut kr_buf = vec![];
    kr_buf.extend_from_slice(&buf);
    kr_buf.extend_from_slice(&secret_key[ski..ski + SYM_BYTES]);
    sha3::Digest::update(&mut kr_hasher, &kr_buf);
    let mut kr = kr_hasher.finalize();

    let cmp = indcpa::encrypt::<K>(&buf, public_key, &kr[SYM_BYTES..]);
    let fail = (bool::from(ciphertext.ct_eq(&cmp)) as u8) - 1;

    let mut krh_hasher = Sha3_256::new();
    sha3::Digest::update(&mut krh_hasher, ciphertext);
    let krh = krh_hasher.finalize();

    for i in 0..SYM_BYTES {
        let skx = &secret_key[..KYBER512_SK_BYTES - SYM_BYTES + i];
        kr[i] = kr[i] ^ (fail & (kr[i] ^ skx[i]));
    }

    let mut ss_shake = Shake256::default();
    let mut ss_shake_buf = vec![];
    ss_shake_buf.extend_from_slice(&kr[..SYM_BYTES]);
    ss_shake_buf.extend_from_slice(&krh);
    ss_shake.update(&ss_shake_buf);

    let mut reader = ss_shake.finalize_xof();
    reader.read(&mut ss_ret);

    ss_ret
}

/// Takes a Kyber-768 ciphertext and a Kyber-768 secret key and returns
/// a 32-byte shared secret.
pub fn kem_decrypt_768(
    ciphertext: [u8; KYBER768_CT_BYTES],
    secret_key: [u8; KYBER768_SK_BYTES],
) -> [u8; KYBER_SS_BYTES] {
    const K: usize = 3;

    let mut ss_ret = [0u8; KYBER_SS_BYTES];

    let indcpa_sk = &secret_key[..INDCPA_SECRETKEY_BYTES_K768];
    let pki = INDCPA_SECRETKEY_BYTES_K768 + INDCPA_PUBLICKEY_BYTES_K768;
    let public_key = &secret_key[INDCPA_SECRETKEY_BYTES_K768..pki];

    let buf = indcpa::decrypt::<K>(&ciphertext, indcpa_sk);
    let ski = KYBER768_SK_BYTES - 2 * SYM_BYTES;

    let mut kr_hasher = Sha3_512::new();
    let mut kr_buf = vec![];
    kr_buf.extend_from_slice(&buf);
    kr_buf.extend_from_slice(&secret_key[ski..ski + SYM_BYTES]);
    sha3::Digest::update(&mut kr_hasher, &kr_buf);
    let mut kr = kr_hasher.finalize();

    let cmp = indcpa::encrypt::<K>(&buf, public_key, &kr[SYM_BYTES..]);
    let fail = (bool::from(ciphertext.ct_eq(&cmp)) as u8) - 1;

    let mut krh_hasher = Sha3_256::new();
    sha3::Digest::update(&mut krh_hasher, ciphertext);
    let krh = krh_hasher.finalize();

    for i in 0..SYM_BYTES {
        let skx = &secret_key[..KYBER768_SK_BYTES - SYM_BYTES + i];
        kr[i] = kr[i] ^ (fail & (kr[i] ^ skx[i]));
    }

    let mut ss_shake = Shake256::default();
    let mut ss_shake_buf = vec![];
    ss_shake_buf.extend_from_slice(&kr[..SYM_BYTES]);
    ss_shake_buf.extend_from_slice(&krh);
    ss_shake.update(&ss_shake_buf);

    let mut reader = ss_shake.finalize_xof();
    reader.read(&mut ss_ret);

    ss_ret
}

/// Takes a Kyber-1024 ciphertext and a Kyber-1024 secret key and returns
/// a 32-byte shared secret.
pub fn kem_decrypt_1024(
    ciphertext: [u8; KYBER1024_CT_BYTES],
    secret_key: [u8; KYBER1024_SK_BYTES],
) -> [u8; KYBER_SS_BYTES] {
    const K: usize = 4;

    let mut ss_ret = [0u8; KYBER_SS_BYTES];

    let indcpa_sk = &secret_key[..INDCPA_SECRETKEY_BYTES_K1024];
    let pki = INDCPA_SECRETKEY_BYTES_K1024 + INDCPA_PUBLICKEY_BYTES_K1024;
    let public_key = &secret_key[INDCPA_SECRETKEY_BYTES_K1024..pki];

    let buf = indcpa::decrypt::<K>(&ciphertext, indcpa_sk);
    let ski = KYBER1024_SK_BYTES - 2 * SYM_BYTES;

    let mut kr_hasher = Sha3_512::new();
    let mut kr_buf = vec![];
    kr_buf.extend_from_slice(&buf);
    kr_buf.extend_from_slice(&secret_key[ski..ski + SYM_BYTES]);
    sha3::Digest::update(&mut kr_hasher, &kr_buf);
    let mut kr = kr_hasher.finalize();

    let cmp = indcpa::encrypt::<K>(&buf, public_key, &kr[SYM_BYTES..]);
    let fail = (bool::from(ciphertext.ct_eq(&cmp)) as u8) - 1;

    let mut krh_hasher = Sha3_256::new();
    sha3::Digest::update(&mut krh_hasher, ciphertext);
    let krh = krh_hasher.finalize();

    for i in 0..SYM_BYTES {
        let skx = &secret_key[..KYBER1024_SK_BYTES - SYM_BYTES + i];
        kr[i] = kr[i] ^ (fail & (kr[i] ^ skx[i]));
    }

    let mut ss_shake = Shake256::default();
    let mut ss_shake_buf = vec![];
    ss_shake_buf.extend_from_slice(&kr[..SYM_BYTES]);
    ss_shake_buf.extend_from_slice(&krh);
    ss_shake.update(&ss_shake_buf);

    let mut reader = ss_shake.finalize_xof();
    reader.read(&mut ss_ret);

    ss_ret
}
