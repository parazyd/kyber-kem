/* This file is part of Kyber-KEM (https://github.com/parazyd/kyber-kem)
 * * Copyright (C) 2023 Dyne.org foundation * * This program is free software: you can redistribute it and/or modify
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

use rand::rngs::OsRng;
use regex::Regex;
use subtle::ConstantTimeEq;

use crate::params::*;
use crate::{kem_decrypt_1024, kem_encrypt_1024, kem_keypair_1024};
use crate::{kem_decrypt_512, kem_encrypt_512, kem_keypair_512};
use crate::{kem_decrypt_768, kem_encrypt_768, kem_keypair_768};

#[allow(clippy::large_enum_variant)]
enum KyberType {
    Kyber512(KemTest512),
    Kyber768(KemTest768),
    Kyber1024(KemTest1024),
}

#[allow(dead_code)]
struct KemTest512 {
    secret_key: [u8; KYBER512_SK_BYTES],
    public_key: [u8; KYBER512_PK_BYTES],
    ciphertext: [u8; KYBER512_CT_BYTES],
    shared_secret: [u8; KYBER_SS_BYTES],
}

#[allow(dead_code)]
struct KemTest768 {
    secret_key: [u8; KYBER768_SK_BYTES],
    public_key: [u8; KYBER768_PK_BYTES],
    ciphertext: [u8; KYBER768_CT_BYTES],
    shared_secret: [u8; KYBER_SS_BYTES],
}

#[allow(dead_code)]
struct KemTest1024 {
    secret_key: [u8; KYBER1024_SK_BYTES],
    public_key: [u8; KYBER1024_PK_BYTES],
    ciphertext: [u8; KYBER1024_CT_BYTES],
    shared_secret: [u8; KYBER_SS_BYTES],
}

static PQCKEMKAT_1642: &str = include_str!("../assets/PQCkemKAT_1632.rsp");
static PQCKEMKAT_2400: &str = include_str!("../assets/PQCkemKAT_2400.rsp");
static PQCKEMKAT_3168: &str = include_str!("../assets/PQCkemKAT_3168.rsp");

fn read_vectors<const K: usize>(vectors: &str) -> Vec<KyberType> {
    let mut ret = vec![];
    let r_sk = Regex::new(r"sk = [A-F0-9]+\n").unwrap();
    let r_pk = Regex::new(r"pk = [A-F0-9]+\n").unwrap();
    let r_ct = Regex::new(r"ct = [A-F0-9]+\n").unwrap();
    let r_ss = Regex::new(r"ss = [A-F0-9]+\n").unwrap();

    let all_sk: Vec<&str> = r_sk.find_iter(vectors).map(|m| m.as_str()).collect();
    assert!(all_sk.len() == 100);

    let all_pk: Vec<&str> = r_pk.find_iter(vectors).map(|m| m.as_str()).collect();
    assert!(all_pk.len() == 100);

    let all_ct: Vec<&str> = r_ct.find_iter(vectors).map(|m| m.as_str()).collect();
    assert!(all_ct.len() == 100);

    let all_ss: Vec<&str> = r_ss.find_iter(vectors).map(|m| m.as_str()).collect();
    assert!(all_ss.len() == 100);

    for i in 0..100 {
        let sk = hex::decode(all_sk[i][5..].trim()).unwrap();
        let pk = hex::decode(all_pk[i][5..].trim()).unwrap();
        let ct = hex::decode(all_ct[i][5..].trim()).unwrap();
        let ss = hex::decode(all_ss[i][5..].trim()).unwrap();

        match K {
            512 => {
                let mut sk_ = [0u8; KYBER512_SK_BYTES];
                sk_.copy_from_slice(&sk);
                let mut pk_ = [0u8; KYBER512_PK_BYTES];
                pk_.copy_from_slice(&pk);
                let mut ct_ = [0u8; KYBER512_CT_BYTES];
                ct_.copy_from_slice(&ct);
                let mut ss_ = [0u8; KYBER_SS_BYTES];
                ss_.copy_from_slice(&ss);

                ret.push(KyberType::Kyber512(KemTest512 {
                    secret_key: sk_,
                    public_key: pk_,
                    ciphertext: ct_,
                    shared_secret: ss_,
                }));
            }

            768 => {
                let mut sk_ = [0u8; KYBER768_SK_BYTES];
                sk_.copy_from_slice(&sk);
                let mut pk_ = [0u8; KYBER768_PK_BYTES];
                pk_.copy_from_slice(&pk);
                let mut ct_ = [0u8; KYBER768_CT_BYTES];
                ct_.copy_from_slice(&ct);
                let mut ss_ = [0u8; KYBER_SS_BYTES];
                ss_.copy_from_slice(&ss);

                ret.push(KyberType::Kyber768(KemTest768 {
                    secret_key: sk_,
                    public_key: pk_,
                    ciphertext: ct_,
                    shared_secret: ss_,
                }));
            }

            1024 => {
                let mut sk_ = [0u8; KYBER1024_SK_BYTES];
                sk_.copy_from_slice(&sk);
                let mut pk_ = [0u8; KYBER1024_PK_BYTES];
                pk_.copy_from_slice(&pk);
                let mut ct_ = [0u8; KYBER1024_CT_BYTES];
                ct_.copy_from_slice(&ct);
                let mut ss_ = [0u8; KYBER_SS_BYTES];
                ss_.copy_from_slice(&ss);

                ret.push(KyberType::Kyber1024(KemTest1024 {
                    secret_key: sk_,
                    public_key: pk_,
                    ciphertext: ct_,
                    shared_secret: ss_,
                }));
            }

            _ => unreachable!(),
        }
    }

    ret
}

#[test]
fn test_vectors_512() {
    let vectors = read_vectors::<512>(PQCKEMKAT_1642);

    for (i, vector) in vectors.iter().enumerate() {
        let KyberType::Kyber512(test) = vector else {
            unreachable!()
        };

        let ss_b = kem_decrypt_512(test.ciphertext, test.secret_key);
        assert!(
            bool::from(test.shared_secret.ct_eq(&ss_b)),
            "Kyber-512 test vector {i} failed"
        );
    }
}

#[test]
fn test_vectors_768() {
    let vectors = read_vectors::<768>(PQCKEMKAT_2400);

    for (i, vector) in vectors.iter().enumerate() {
        let KyberType::Kyber768(test) = vector else {
            unreachable!()
        };

        let ss_b = kem_decrypt_768(test.ciphertext, test.secret_key);
        assert!(
            bool::from(test.shared_secret.ct_eq(&ss_b)),
            "Kyber-768 test vector {i} failed"
        );
    }
}

#[test]
fn test_vectors_1024() {
    let vectors = read_vectors::<1024>(PQCKEMKAT_3168);

    for (i, vector) in vectors.iter().enumerate() {
        let KyberType::Kyber1024(test) = vector else {
            unreachable!()
        };

        let ss_b = kem_decrypt_1024(test.ciphertext, test.secret_key);
        assert!(
            bool::from(test.shared_secret.ct_eq(&ss_b)),
            "Kyber-768 test vector {i} failed"
        );
    }
}

#[test]
fn test_self_512() {
    for _ in 0..1000 {
        let (sk, pk) = kem_keypair_512(&mut OsRng);
        let (ciphertext, ss_a) = kem_encrypt_512(pk, &mut OsRng);
        let ss_b = kem_decrypt_512(ciphertext, sk);
        assert!(bool::from(ss_a.ct_eq(&ss_b)));
    }
}

#[test]
fn test_self_768() {
    for _ in 0..1000 {
        let (sk, pk) = kem_keypair_768(&mut OsRng);
        let (ciphertext, ss_a) = kem_encrypt_768(pk, &mut OsRng);
        let ss_b = kem_decrypt_768(ciphertext, sk);
        assert!(bool::from(ss_a.ct_eq(&ss_b)));
    }
}

#[test]
fn test_self_1024() {
    for _ in 0..1000 {
        let (sk, pk) = kem_keypair_1024(&mut OsRng);
        let (ciphertext, ss_a) = kem_encrypt_1024(pk, &mut OsRng);
        let ss_b = kem_decrypt_1024(ciphertext, sk);
        assert!(bool::from(ss_a.ct_eq(&ss_b)));
    }
}
