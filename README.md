Kyber-KEM
=========

[![CI](https://img.shields.io/github/actions/workflow/status/parazyd/kyber-kem/ci.yml?branch=master&style=flat-square)](https://github.com/parazyd/kyber-kem/actions)
[![Docs](https://img.shields.io/badge/rust-doc-blue?style=flat-square)](https://docs.rs/kyber-kem)

Implementation of [Kyber](https://pq-crystals.org/kyber) IND-CCA2
secure key encapsulation mechanism (KEM)

This is a direct Rust reimplementation/port of the
[Go implementation](https://github.com/SymbolicSoft/kyber-k2so)
Symbolic Software under the MIT license.

This Rust implementation is licensed under GNU AGPL-3

## Benchmarks

```
$ cargo bench
```

Intel i7-1370P results:

| Function           |           |               |           |
| -------------------|-----------|---------------|-----------|
| `kem_keypair_512`  | 17.907 µs | **18.019 µs** | 18.127 µs |
| `kem_encrypt_512`  | 22.458 µs | **22.504 µs** | 22.562 µs |
| `kem_decrypt_512`  | 27.844 µs | **28.058 µs** | 28.288 µs |
| `kem_keypair_768`  | 31.836 µs | **31.950 µs** | 32.103 µs |
| `kem_encrypt_768`  | 37.207 µs | **37.298 µs** | 37.435 µs |
| `kem_decrypt_768`  | 44.192 µs | **44.402 µs** | 44.632 µs |
| `kem_keypair_1024` | 53.455 µs | **53.568 µs** | 53.721 µs |
| `kem_encrypt_1024` | 56.700 µs | **56.820 µs** | 56.962 µs |
| `kem_decrypt_1024` | 64.039 µs | **64.464 µs** | 64.992 µs |
