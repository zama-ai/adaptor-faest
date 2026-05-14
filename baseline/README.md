# Verifiable Encryption of AES keys with Helium and Kyber 

This repository contains the implementation of verifiable encryption (VE) from MPC-in-the-head, as described in our paper. 
The basis for the implementation is the [Helium+AES](https://eprint.iacr.org/2022/588) signature scheme, which proves knowledge of an AES key associated with
public plaintext-ciphertext pair. We apply our VE transform using a public-key encryption (PKE) 
scheme based on [Kyber](https://www.pq-crystals.org/kyber/), therefore this implementation allows one to verifiably encrypt an AES key to a Kyber public key. 

It also includes an **adaptor signature** construction that composes FAEST 128f with Helium-AES into a six-algorithm scheme (KeyGen, preSign, pVer, Adapt, Ver, Ext).

## Helium and Kyber implementations
The implementation is based on the publicly available Helium code (https://github.com/IAIK/bnpp_helium_signatures).
In many places the code *signature* refers to the proof in the context of verifiable encryption. (similarly for *sign* and *prove*)

Kyber is the AVX2 version taken from [PQClean](https://github.com/PQClean/PQClean), along with some of the `common` code of
PQClean (main was at `c1b19a865de329e87e9b3e9152362fcb709da8ab` (April 2023) when we took Kyber from PQClean).
The Makefile is modified to build a static library that includes the `common' code from PQClean. 
We added a deterministic version of kem_enc that allows the caller to pass the randomness used for encryption.
We add a variant of KEM decapsulation that makes failures explicit, allowing the caller to check for
decryption failures (see page 14 of the Kyber [spec](https://www.pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf#page=14) for discussion).
We also added `pke_keygen_seeded` — a deterministic variant of Kyber key generation that takes an explicit 64-byte seed, used by the adaptor signature scheme.

## Adaptor Signature (`adaptor_signature.h` / `adaptor_signature.cpp`)

The adaptor signature scheme binds a Helium-AES verifiable encryption key into a FAEST 128f signature, enabling a two-phase signing protocol where the full signature is only completable by a party that holds the corresponding AES key (the witness).

The six algorithms are:

| Algorithm | Description |
|-----------|-------------|
| `adaptor_keygen()` | Generates a FAEST 128f keypair `(apk, ask)`. |
| `adaptor_presign(ask, msg, helium_pk, instance)` | Draws a random 64-byte seed, derives a Kyber PKE keypair `(enc_key, dec_key)` deterministically from it, and produces a FAEST signature over `msg ‖ helium_pk ‖ enc_key`. Returns `σ̃ = (faest_sig, seed)`. |
| `adaptor_pver(σ̃, msg, apk, helium_pk, instance)` | Reconstructs `enc_key` from `σ̃.seed` and verifies the FAEST signature. |
| `adaptor_adapt(apk, msg, σ̃, helium_keypair, instance)` | Reconstructs `enc_key` from `σ̃.seed`, runs `helium_sign` with the witness `helium_keypair`, and returns the full signature `σ = (helium_pk, enc_key, faest_sig, helium_sig)`. |
| `adaptor_ver(apk, msg, σ, instance)` | Verifies both the FAEST signature over `msg ‖ helium_pk ‖ enc_key` and the Helium signature. |
| `adaptor_ext(apk, msg, σ̃, σ, instance)` | Verifies `σ`, reconstructs `dec_key` from `σ̃.seed`, compresses `helium_sig`, and calls `helium_decrypt` to recover the AES key. |

The FAEST 128f implementation is in `faest-arch-opt/` and is compiled as a separate static library (`faest_lib`) requiring C++23. The adaptor code is compiled as `adaptor_lib` (also C++23) and links against both `helium_static` and `faest_lib`.

## Requirements
Tested on Ubuntu 22.04  
C++23 compatible toolchain (GCC 13+) — required for FAEST  
C++17 compatible toolchain for all other components

For testing and benchmarking:

* [GMP](https://gmplib.org/)
* [NTL](https://shoup.net/ntl)

## Setup
The project uses `cmake`. To build it:
```bash
mkdir build
cd build
cmake ..
make 
# tests (only if you built them.  Use "ccmake ." from the build dir to toggle whether tests are built )
make test
```
To run the verifiable encryption benchmarks (for the `Prove`, `Verify`, `Compress` and `Decrypt` functions),
 you must build the tests, then run 
```
./signature_test  
```

To run the adaptor signature round-trip test (KeyGen → preSign → pVer → Adapt → Ver → Ext):
```
./adaptor_test
```
The test verifies all 11 assertions including that `adaptor_ext` recovers the original AES key.

To run some extended benchmarks of the `Prove` and `Verify` functions 
```
python3 ../tools/bench_all.py   # benchmarks a wide range of parameters
./bench_free -i <iterations> <kappa=16> <Sboxes=200> <N> <tau> # benchmark parameters freely; note that (N, tau) should be chose to ensure soundness
```
The benchmark script auto-detects the `SCALING_FACTOR` based on whether the Linux perf hardware cycle counter is available (`/proc/sys/kernel/perf_event_paranoid ≤ 2`), falling back to microseconds otherwise.

## Adaptor Signature Benchmarks

The `bench_adaptor` binary times all six adaptor operations (KeyGen, preSign, pVer, Adapt, Ver, Ext) and reports per-iteration timings in milliseconds along with signature sizes in bytes.

Run from the `build/` directory:

```bash
./bench_adaptor -i <iterations> <param>
```

`<param>` selects the Helium instance:

| param | N   | tau | note |
|-------|-----|-----|------|
| 1     | 16  | 31  | AES128_L1_Param1 |
| 2     | 57  | 22  | AES128_L1_Param2 |
| 3     | 256 | 16  | AES128_L1_Param3 (default for benchmarking) |

Example (101 iterations, N=256/tau=16):

```bash
./bench_adaptor -i 101 3
```

Output is CSV with a header row, one row per iteration, and a trailing average over the last 100 rows (row 0 is a warmup and excluded from the average).

To produce a LaTeX table row for the paper, run the Python wrapper from the `build/` directory:

```bash
python3 ../tools/bench_adaptor.py
```

This runs `bench_adaptor -i 101 3`, parses the output (skipping the warmup row), and prints a `\midrule`-delimited LaTeX row with columns: Scheme, |apk|, |ask|, |σ̃|, |σ|, KeyGen, preSign, pVer, Adapt, Ver, Ext (all times in ms).
