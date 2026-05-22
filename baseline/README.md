# Baseline Adaptor Signature for AES-128
This folder includes an implementation of the [Ciampi et al.](https://eprint.iacr.org/2024/1773.pdf) adaptor signature construction, instantiated with FAEST-128f and the [Takahash-Zaverucha](https://eprint.iacr.org/2021/1704.pdf) verifiable encryption scheme. 
The C++ implementation is based on [`faest-arch-opt`](https://github.com/faest-sign/faest-arch-opt) and [`verenc-mpcith`](https://github.com/akiratk0355/verenc-mpcith/tree/main/helium_aes). 
The scheme essentially proceeds as follows:

- The signer first generates a Kyber key pair, pre-signs the Kyber public-key with FAEST-128f together with a message and instance (AES-128 ciphertext), and outputs the FAEST-128f signature and the key generation seed for Kyber as a presigature. 
- The party holding the corresponding witness (the AES-128 key) adapts the pre-signature into a complete signature, by running the verifiable encryption of the AES key under the Kyber public key derived from the seed.
- To extract the witness from the pre-signature and the complete signature, one can run the Kyber decryption algorithm and reconstruct secret shares of the witness after verifying the proof. 

In more detail, the scheme consists of the following six algorithms:

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

`faest-arch-opt/` is a git submodule. After cloning, initialise it before building:

```bash
git submodule update --init
```

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
