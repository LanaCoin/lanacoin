Post-quantum signatures (ML-DSA-44)
===================================

This directory contains the ML-DSA-44 signature scheme (NIST FIPS 204,
security category 2) used by the LanaCoin post-quantum hard fork
(see doc/pq-hardfork.md).

Source
------

* `mldsa44/` is the PQClean "clean" implementation of ML-DSA-44
  (crypto_sign/ml-dsa-44/clean), based on the pq-crystals reference
  implementation, commit cbcd8753a43402885c90343cd6335fb54712cda1.
* `fips202.c`, `fips202.h` and `randombytes.h` are from PQClean `common/`.
* Obtained from the `pqcrypto-mldsa` 0.1.2 package which bundles PQClean.
* License: CC0 / public domain (see `mldsa44/LICENSE`).

LanaCoin changes
----------------

* `crypto_sign_keypair_seed()`: deterministic key generation from a 32 byte
  seed (FIPS 204 ML-DSA.KeyGen_internal), so wallets only need to store the
  seed. `crypto_sign_keypair()` now draws the seed and calls it.
* `crypto_sign_signature_ctx_rnd()`: signing with caller supplied 32 byte
  randomness (for known answer tests). `crypto_sign_signature_ctx()` draws
  it from `randombytes()` and falls back to the deterministic variant
  (rnd = 0, allowed by FIPS 204) if no randomness is available.
* `randombytes.c`: OpenSSL `RAND_bytes`.

No other changes; the arithmetic, encoding and verification code is
unmodified.

Validation
----------

The implementation was checked against the NIST ACVP ML-DSA-44 test vectors
(keyGen; sigGen and sigVer via an independent implementation) and
cross-checked byte for byte with an independent implementation on random
keys, messages and contexts. `src/test/pqkey_tests.cpp` contains known answer
tests that run with the unit tests.
