LanaCoin post-quantum hard fork
===============================

LanaCoin replaces ECDSA (secp256k1) signatures with **ML-DSA-44**, the
lattice based signature scheme standardized by NIST in FIPS 204
(CRYSTALS-Dilithium, security category 2). ECDSA can be broken by a large
quantum computer (Shor's algorithm); ML-DSA is designed to resist it.
SHA-256d (proof-of-work, transaction and block hashes, addresses) and the
AES-256 wallet encryption are not affected in a meaningful way (Grover's
algorithm only halves their security level) and stay as they are.

This is a **hard fork**: every node, staker, wallet, exchange and explorer
has to upgrade before it activates.

Schedule
--------

The rules switch by **block time** (the timestamp in the block header), not
by block height:

| Network | Post-quantum fork                    | ECDSA sunset                         |
|---------|--------------------------------------|--------------------------------------|
| Mainnet | 7 May 2028 06:39 GMT+2 (1841287140)  | 7 May 2029 06:39 GMT+2 (1872823140)  |
| Testnet | 7 Feb 2028 06:39 GMT+1 (1833514740)  | 7 Apr 2028 06:39 GMT+2 (1838695140)  |

7 May 06:39 is the time of Lana's birthday used for the genesis block.
Testnet goes through both steps before the mainnet fork. On testnet and
regtest `-pqforktime=<unix time>` and `-ecdsasunsettime=<unix time>` move
the dates for testing; on mainnet they are fixed.

`getinfo` shows the dates and whether the fork and the sunset are active
(`postquantum` object).

What changes
------------

### Before the fork (now until 7 May 2028)

Nothing changes on the network. Upgraded wallets already create post-quantum
keys in the background (the post-quantum key pool), so wallet backups made
before the fork contain the keys used after it. Post-quantum addresses can be
created (`getnewaddress "" postquantum`) but **can not receive coins yet**:
such outputs could not be spent before the fork, so wallets refuse to send to
them and nodes do not relay them.

### From the fork (7 May 2028)

* **New outputs must be quantum safe.** A transaction or block that creates
  an output to an ECDSA address (`L...`), a pay-to-pubkey or an old P2SH
  address is invalid. Allowed are post-quantum addresses (`LQ...`),
  post-quantum script addresses (`LS...`), `OP_RETURN` data outputs and the
  empty coinbase/coinstake marker.
* **ECDSA coins can still be spent** (to post-quantum addresses) for one
  year, until the ECDSA sunset. Wallets send change to post-quantum
  addresses automatically.
* **Staking:** blocks are signed with ML-DSA-44. Coins on ECDSA addresses
  keep staking until the sunset; their stake reward and the staked coins go
  to the wallet's post-quantum staking address. Coins therefore move to
  quantum safe addresses by staking alone.
* New addresses in the wallet (GUI and RPC) are post-quantum.

### From the ECDSA sunset (7 May 2029)

ECDSA signatures are no longer valid (`OP_CHECKSIG`, `OP_CHECKSIGVERIFY`,
`OP_CHECKMULTISIG`, `OP_CHECKMULTISIGVERIFY` fail, also for the stake kernel).
**Coins that are still on ECDSA addresses then can not be moved any more.**
Everybody has to move their coins before 7 May 2029 — by sending them to a
post-quantum address of their own, or simply by staking.

What users have to do
---------------------

1. Upgrade the wallet before 7 May 2028 and make a new wallet backup after
   upgrading (it then contains the post-quantum key pool).
2. After the fork, keep the wallet staking, or send the coins to a new
   address of your own (`getnewaddress` returns a post-quantum address).
   This must be done before 7 May 2029.
3. Make a new backup after you used about 100 new addresses (as before).

Exchanges and services
----------------------

* Upgrade nodes before the fork date. Old nodes will be on a different chain
  from the first post-fork block on.
* After the fork, deposit addresses must be post-quantum (`getnewaddress` and
  `getaccountaddress` return them automatically). Payouts to `L...`
  addresses are invalid after the fork; validate user supplied addresses with
  `validateaddress` (`"ispostquantum": true`).
* Post-quantum transactions are larger: an input is about 3.8 kB (signature
  2420 bytes, public key 1313 bytes) instead of about 150 bytes, an output
  46 instead of 34 bytes. The fee rules are unchanged (minimum fee 100
  lanoshis per started 1000 bytes), so the minimum fee of a transaction with
  one input rises from 0.000001 to about 0.000004 LANA.
* Back up post-quantum keys with `dumpwallet` / `dumpprivkey`; post-quantum
  secret keys look like `LK...` (testnet `TK...`) and are imported with
  `importprivkey` / `importwallet`.

Technical specification
-----------------------

### Signature scheme

* ML-DSA-44 (FIPS 204), PQClean "clean" implementation of the pq-crystals
  reference code, in `src/pqcrypto` (see its README for provenance and
  validation against the NIST ACVP vectors).
* A private key is a 32 byte seed; the ML-DSA key pair is derived from it
  (`ML-DSA.KeyGen_internal`).
* A serialized public key is `0x01 || pk` (1313 bytes); the first byte names
  the algorithm, so further algorithms can be added later without new
  opcodes or address types.
* Signatures are hedged (randomized) and domain separated with the FIPS 204
  context string: `"LanaCoin/tx"` for transaction inputs,
  `"LanaCoin/block"` for block signatures, `"LanaCoin/message"` reserved for
  message signing. A signature for one purpose is never valid for another.

### Script

| Opcode                     | Value  | Before the fork | After the fork |
|----------------------------|--------|-----------------|----------------|
| `OP_CHECKSIGPQ`            | `0xc0` | invalid opcode  | `(sig pubkey -- bool)` |
| `OP_CHECKSIGPQVERIFY`      | `0xc1` | invalid opcode  | as above, then `VERIFY` |

* `sig` is the 2420 byte ML-DSA-44 signature of the signature hash
  (`SignatureHash`, same as for ECDSA) followed by the hash type byte.
* Strict encoding: the public key must be valid (known algorithm, exact
  size) and a non-empty signature must have the exact size and a defined
  hash type, otherwise the script fails. An empty signature pushes false.
* `SIGHASH_SINGLE` without a matching output (the "SIGHASH_SINGLE bug") is
  rejected, and the signature is not removed from the script code
  (no `FindAndDelete`).
* Push size limit 16384 bytes and script size limit 65536 bytes (520 and
  10000 before).

Output templates:

* Post-quantum key hash (`LQ...`):
  `OP_DUP OP_HASH256 <32 byte double SHA-256 of the public key> OP_EQUALVERIFY OP_CHECKSIGPQ`,
  spent with `<sig> <pubkey>`.
* P2SH256 (`LS...`): `OP_HASH256 <32 byte double SHA-256 of the script> OP_EQUAL`,
  with pay-to-script-hash (BIP16) semantics after the fork, e.g. for
  post-quantum multisig: `<pk1> OP_CHECKSIGPQVERIFY <pk2> OP_CHECKSIGPQ`.

256 bit hashes keep 128 bit security against quantum preimage search.

### Consensus rules after the fork (by block time)

1. Every output of every transaction is a post-quantum key hash, a P2SH256
   script hash, begins with `OP_RETURN`, or is empty with value 0.
2. Script flags `SCRIPT_VERIFY_PQ` (and after the sunset
   `SCRIPT_VERIFY_NO_ECDSA`) apply to all inputs, including the stake kernel.
3. Post-quantum signature operations are counted separately: at most 2000
   per block (`MAX_BLOCK_PQ_SIGOPS`), counted in scriptSigs, scriptPubKeys and
   P2SH256 redeem scripts. The legacy sigop count is unchanged.
4. Proof-of-stake block signature: `vchBlockSig = pubkey (1313 bytes) ||
   ML-DSA-44 signature (2420 bytes)` of the block hash with the
   `"LanaCoin/block"` context. The hash of `pubkey` must equal the key hash
   of the coinstake output `vout[1]`, which is either a post-quantum key hash
   or `OP_RETURN <32 byte key hash>` (for multisig staking).

Blocks before the fork are validated exactly as before; in particular the
new opcodes stay invalid and post-quantum sigops are not counted for them.

### Addresses and keys (base58check, 2 version bytes)

| Type                       | Mainnet       | Testnet       | Payload  |
|----------------------------|---------------|---------------|----------|
| Post-quantum key hash      | `131 46` LQ…  | `178 128` TQ… | 32 bytes |
| P2SH256                    | `131 105` LS… | `178 187` TS… | 32 bytes |
| Post-quantum secret (seed) | `130 152` LK… | `177 234` TK… | 32 bytes |

Addresses are 52 characters long.

### Policy

* Before the fork post-quantum outputs are non-standard (not relayed).
* After the fork scriptSigs may be up to 20480 bytes; at most 400
  post-quantum sigops per transaction.

### Wallet file

New wallet.dat records (`pqkey`, `cpqkey`, `pqkeymeta`, `pqpool`,
`cscript256`, `pqstakekey`, `pqacc`) are ignored by older versions, which
can therefore still open an upgraded wallet (without seeing the
post-quantum keys). Encrypted wallets encrypt the post-quantum seed exactly
like ECDSA secrets (AES-256-CBC with the wallet master key).

Tests
-----

* `src/test/pqkey_tests.cpp`: NIST ACVP key generation vectors,
  deterministic signatures matching an independent ML-DSA implementation,
  negative cases.
* `src/test/pqfork_tests.cpp`: activation times, post-quantum spends, ECDSA
  sunset, P2SH256 multisig, script limits, output rule, block signatures,
  addresses, encrypted keystore.
* `src/test/pqwallet_tests.cpp`: wallet keys and key pool, addresses and
  change around the fork, send checks, wallet file round trip.
