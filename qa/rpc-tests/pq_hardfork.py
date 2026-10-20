#!/usr/bin/env python3
# End-to-end test of the post-quantum hard fork on two regtest nodes:
# before the fork, after the fork and after the ECDSA sunset.
#
# Usage: qa/rpc-tests/pq_hardfork.py <path to lanacoind> <empty work directory>
# Blocks are mined with getwork (regtest difficulty); no other tools needed.
import base64, hashlib, json, os, shutil, struct, subprocess, sys, time, urllib.request

if len(sys.argv) != 3:
    raise SystemExit("usage: %s <lanacoind> <work directory>" % sys.argv[0])
LANACOIND = sys.argv[1]
BASE = sys.argv[2]
RPCUSER, RPCPASS = "pq", "pqtest"
NODES = [{"p2p": 29700, "rpc": 29800}, {"p2p": 29701, "rpc": 29801}]
checks = 0

RUNNING = []

def ok(cond, msg):
    global checks
    checks += 1
    if not cond:
        for p in RUNNING:
            p.kill()
        raise SystemExit("FAILED: " + msg)
    print("  ok  " + msg)

def rpc(n, method, *params):
    req = urllib.request.Request("http://127.0.0.1:%d/" % NODES[n]["rpc"],
                                 json.dumps({"method": method, "params": list(params), "id": 1}).encode())
    req.add_header("Authorization", "Basic " + base64.b64encode(("%s:%s" % (RPCUSER, RPCPASS)).encode()).decode())
    req.add_header("Content-Type", "application/json")
    try:
        r = json.loads(urllib.request.urlopen(req, timeout=60).read())
    except urllib.error.HTTPError as e:
        r = json.loads(e.read())
    if r.get("error"):
        raise RuntimeError(r["error"]["message"])
    return r["result"]

def rpc_err(n, method, *params):
    try:
        rpc(n, method, *params)
        return None
    except RuntimeError as e:
        return str(e)

def start(n, extra):
    d = os.path.join(BASE, "node%d" % n)
    os.makedirs(d, exist_ok=True)
    args = [LANACOIND, "-regtest", "-datadir=" + d, "-port=%d" % NODES[n]["p2p"], "-rpcport=%d" % NODES[n]["rpc"],
            "-rpcuser=" + RPCUSER, "-rpcpassword=" + RPCPASS, "-server", "-listen", "-discover=0", "-dnsseed=0",
            "-staking=0", "-keypool=20", "-printtoconsole=0", "-debug=0"] + extra
    if n == 1:
        args.append("-connect=127.0.0.1:%d" % NODES[0]["p2p"])
    log = open(os.path.join(d, "stdout.log"), "a")
    p = subprocess.Popen(args, stdout=log, stderr=log)
    RUNNING.append(p)
    for _ in range(300):
        try:
            rpc(n, "getinfo")
            return p
        except Exception:
            if p.poll() is not None:
                raise SystemExit("node%d exited, see %s" % (n, d))
            time.sleep(0.2)
    raise SystemExit("node%d did not start" % n)

def stop(procs):
    for n in range(len(procs)):
        try:
            rpc(n, "stop")
        except Exception:
            pass
    for p in procs:
        p.wait(timeout=120)
        RUNNING.remove(p)

def wait_connected():
    for _ in range(300):
        if rpc(0, "getconnectioncount") > 0 and rpc(1, "getconnectioncount") > 0:
            return
        time.sleep(0.2)
    raise SystemExit("nodes did not connect")

def mine(n, count=1):
    """Mine PoW blocks with getwork (sha256d, regtest difficulty)"""
    for _ in range(count):
        height = rpc(n, "getblockcount")
        for _attempt in range(1000):
            try:
                work = rpc(n, "getwork")
                break
            except RuntimeError as e:
                time.sleep(0.2)  # initial download for a moment after start
        else:
            raise SystemExit("getwork unavailable")
        data = bytearray.fromhex(work["data"])
        target = int.from_bytes(bytes.fromhex(work["target"]), "little")
        header = bytearray(b"".join(bytes(reversed(data[i:i+4])) for i in range(0, 80, 4)))
        for nonce in range(1 << 32):
            header[76:80] = struct.pack("<I", nonce)
            h = hashlib.sha256(hashlib.sha256(bytes(header)).digest()).digest()
            if int.from_bytes(h, "little") <= target:
                break
        data[76:80] = struct.pack(">I", nonce)
        if not rpc(n, "getwork", data.hex()):
            raise SystemExit("block rejected")
        for _ in range(100):
            if rpc(n, "getblockcount") > height:
                break
            time.sleep(0.05)

def sync():
    for _ in range(600):
        if rpc(0, "getblockcount") == rpc(1, "getblockcount") and \
           rpc(0, "getbestblockhash") == rpc(1, "getbestblockhash"):
            return
        time.sleep(0.1)
    raise SystemExit("nodes did not sync")

def sync_mempool(txid):
    for _ in range(300):
        if txid in rpc(1, "getrawmempool"):
            return True
        time.sleep(0.1)
    return False

def out_types(n, txid):
    tx = rpc(n, "decoderawtransaction", rpc(n, "getrawtransaction", txid))
    return [o["scriptPubKey"]["type"] for o in tx["vout"]]

def next_switch_time(n):
    """A time after the tip (fast mining puts block times ahead of the clock)
    and wait until the clock has passed it, so mempool and blocks agree"""
    t = max(int(time.time()), rpc(n, "getblock", rpc(n, "getbestblockhash"))["time"]) + 2
    while time.time() < t + 1:
        time.sleep(0.2)
    return t

def spend_utxo(n, utxo, dest, fee=0.01):
    raw = rpc(n, "createrawtransaction", [{"txid": utxo["txid"], "vout": utxo["vout"]}],
              {dest: round(utxo["amount"] - fee, 6)})
    signed = rpc(n, "signrawtransaction", raw)
    return signed

shutil.rmtree(BASE, ignore_errors=True)
os.makedirs(BASE)
now = int(time.time())

print("== Phase 1: before the post-quantum fork")
fork, sunset = now + 7 * 86400, now + 14 * 86400
times = ["-pqforktime=%d" % fork, "-ecdsasunsettime=%d" % sunset]
procs = [start(0, times), start(1, times)]
wait_connected()
info = rpc(0, "getinfo")
ok(not info["postquantum"]["active"], "fork not active, getinfo reports the fork time %d" % info["postquantum"]["forktime"])
mine(0, 20)
sync()
ok(rpc(1, "getblockcount") == 20, "20 PoW blocks mined and relayed")
legacy = rpc(0, "getnewaddress")
pq_early = rpc(0, "getnewaddress", "", "postquantum")
ok(rpc(0, "validateaddress", legacy)["ispostquantum"] is False, "default address is legacy before the fork: " + legacy)
ok(pq_early.startswith("TQ") and len(pq_early) == 52, "post-quantum address can be created early: " + pq_early)
err = rpc_err(0, "sendtoaddress", pq_early, 10)
ok(err is not None and "only after" in err, "sending to a post-quantum address before the fork is refused: " + str(err))
txid = rpc(0, "sendtoaddress", legacy, 1000)
ok(sync_mempool(txid), "legacy transaction relayed")
mine(0)
sync()
ok(rpc(0, "gettransaction", txid)["confirmations"] == 1, "legacy transaction confirmed")
ok(rpc(0, "getinfo")["pqkeypoolsize"] >= 20, "post-quantum key pool filled before the fork")
fork = next_switch_time(0)
stop(procs)

print("== Phase 2: after the post-quantum fork")
times = ["-pqforktime=%d" % fork, "-ecdsasunsettime=%d" % (fork + 7 * 86400)]
procs = [start(0, times), start(1, times)]
wait_connected()
ok(rpc(0, "getinfo")["postquantum"]["active"], "fork active")
ok(rpc(0, "getblockcount") == 21, "pre-fork chain still valid after restart (height %d)" % rpc(0, "getblockcount"))
pq1 = rpc(0, "getnewaddress")
ok(pq1.startswith("TQ"), "default address is post-quantum after the fork: " + pq1)
va = rpc(0, "validateaddress", pq1)
ok(va["ismine"] and va["ispostquantum"] and len(va["pubkey"]) == 2 * 1313, "validateaddress shows the ML-DSA-44 public key")
mine(0)
sync()
coinbase = rpc(0, "getblock", rpc(0, "getbestblockhash"))["tx"][0]
ok(out_types(0, coinbase) == ["pqkeyhash"], "PoW coinbase pays to a post-quantum address")
err = rpc_err(0, "sendtoaddress", legacy, 10)
ok(err is not None and "post-quantum" in err, "sending to a legacy address after the fork is refused: " + str(err))

# ECDSA coins (still valid until the sunset) to a post-quantum address
txid = rpc(0, "sendtoaddress", pq1, 5000)
types = out_types(0, txid)
ok(all(t == "pqkeyhash" for t in types), "outputs incl. change are post-quantum: %s" % types)
ok(sync_mempool(txid), "transaction relayed to the second node")
mine(0)
sync()
ok(rpc(1, "getblockcount") == rpc(0, "getblockcount"), "block with the transaction accepted by the second node")

# Spend the post-quantum coins: ML-DSA-44 signatures checked by OP_CHECKSIGPQ
pq2 = rpc(1, "getnewaddress")
utxo = [u for u in rpc(0, "listunspent", 1) if u["address"] == pq1][0]
signed = spend_utxo(0, utxo, pq2)
ok(signed["complete"], "post-quantum input signed")
size = len(signed["hex"]) // 2
ok(3700 < size < 4000, "transaction size with a post-quantum input: %d bytes" % size)
txid = rpc(0, "sendrawtransaction", signed["hex"])
ok(sync_mempool(txid), "post-quantum spend accepted and relayed")
mine(0)
sync()
ok(rpc(1, "gettransaction", txid)["confirmations"] == 1, "post-quantum spend confirmed, received by node 2")
ok(abs(rpc(1, "getbalance") - (utxo["amount"] - 0.01)) < 1e-6, "node 2 balance %s" % rpc(1, "getbalance"))

# A tampered post-quantum signature is rejected
utxo2 = [u for u in rpc(1, "listunspent", 1)][0]
signed = spend_utxo(1, utxo2, pq1)
raw = bytearray.fromhex(signed["hex"])
raw[200] ^= 1
err = rpc_err(1, "sendrawtransaction", raw.hex())
ok(err is not None, "transaction with a modified post-quantum signature rejected")

# Key backup: dumpprivkey on node 1, importprivkey on node 2
secret = rpc(0, "dumpprivkey", pq1)
ok(secret.startswith("TK"), "dumpprivkey gives a post-quantum secret")
rpc(1, "importprivkey", secret, "imported")
ok(rpc(1, "validateaddress", pq1)["ismine"], "importprivkey: node 2 owns the address")

# Mature post-quantum coinbase and spend it
mine(0, 16)
sync()
utxo = [u for u in rpc(0, "listunspent", 1)
        if rpc(0, "validateaddress", u["address"])["ispostquantum"] and u["amount"] >= 10000][0]
signed = spend_utxo(0, utxo, pq2)
txid = rpc(0, "sendrawtransaction", signed["hex"])
mine(0)
sync()
ok(rpc(0, "gettransaction", txid)["confirmations"] == 1, "post-quantum coinbase spent")
legacy_utxos = [u for u in rpc(0, "listunspent", 1) if not rpc(0, "validateaddress", u["address"])["ispostquantum"]]
ok(len(legacy_utxos) > 0, "node 1 still has ECDSA coins: %d" % len(legacy_utxos))
sunset = next_switch_time(0)
stop(procs)

print("== Phase 3: after the ECDSA sunset")
times = ["-pqforktime=%d" % fork, "-ecdsasunsettime=%d" % sunset]
procs = [start(0, times), start(1, times)]
wait_connected()
ok(rpc(0, "getinfo")["postquantum"]["ecdsasunset"], "ECDSA sunset active")
signed = spend_utxo(0, legacy_utxos[0], pq2)
err = rpc_err(0, "sendrawtransaction", signed["hex"])
ok(err is not None, "ECDSA signature rejected after the sunset")
utxo = [u for u in rpc(0, "listunspent", 1) if rpc(0, "validateaddress", u["address"])["ispostquantum"]][0]
signed = spend_utxo(0, utxo, pq2)
txid = rpc(0, "sendrawtransaction", signed["hex"])
mine(0)
sync()
ok(rpc(1, "gettransaction", txid)["confirmations"] == 1, "post-quantum spend after the sunset confirmed")
# The wallet only selects coins that are still spendable
txid = rpc(0, "sendtoaddress", pq2, 100)
ok(sync_mempool(txid), "sendtoaddress after the sunset uses post-quantum coins only")
mine(0)
sync()
ok(rpc(1, "gettransaction", txid)["confirmations"] == 1, "and is confirmed")
stop(procs)

print("ALL %d CHECKS PASSED" % checks)
