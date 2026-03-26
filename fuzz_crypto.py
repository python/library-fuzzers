from fuzz_dp import FuzzedDataProvider
import hashlib
import hmac
import io

import _md5, _sha1, _sha2, _sha3, _blake2, _hmac

HASH_CTORS = [
    _md5.md5, _sha1.sha1,
    _sha2.sha224, _sha2.sha256, _sha2.sha384, _sha2.sha512,
    _sha3.sha3_224, _sha3.sha3_256, _sha3.sha3_384, _sha3.sha3_512,
    _blake2.blake2b, _blake2.blake2s,
]
SHAKE_CTORS = [_sha3.shake_128, _sha3.shake_256]

HMAC_COMPUTE_FUNCS = [
    getattr(_hmac, name)
    for name in ['compute_md5', 'compute_sha1', 'compute_sha256', 'compute_sha512']
    if hasattr(_hmac, name)
]

HMAC_ALGOS = ['md5', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3_256', 'blake2s']
PBKDF2_ALGOS = ['sha1', 'sha256', 'sha512']
HASHLIB_ALGOS = ['md5', 'sha256', 'sha3_256', 'sha512']

# --- chain_hash_actions action constants ---
HASH_ACTION_UPDATE = 0
HASH_ACTION_DIGEST = 1
HASH_ACTION_HEXDIGEST = 2
HASH_ACTION_COPY_DIGEST = 3
HASH_ACTION_READ_ATTRS = 4

# --- op_shake_chain action constants ---
SHAKE_ACTION_UPDATE = 0
SHAKE_ACTION_DIGEST = 1
SHAKE_ACTION_COPY_DIGEST = 2

# --- FuzzerRunOne operation constants ---
OP_HASH_CHAIN = 0
OP_SHAKE_CHAIN = 1
OP_BLAKE2B_KEYED = 2
OP_BLAKE2S_KEYED = 3
OP_BLAKE2B_VARDIGEST = 4
OP_BLAKE2S_VARDIGEST = 5
OP_HMAC_COMPUTE = 6
OP_PYHMAC_CHAIN = 7
OP_HMAC_DIGEST = 8
OP_HMAC_COMPARE = 9
OP_HASHLIB_CHAIN = 10
OP_HASHLIB_FILE_DIGEST = 11
OP_PBKDF2 = 12

def chain_hash_actions(h, fdp):
    for _ in range(fdp.ConsumeIntInRange(1, 100)):
        if fdp.remaining_bytes() == 0:
            break
        action = fdp.ConsumeIntInRange(HASH_ACTION_UPDATE, HASH_ACTION_READ_ATTRS)
        if action == HASH_ACTION_UPDATE:
            n = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 10000))
            h.update(fdp.ConsumeBytes(n))
        elif action == HASH_ACTION_DIGEST:
            h.digest()
        elif action == HASH_ACTION_HEXDIGEST:
            h.hexdigest()
        elif action == HASH_ACTION_COPY_DIGEST:
            h.copy().digest()
        elif action == HASH_ACTION_READ_ATTRS:
            _ = h.name
            _ = h.digest_size
            _ = h.block_size

def op_hash_chain(fdp):
    ctor = fdp.PickValueInList(HASH_CTORS)
    n = fdp.ConsumeIntInRange(0, 10000)
    init_data = fdp.ConsumeBytes(n)
    h = ctor(init_data)
    chain_hash_actions(h, fdp)

def op_shake_chain(fdp):
    ctor = fdp.PickValueInList(SHAKE_CTORS)
    n = fdp.ConsumeIntInRange(0, 10000)
    init_data = fdp.ConsumeBytes(n)
    h = ctor(init_data)
    for _ in range(fdp.ConsumeIntInRange(1, 100)):
        if fdp.remaining_bytes() == 0:
            break
        action = fdp.ConsumeIntInRange(SHAKE_ACTION_UPDATE, SHAKE_ACTION_COPY_DIGEST)
        if action == SHAKE_ACTION_UPDATE:
            n2 = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 10000))
            h.update(fdp.ConsumeBytes(n2))
        elif action == SHAKE_ACTION_DIGEST:
            length = fdp.ConsumeIntInRange(1, 10000)
            h.digest(length)
        elif action == SHAKE_ACTION_COPY_DIGEST:
            h2 = h.copy()
            length = fdp.ConsumeIntInRange(1, 10000)
            h2.digest(length)

def op_blake2_keyed(fdp, ctor, max_key, max_salt, max_person):
    key_len = fdp.ConsumeIntInRange(0, max_key)
    key = fdp.ConsumeBytes(key_len)
    salt_len = fdp.ConsumeIntInRange(0, max_salt)
    salt = fdp.ConsumeBytes(salt_len)
    person_len = fdp.ConsumeIntInRange(0, max_person)
    person = fdp.ConsumeBytes(person_len)
    n = fdp.ConsumeIntInRange(0, 10000)
    data = fdp.ConsumeBytes(n)
    h = ctor(data, key=key, salt=salt, person=person)
    chain_hash_actions(h, fdp)

def op_blake2_vardigest(fdp, ctor, max_ds):
    ds = fdp.ConsumeIntInRange(1, max_ds)
    n = fdp.ConsumeIntInRange(0, 10000)
    data = fdp.ConsumeBytes(n)
    h = ctor(data, digest_size=ds)
    chain_hash_actions(h, fdp)

def op_hmac_compute(fdp):
    if not HMAC_COMPUTE_FUNCS:
        return
    func = fdp.PickValueInList(HMAC_COMPUTE_FUNCS)
    key_len = fdp.ConsumeIntInRange(1, 10000)
    key = fdp.ConsumeBytes(key_len) or b'\x00'
    msg = fdp.ConsumeBytes(fdp.remaining_bytes())
    func(key, msg)

def op_pyhmac_chain(fdp):
    algo = fdp.PickValueInList(HMAC_ALGOS)
    key_len = fdp.ConsumeIntInRange(1, 10000)
    key = fdp.ConsumeBytes(key_len) or b'\x00'
    h = hmac.new(key, digestmod=algo)
    chain_hash_actions(h, fdp)

def op_hmac_digest(fdp):
    key_len = fdp.ConsumeIntInRange(1, 10000)
    key = fdp.ConsumeBytes(key_len) or b'\x00'
    msg = fdp.ConsumeBytes(fdp.remaining_bytes())
    hmac.digest(key, msg, 'sha256')

def op_hmac_compare(fdp):
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    h = hmac.new(b'k', data, 'sha256')
    dig = h.digest()
    cmp_data = fdp.ConsumeBytes(len(dig))
    hmac.compare_digest(dig, cmp_data)

def op_hashlib_chain(fdp):
    algo = fdp.PickValueInList(HASHLIB_ALGOS)
    n = fdp.ConsumeIntInRange(0, 10000)
    init_data = fdp.ConsumeBytes(n)
    h = hashlib.new(algo, init_data, usedforsecurity=False)
    chain_hash_actions(h, fdp)

def op_hashlib_file_digest(fdp):
    algo = fdp.PickValueInList(HASHLIB_ALGOS)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    bio = io.BytesIO(data)
    h = hashlib.file_digest(bio, algo)
    h.hexdigest()

def op_pbkdf2(fdp):
    algo = fdp.PickValueInList(PBKDF2_ALGOS)
    salt_len = fdp.ConsumeIntInRange(1, 10000)
    salt = fdp.ConsumeBytes(salt_len) or b'\x00'
    pw = fdp.ConsumeBytes(fdp.remaining_bytes())
    hashlib.pbkdf2_hmac(algo, pw, salt, 1)

# Fuzzes CPython's cryptographic C modules (Modules/_hashopenssl.c,
# Modules/blake2module.c, Modules/sha2module.c, Modules/sha3module.c,
# Modules/hmacmodule.c). Exercises hash chains with update/digest/copy
# for MD5, SHA-1/2/3, BLAKE2b/s (with key/salt/personalization), SHAKE
# variable-length digests, HMAC construction and comparison, file_digest,
# and PBKDF2 key derivation.
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(OP_HASH_CHAIN, OP_PBKDF2)
    try:
        if op == OP_HASH_CHAIN:
            op_hash_chain(fdp)
        elif op == OP_SHAKE_CHAIN:
            op_shake_chain(fdp)
        elif op == OP_BLAKE2B_KEYED:
            op_blake2_keyed(fdp, hashlib.blake2b, 64, 16, 16)
        elif op == OP_BLAKE2S_KEYED:
            op_blake2_keyed(fdp, hashlib.blake2s, 32, 8, 8)
        elif op == OP_BLAKE2B_VARDIGEST:
            op_blake2_vardigest(fdp, hashlib.blake2b, 64)
        elif op == OP_BLAKE2S_VARDIGEST:
            op_blake2_vardigest(fdp, hashlib.blake2s, 32)
        elif op == OP_HMAC_COMPUTE:
            op_hmac_compute(fdp)
        elif op == OP_PYHMAC_CHAIN:
            op_pyhmac_chain(fdp)
        elif op == OP_HMAC_DIGEST:
            op_hmac_digest(fdp)
        elif op == OP_HMAC_COMPARE:
            op_hmac_compare(fdp)
        elif op == OP_HASHLIB_CHAIN:
            op_hashlib_chain(fdp)
        elif op == OP_HASHLIB_FILE_DIGEST:
            op_hashlib_file_digest(fdp)
        elif op == OP_PBKDF2:
            op_pbkdf2(fdp)
    except Exception:
        pass
