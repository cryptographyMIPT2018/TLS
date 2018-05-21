import hashlib

from TLS.hash.hash import *


def printb(bytes):
    print(len(bytes))
    print(", ".join(hex(x) for x in bytes))


def Xor(a, b):
    assert (len(a) == len(b))
    return bytes(x ^ y for x, y in zip(a, b))


def stratch(K):
    return bytes((list(K) + [0] * 64)[:64])


def hmac(K, data, hash_fun):
    K = stratch(K)
    print("K")
    printb(K)
    ipad = bytes([0x36] * 64)
    opad = bytes([0x5C] * 64)
    printb(Xor(K, ipad))
    print("1 hash")
    printb(hash_fun(Xor(K, ipad) + data))
    print("---")
    mid = hash_fun(Xor(K, ipad) + data)
    printb(mid)
    mid = Xor(K, opad) + mid
    printb(Xor(K, opad))
    printb(mid)
    printb(hash_fun(mid))
    print("----")
    return hash_fun(Xor(K, opad) + hash_fun(Xor(K, ipad) + data))


def sha(data):
    result = hashlib.sha1(data).hexdigest()
    return bytes.fromhex(result)


def hmac_sha(K, data):
    return hmac(K, data, sha)


def hmac256(K, data):
    return hmac(K, data, hash256)


def hmac512(K, data):
    return hmac(K, data, hash512)
