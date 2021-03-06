import hashlib

from TLS.hash.hash import *


def Xor(a, b):
    assert (len(a) == len(b))
    return bytes(x ^ y for x, y in zip(a, b))


def stratch(K):
    return (list(K) + [0] * 64)[:64]


def hmac(K, data, hash_fun):
    K = stratch(K)
    ipad = bytes([0x36] * 64)
    opad = bytes([0x5C] * 64)
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
