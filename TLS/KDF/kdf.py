from TLS.HMAC.hmac import *


def KDF_TREE_256(K, label, seed, R, L, i):
    return hmac256(K, i.to_bytes(R, byteorder="big") + label + bytes([0]) + seed +
                   L.to_bytes((L.bit_length() + 7) // 8, byteorder="big"))
