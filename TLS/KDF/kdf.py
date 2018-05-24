from TLS.HMAC.hmac import *


def KDF_TREE_256(K, label, seed, R, L, i):
    """
    :param K: input key
    :param L: length_of_key_material
    :param i: number_of_key
    :return: K(i)
    """
    return hmac256(K, i.to_bytes(R, byteorder="big") + label + bytes([0]) + seed +
                   L.to_bytes((L.bit_length() + 7) // 8, byteorder="big"))
