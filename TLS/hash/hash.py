from TLS.hash.basic_transforms import *


def S(data):
    return pi_permutation(data)


def P(data):
    return bytes(reversed(byte_shuffle(reversed(data))))


def L(data):
    return linear512(data)


def X(k, h):
    assert (len(k) == 64)
    assert (len(h) == 64)
    return bytes(a ^ b for a, b in zip(k, h))


def g(h, m, N):
    assert (len(h) == 64)
    assert (len(m) == 64)
    assert (len(N) == 64)
    C = [
        "b1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507",
        "6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b501319ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7",
        "f574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7bd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2",
        "ef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353fa9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e",
        "4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbdbfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57",
        "ae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e",
        "f4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c90992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493",
        "9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49af4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e",
        "378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb",
        "abbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b3361039fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced",
        "7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b",
        "378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720"
    ]
    C = [bytes(x) for x in C]
    K = X(h, N)
    E = m
    for i in range(13):
        E = X(K, E)
        if i < 12:
            K = X(C[i], K)
            K = L(P(S(K)))
            E = L(P(S(E)))

    return X(X(E, h), m)


def hash256(data, length):
    """
    :param length: length in bits
    """
    return hash_function(data, length, 256)


def hash512(data, length):
    """
    :param length: length in bits
    """

    return hash_function(data, length, 512)


def hash_function(data, length, output_size=512):
    """
    :param data: data should be right aligned (
    :param length: length in bits
    :return: hash of data with  output_size length
    """

    assert (len(data) * 8 >= length > (len(data) - 1) * 8)
    if output_size == 256:
        IV = bytes([1] * 64)
        crop = True
    elif output_size == 512:
        IV = bytes([0] * 64)
        crop = False
    else:
        raise AttributeError("output size {} is incorrect, 256 or 512 expected")
    N = bytes([0] * 64)
    Sigma = bytes([0] * 64)
    h = IV
    while length >= 512:
        end = data[-64:]
        data = data[:-64]
        length -= 512
        h = g(h, end, N)
        N = int.from_bytes(N, byteorder="big")
        N = (N + 512) % (2 ** 512)
        N = N.to_bytes(64, byteorder="big")
        Sigma = int.from_bytes(N, byteorder="big")
        Sigma = (Sigma + int.from_bytes(h, byteorder="big")) % (2 ** 512)
        Sigma = Sigma.to_bytes(64, byteorder="big")
    if length % 8 == 0:
        data = bytes([1] + list(data))

    else:
        data = bytes([data[0] | (1 << length % 8)] + list(data[1:]))
    data = bytes([0] * (length // 8 - 1) + list(data))
    h = g(h, data, N)
    N = int.from_bytes(N, byteorder="big")
    N = (N + length) % (2 ** 512)
    N = N.to_bytes(64, byteorder="big")
    Sigma = int.from_bytes(N, byteorder="big")
    Sigma = (Sigma + int.from_bytes(data, byteorder="big")) % (2 ** 512)
    Sigma = Sigma.to_bytes(64, byteorder="big")
    h = g(h, N, bytes([0] * 64))
    h = g(h, Sigma, bytes([0] * 64))
    if crop:
        h = h[:32]
    return h
