from TLS.hash.basic_transforms import *


def hash256(data):
    return hash_function(data, 8 * len(data), 256)


def hash512(data):
    """
    :param length: length in bits
    """

    return hash_function(data, 8 * len(data), 512)


def hash256_bit_length(data, length):
    """
    :param length: length in bits
    """
    return hash_function(data, length, 256)


def hash512_bit_length(data, length):
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
        Sigma = int.from_bytes(Sigma, byteorder="big")
        Sigma = (Sigma + int.from_bytes(end, byteorder="big")) % (2 ** 512)
        Sigma = Sigma.to_bytes(64, byteorder="big")
    if length % 8 == 0:
        data = bytes([1] + list(data))

    else:
        data = bytes([data[0] | (1 << length % 8)] + list(data[1:]))
    data = bytes([0] * (64 - length // 8 - 1) + list(data))
    h = g(h, data, N)
    N = int.from_bytes(N, byteorder="big")
    N = (N + length) % (2 ** 512)
    N = N.to_bytes(64, byteorder="big")
    Sigma = int.from_bytes(Sigma, byteorder="big")
    Sigma = (Sigma + int.from_bytes(data, byteorder="big")) % (2 ** 512)
    Sigma = Sigma.to_bytes(64, byteorder="big")
    h = g(h, N, bytes([0] * 64))
    h = g(h, Sigma, bytes([0] * 64))
    if crop:
        h = h[:32]
    return h
