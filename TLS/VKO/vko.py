from TLS.elliptic.elliptic_curve import  *
from TLS.hash.hash import *

def K(x, Y, UMK, curve):
    multiplicator = curve.m // curve.q * UMK * (x % curve.q)
    return curve.multiply_by_number(Y, multiplicator)

def KEK_VKO256(x, Y, UMK, curve):
    return bytes(list(reversed(hash256(bytes(list(reversed(K(x, Y, UMK, curve).to_bytes())))))))

def KEK_VKO512(x, Y, UMK, curve):
    return bytes(list(reversed(hash512(bytes(list(reversed(K(x, Y, UMK, curve).to_bytes())))))))
