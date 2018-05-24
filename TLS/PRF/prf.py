from TLS.HMAC.hmac import *


def prf256(secret, label, seed, length):
    answer = bytes(0)
    S = label + seed
    A = hmac256(secret, S)
    for i in range(length):
        answer += hmac256(secret, A + S)
        A = A = hmac256(secret, A)
    return answer
