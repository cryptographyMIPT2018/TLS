from TLS.VKO.vko import KEK_VKO512
from TLS.elliptic.elliptic_curve import EllipticCurve

def KEG(d, Q, h):
    r = int(h[:16])
    UKM = r if r != b'\x00' else 1
    return KEK_VKO512(d, Q, UKM, EllipticCurve("C"))
