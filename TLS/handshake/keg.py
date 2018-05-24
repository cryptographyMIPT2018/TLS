def KEG(d, Q, h):
    r = int(h[:16])
    UKM = r if r != b'\x00' else 1
