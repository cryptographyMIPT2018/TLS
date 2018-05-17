import random

from elliptic_curve import Point, EllipticCurve

TEST_CURVE_PARAMETERS = {
    'a': 7,
    'b': 43308876546767276905765904595650931995942111794451039583252968842033849580414,
    'm': 57896044618658097711785492504343953927082934583725450622380973592137631069619,
    'p': 57896044618658097711785492504343953926634992332820282019728792003956564821041,
    'q': 57896044618658097711785492504343953927082934583725450622380973592137631069619,
    'x': 2,
    'y': 4018974056539037503335449422937059775635739389905545080690979365213431566280
}

class Signer:

    def __init__(self, curve, hash_f, d=None, Q=None):
        self.curve = curve
        self.hash_f = hash_f
        self.d = d
        self.Q = Q
        if self.d is not None:
            self.Q = curve.multiply_by_number(curve.get_forming(), d)

    def e_from_h(self, h):
        a = int.from_bytes(h, byteorder='little', signed=False)
        e = a % self.curve.q
        if e == 0:
            e = 1
        return e

    def get_point_x(self, c):
        p = self.curve.p
        return (c.x * pow(c.z, p - 2, p)) % p

    def sign(self, m):
        # Notice, that indexing in python bytes is from left to right
        # but in standart it is from right to left
        # Here indexes are correct, while left-right relations are not

        assert(self.curve is not None)
        assert(self.d is not None)

        # step 1
        h = self.hash_f(m)

        # step 2
        e = self.e_from_h(h)

        q = self.curve.q
        while True:
            while True:
                # step 3
                k = random.randint(1, q - 1)

                # step 4
                P = self.curve.get_forming()
                C = self.curve.multiply_by_number(P, k)
                r = self.get_point_x(C) % q

                if r != 0:
                    break

            # step 5
            s = (r * self.d + k * e) % q

            if s != 0:
                break

        # step 6
        sv = s.to_bytes(32, byteorder='little')
        rv = r.to_bytes(32, byteorder='little')

        signature = sv + rv

        return signature

    def check(self, m, signature):
        assert(self.curve is not None)
        assert(self.Q is not None)

        # step 1
        if len(signature) != 64:
            return False
        s = int.from_bytes(signature[:32], byteorder='little', signed=False)
        r = int.from_bytes(signature[32:], byteorder='little', signed=False)
        q = self.curve.q
        if not 0 < s < q or not 0 < r < q:
            return False

        # step 2
        h = self.hash_f(m)

        # step 3
        e = self.e_from_h(h)

        # step 4
        v = pow(e, q - 2, q)

        # step 5
        z1 = (s * v) % q
        z2 = (q - (r * v) % q) % q

        # step 6
        P = self.curve.get_forming()
        C = self.curve.summ(self.curve.multiply_by_number(P, z1),
                            self.curve.multiply_by_number(self.Q, z2))
        R = self.get_point_x(C) % q

        # step 7
        return r == R
