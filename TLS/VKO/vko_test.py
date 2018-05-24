import unittest

from TLS.VKO.vko import *


class VKOTest1(unittest.TestCase):
    def test_vko(self):
        UMK = int.from_bytes(bytes.fromhex("1d 80 60 3c 85 44 c7 27"), "little")
        x = int.from_bytes(bytes.fromhex(
            "c9 90 ec d9 72 fc e8 4e c4 db 02 27 78 f5 0f ca c7 26 f4 67 08 38 4b 8d 45 83 04 96 2d 71 47 f8 c2 db 41 ce f2 2c 90 b1 02 f2 96 84 04 f9 b9 be 6d 47 c7 96 92 d8 18 26 b3 2b 8d ac a4 3c b6 67"),
                           "little")
        y = int.from_bytes(bytes.fromhex(
            "48 c8 59 f7 b6 f1 15 85 88 7c c0 5e c6 ef 13 90 cf ea 73 9b 1a 18 c0 d4 66 22 93 ef 63 b7 9e 3b 80 14 07 0b 44 91 85 90 b4 b9 96 ac fe a4 ed fb bb cc cc 8c 06 ed d8 bf 5b da 92 a5 13 92 d0 db"),
                           "little")

        curve = EllipticCurve("A")
        P = curve.get_forming()
        X = curve.multiply_by_number(P, x)
        Y = curve.multiply_by_number(P, y)
        X_answer = bytes.fromhex("aa b0 ed a4 ab ff 21 20 8d 18 79 9f b9 a8 55 66 54 ba 78 30 70 eb a1 0c b9 ab b2 53 ec 56 dc f5 d3 cc ba 61 92 e4 64 e6 e5 bc b6 de a1 37 79 2f 24 31 f6 c8 97 eb 1b 3c 0c c1 43 27 b1 ad c0 a7 91 46 13 a3 07 4e 36 3a ed b2 04 d3 8d 35 63 97 1b d8 75 8e 87 8c 9d b1 14 03 72 1b 48 00 2d 38 46 1f 92 47 2d 40 ea 92 f9 95 8c 0f fa 4c 93 75 64 01 b9 7f 89 fd be 0b 5e 46 e4 a4 63 1c db 5a")
        self.assertEqual(X_answer, X.to_bytes())
        Y_answer = bytes.fromhex("19 2f e1 83 b9 71 3a 07 72 53 c7 2c 87 35 de 2e a4 2a 3d bc 66 ea 31 78 38 b6 5f a3 25 23 cd 5e fc a9 74 ed a7 c8 63 f4 95 4d 11 47 f1 f2 b2 5c 39 5f ce 1c 12 91 75 e8 76 d1 32 e9 4e d5 a6 51 04 88 3b 41 4c 9b 59 2e c4 dc 84 82 6f 07 d0 b6 d9 00 6d da 17 6c e4 8c 39 1e 3f 97 d1 02 e0 3b b5 98 bf 13 2a 22 8a 45 f7 20 1a ba 08 fc 52 4a 2d 77 e4 3a 36 2a b0 22 ad 40 28 f7 5b de 3b 79")
        self.assertEqual(Y_answer, Y.to_bytes())
        KEK_X = KEK_VKO(x, Y, UMK, curve)
        KEK_Y = KEK_VKO(y, X, UMK, curve)
        self.assertEqual(KEK_X, KEK_Y)
        KEK_answer = bytes.fromhex("c9 a9 a7 73 20 e2 cc 55 9e d7 2d ce 6f 47 e2 192c ce a9 5f a6 48 67 05 82 c0 54 c0 ef 36 c2 21")
        self.assertEqual(KEK_X, KEK_answer)

if __name__ == '__main__':
    unittest.main()


