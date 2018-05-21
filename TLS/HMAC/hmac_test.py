# import unittest

from TLS.HMAC.hmac import *


# class HmacTest1(unittest.TestCase):
#     def test_hash_256(self):
#         key = bytes.fromhex("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f")
#         data = bytes.fromhex("01 26 bd b8 78 00 af 21 43 41 45 65 63 78 01 00")
#         self.assertEqual(hmac256(key, data), bytes.fromhex("a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34 01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9"))

"a5 9b ab 22 ec ae 19 c6 5f bd e6 e5 f4 e9 f5 d8 54 9d 31 f0 37 f9 df 9b 90 55 00 e1 71 92 3a 77 3d 5f 15 30 f2 ed 7e 96 4c b2 ee dc 29 e9 ad 2f 3a fe 93 b2 81 4f 79 f5 00 0f fc 03 66 c2 51 e6"


def printb(bytes):
    print(len(bytes))
    print("|".join(hex(x) for x in bytes))

if __name__ == '__main__':

    # key = bytes.fromhex(
    #     "70717273 74757677 78797a7b 7c7d7e7f 80818283")
    # data = bytes.fromhex("48656c6c 6f20576f 726c64")
    key = bytes.fromhex(
        "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f")
    data = bytes.fromhex("01 26 bd b8 78 00 af 21 43 41 45 65 63 78 01 00")

    printb(key)
    printb(data)
    printb(hmac512(key, data))
    printb(bytes.fromhex("a5 9b ab 22 ec ae 19 c6 5f bd e6 e5 f4 e9 f5 d8 54 9d 31 f0 37 f9 df 9b 90 55 00 e1 71 92 3a 77 3d 5f 15 30 f2 ed 7e 96 4c b2 ee dc 29 e9 ad 2f 3a fe 93 b2 81 4f 79 f5 00 0f fc 03 66 c2 51 e6"))

    # unittest.main()
