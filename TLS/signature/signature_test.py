#!/usr/bin/python3

import unittest
import pprint
import random
import sys

# dirty hack, because I don't understand how to properly make packages
sys.path.append("../elliptic")

from elliptic_curve import EllipticCurve
from signature import Signer

TEST_CURVE_PARAMETERS = {
    'a': 7,
    'b': 43308876546767276905765904595650931995942111794451039583252968842033849580414,
    'm': 57896044618658097711785492504343953927082934583725450622380973592137631069619,
    'p': 57896044618658097711785492504343953926634992332820282019728792003956564821041,
    'q': 57896044618658097711785492504343953927082934583725450622380973592137631069619,
    'x': 2,
    'y': 4018974056539037503335449422937059775635739389905545080690979365213431566280
}

class TestSigner(unittest.TestCase):

    def test_acceptance(self):
        h = lambda m: hash(m).to_bytes(256, byteorder='little')
        signer = Signer(EllipticCurve(curve=TEST_CURVE_PARAMETERS), h, 12345)
        text = "Hello, world!"
        signature = signer.sign(text)
        self.assertTrue(signer.check(text, signature))
        self.assertFalse(signer.check(text, signature + b'\00'))
        self.assertFalse(signer.check(text, signature[:-1] + b'\00'))


if __name__ == '__main__':
    unittest.main()
