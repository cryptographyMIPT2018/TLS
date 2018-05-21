#!/usr/bin/python3

import unittest
import pprint
import random
import sys
import ctypes

if __name__ == '__main__':
    # dirty hack, because I don't understand how to properly make packages
    sys.path.append("../elliptic")
    sys.path.append("../hash")
    sys.path.append("../")
    sys.path.append("../..")

from elliptic_curve import EllipticCurve
from signature import Signer
from hash import hash256

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
        signer = Signer(EllipticCurve(curve=TEST_CURVE_PARAMETERS), d=12345)
        text = b"Hello, world!"
        signature = signer.sign(text)
        self.assertTrue(signer.check(text, signature))
        self.assertFalse(signer.check(text, signature + b'\00'))
        self.assertFalse(signer.check(text, signature[:-1] + b'\00'))

    def test_white_box(self):
        d = 55441196065363246126355624130324183196576709222340016572108097750006097525544
        signer = Signer(EllipticCurve(curve=TEST_CURVE_PARAMETERS), d=d)
        self.assertEqual(signer.Q.x, 57520216126176808443631405023338071176630104906313632182896741342206604859403)
        self.assertEqual(signer.Q.y, 17614944419213781543809391949654080031942662045363639260709847859438286763994)
        self.assertEqual(signer.Q.z, 1)
        inner_params = {}
        signature = signer.sign(b"",
            force_e=20798893674476452017134061561508270130637142515379653289952617252661468872421,
            force_k=53854137677348463731403841147996619241504003434302020712960838528893196233395,
            inner_params_out=inner_params)

        self.assertEqual(inner_params['C'].x, 29700980915817952874371204983938256990422752107994319651632687982059210933395)
        self.assertEqual(inner_params['C'].y, 32842535278684663477094665322517084506804721032454543268132854556539274060910)
        self.assertEqual(inner_params['C'].z, 1)
        self.assertEqual(inner_params['r'], 29700980915817952874371204983938256990422752107994319651632687982059210933395)
        self.assertEqual(inner_params['s'], 574973400270084654178925310019147038455227042649098563933718999175515839552)


if __name__ == '__main__':
    unittest.main()
