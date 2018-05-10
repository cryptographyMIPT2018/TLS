#!/usr/bin/python3

import unittest
import re
import pprint

from elliptic_curve import Point, EllipticCurve

HEADER = ['p', 'a', 'b', 'm', 'q', 'x', 'y']

pprint = pprint.PrettyPrinter(indent=4).pprint

SET_A_STR = """
INTEGER
 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FD
 C7
 INTEGER
 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FD
 C4
 INTEGER
 00 E8 C2 50 5D ED FC 86 DD C1 BD 0B 2B 66 67 F1
 DA 34 B8 25 74 76 1C B0 E8 79 BD 08 1C FD 0B 62
 65 EE 3C B0 90 F3 0D 27 61 4C B4 57 40 10 DA 90
 DD 86 2E F9 D4 EB EE 47 61 50 31 90 78 5A 71 C7
 60
 INTEGER
 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
 FF 27 E6 95 32 F4 8D 89 11 6F F2 2B 8D 4E 05 60
 60 9B 4B 38 AB FA D2 B8 5D CA CD B1 41 1F 10 B2
 75
 INTEGER
 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
 FF 27 E6 95 32 F4 8D 89 11 6F F2 2B 8D 4E 05 60
 60 9B 4B 38 AB FA D2 B8 5D CA CD B1 41 1F 10 B2
 75
 INTEGER
 03
 INTEGER
 75 03 CF E8 7A 83 6A E3 A6 1B 88 16 E2 54 50 E6
 CE 5E 1C 93 AC F1 AB C1 77 80 64 FD CB EF A9 21
 DF 16 26 BE 4F D0 36 E9 3D 75 E6 A5 0E 3A 41 E9
 80 28 FE 5F C2 35 F5 B8 89 A5 89 CB 52 15 F2 A4
 }
"""

SET_B_STR = """
INTEGER
 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 6F
 INTEGER
 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 6C
 INTEGER
 68 7D 1B 45 9D C8 41 45 7E 3E 06 CF 6F 5E 25 17
 B9 7C 7D 61 4A F1 38 BC BF 85 DC 80 6C 4B 28 9F
 3E 96 5D 2D B1 41 6D 21 7F 8B 27 6F AD 1A B6 9C
 50 F7 8B EE 1F A3 10 6E FB 8C CB C7 C5 14 01 16
 INTEGER
 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 01 49 A1 EC 14 25 65 A5 45 AC FD B7 7B D9 D4 0C
 FA 8B 99 67 12 10 1B EA 0E C6 34 6C 54 37 4F 25
 BD
 INTEGER
 00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 01 49 A1 EC 14 25 65 A5 45 AC FD B7 7B D9 D4 0C
 FA 8B 99 67 12 10 1B EA 0E C6 34 6C 54 37 4F 25
 BD
 INTEGER
 02
 INTEGER
 1A 8F 7E DA 38 9B 09 4C 2C 07 1E 36 47 A8 94 0F
 3C 12 3B 69 75 78 C2 13 BE 6D D9 E6 C8 EC 73 35
 DC B2 28 FD 1E DF 4A 39 15 2C BC AA F8 C0 39 88
 28 04 10 55 F9 4C EE EC 7E 21 34 07 80 FE 41 BD
"""


def hex_str_to_int(s):
    return int(re.sub(r"[^\w\d]", "", s), 16)


def split_gost_integers(text):
    return list(filter(lambda s: len(s) > 0, map(str.strip, text.split("INTEGER"))))


def parse_gost_integers(text):
    return list(map(hex_str_to_int, split_gost_integers(text)))


def parse_curve_parameters(text):
    return dict(zip(HEADER, parse_gost_integers(text)))


class TestPoint(unittest.TestCase):

    def test_eq(self):
        self.assertTrue(Point(2, 2, 1) == Point(4, 4, 2))
        self.assertTrue(Point(9, 1, 1) == Point(36, 4, 4))
        self.assertTrue(Point(3, 0, 1) == Point(-6, 0, -2))
        self.assertTrue(Point(2, 2, 0) == Point(4, 4, 0))
        self.assertTrue(Point(2, 0, 0) == Point(4, 0, 0))
        self.assertTrue(Point(-1, 1, 1) == Point(1, -1, -1))

        self.assertTrue(Point(0, 0, 0) != Point(4, 0, 0))
        self.assertTrue(Point(-1, 2, 0) != Point(4, 0, 0))
        self.assertTrue(Point(-1, 1, 0) != Point(1, -1, 0))
        self.assertTrue(Point(4, 1, 1) != Point(1, -1, -1))
        self.assertTrue(Point(-1, 4, 1) != Point(1, 7, 2))


class TestEllipticCurve(unittest.TestCase):

    def test_compare_parameters_with_gost_text(self):
        # ~ pprint(parse_curve_parameters(SET_A_STR))
        # ~ pprint(parse_curve_parameters(SET_B_STR))
        self.assertEqual(parse_curve_parameters(SET_A_STR), EllipticCurve.PARAMETERS['A'])
        self.assertEqual(parse_curve_parameters(SET_B_STR), EllipticCurve.PARAMETERS['B'])

    def test_correctness_of_parameters(self):
        ec = EllipticCurve('A')
        self.assertTrue(ec.is_on_curve(ec.get_forming()))
        ec = EllipticCurve('B')
        self.assertTrue(ec.is_on_curve(ec.get_forming()))

    def test_multiply_by_number(self):
        ec = EllipticCurve('A')
        a = ec.get_forming()
        for k in [-1233535, 1231, 0, -1, 1, 1231341]:
            self.assertTrue(ec.is_on_curve(ec.multiply_by_number(a, k)))
        mul = ec.multiply_by_number
        self.assertEqual(mul(mul(a, 10), 10), mul(a, 100))
        self.assertEqual(mul(mul(a, 2), -3), mul(a, -6))
        self.assertEqual(mul(mul(a, -4), 7), mul(a, -28))
        self.assertEqual(mul(mul(a, 123), -122), mul(a, 1))
        self.assertEqual(mul(a, ec.get_zero()), a)

    def test_summ(self):
        ec = EllipticCurve("test")
        point_a = Point(17, 10)
        point_b = Point(95, 31)
        ref = Point(1, 54)
        result = ec.summ(point_a, point_b)

        def point_eq(point1, point2):
            return (point1.x, point1.y, point1.z) == (point2.x, point2.y, point2.z)

        self.assertTrue(point_eq(result, ref))

    def test_is_on_curve(self):
        pass

    def test_split(self):
        pass


if __name__ == '__main__':
    unittest.main()
