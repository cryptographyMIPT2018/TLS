import sys
import os

cert_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(cert_dir, '../../'))

from TLS.elliptic.elliptic_curve import Point
from TLS.certificates.certificate import get_public_key, get_certificate_bytes, get_id, verify_certificate
import unittest


class TestCertificateFunctions(unittest.TestCase):
    fake_cert_bytes = b'\x01' + b'\x00' * 128
    x_bytes = int.to_bytes(3142295020441544971238076848556545922102739883486524028948654960522718845415850766758333141890805990252830768512042535852276749154186616268058178813455542, 64, 'little')
    y_bytes = int.to_bytes(4670470084951911396003988124768315170305199371917345913529797825175008882601627617755129675595434278182470164451448648253936639624494273927513088525900442, 64, 'little')
    valid_cert_bytes = b'\x00' + x_bytes + y_bytes

    def test_get_public_key(self):
        self.assertEqual(get_public_key(self.fake_cert_bytes), Point(0, 0))

    def test_get_bytes(self):
        cert_bytes = get_certificate_bytes(1)
        self.assertIsInstance(cert_bytes, bytes)
        self.assertTrue(len(cert_bytes) == 129)

        cert_bytes = get_certificate_bytes(0)
        self.assertEqual(cert_bytes, self.valid_cert_bytes)

    def test_get_id(self):
        self.assertEqual(get_id(self.fake_cert_bytes), 1)

    def test_verify_certificate(self):
        self.assertFalse(verify_certificate(self.fake_cert_bytes))
        self.assertTrue(verify_certificate(self.valid_cert_bytes))


if __name__ == '__main__':
    unittest.main()
