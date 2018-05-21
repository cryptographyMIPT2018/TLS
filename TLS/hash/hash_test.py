import unittest

from TLS.hash.hash import *


class HashTest1(unittest.TestCase):
    def test_hash_512(self):
        message = bytes.fromhex(
            "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130")

        answer = bytes.fromhex(
            "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b")

        self.assertEqual(hash512_bit_length(message, 504), answer)
        self.assertEqual(hash512(message), answer)

    def test_hash_256(self):
        message = bytes.fromhex(
            "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130")
        answer = bytes.fromhex(
            "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d")
        self.assertEqual(hash256_bit_length(message, 504), answer)
        self.assertEqual(hash256(message), answer)


class HashTest2(unittest.TestCase):
    def test_hash_512(self):
        message = bytes.fromhex(
            "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1")

        answer = bytes.fromhex(
            "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f03 7613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e")

        self.assertEqual(hash512_bit_length(message, 576), answer)
        self.assertEqual(hash512(message), answer)

    def test_hash_256(self):
        message = bytes.fromhex(
            "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1")

        answer = bytes.fromhex(
            "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d")
        self.assertEqual(hash256_bit_length(message, 576), answer)
        self.assertEqual(hash256(message), answer)


if __name__ == '__main__':
    unittest.main()
