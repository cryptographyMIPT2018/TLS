import unittest
from message_structures import SERVER_HELLO, CLIENT_HELLO


class TestServerHello(unittest.TestCase):
    bytes_str = bytes.fromhex("02 00 00 3D 03 03 93 3E A2 1E 49 C3 1B C3 A3 45 61 65 88 96 84 CA A5 57 6C E7 92 4A 24 F5 81 13 80 8D BD 9E F8 56 10 C3 80 2A 56 15 50 EC 78 D6 ED 51 AC 24 39 D7 E7 FF 89 00 00 05 FF 01 00 01 00")
    data = {
        'server_version': {'major': b'\x03', 'minor': b'\x03'},
        'random': bytes.fromhex('933EA21E49C31BC3A3456165889684CAA5576CE7924A24F58113808DBD9EF856'),
        'session_id': bytes.fromhex('C3802A561550EC78D6ED51AC2439D7E7'),
        'cipher_suite': bytes.fromhex('FF89'),
        'compression_method': b'\x00',
        'extensions': [{
            'Extention': {
                'extension_type': bytes.fromhex('FF01'),
                'extension_data': {'renegotiated_connection': b''}
            }
        }],
    }

    def test_to_bytes(self):
        result = SERVER_HELLO.to_bytes(self.data)
        self.assertTrue(self.bytes_str == result)

    def test_parse_bytes(self):
        result = SERVER_HELLO.parse_bytes(self.bytes_str)
        print(result)
        self.assertDictEqual(result, self.data)


class TestClientHello(unittest.TestCase):
    bytes_str = bytes.fromhex("01 00 00 3C 03 03 93 3E A2 1E C3 80 2A 56 15 50 EC 78 D6 ED 51 AC 24 39 D7 E7 49 C3 1B C3 A3 45 61 65 88 96 84 CA 00 00 04 FF 88 FF 89 01 00 00 0F 00 0D 00 06 00 04 EE EE EF EF FF 01 00 01 00")
    data = {
        'server_version': {'major': b'\x03', 'minor': b'\x03'},
        'random': bytes.fromhex('933EA21EC3802A561550EC78D6ED51AC2439D7E749C31BC3A3456165889684CA'),
        'session_id': b'',
        'cipher_suites': [{'CipherSuite': bytes.fromhex('FF88')}, {'CipherSuite': bytes.fromhex('FF89')}],
        'compression_methods': [{'CompressionMethod': b'\x00'}],
        'extensions': [
            {'Extention': {
                'extension_type': bytes.fromhex('000D'),
                'extension_data': {
                    'supported_signature_algorithms': [
                        {'SignatureAlgorithm': {'hash': b'\xee', 'signature': b'\xee'}},
                        {'SignatureAlgorithm': {'hash': b'\xef', 'signature': b'\xef'}}
                    ],
                }
            }},
            {'Extention': {
                'extension_type': bytes.fromhex('FF01'),
                'extension_data': {'renegotiated_connection': b''}
            }}
        ],
    }

    def test_to_bytes(self):
        result = CLIENT_HELLO.to_bytes(self.data)
        self.assertTrue(self.bytes_str == result)

    def test_parse_bytes(self):
        result = CLIENT_HELLO.parse_bytes(self.bytes_str)
        print(result)
        print(self.data)
        self.assertDictEqual(result, self.data)


if __name__ == '__main__':
    unittest.main()
