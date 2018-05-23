import unittest
from message_structures import SERVER_HELLO, CLIENT_HELLO, CLIENT_KEY_EXCHANGE_MESSAGE


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
        self.assertDictEqual(result, self.data)


class TestClientKeyExchange(unittest.TestCase):
    bytes_str = bytes.fromhex("10 00 00 95 30 81 92 04 28 9E C3 E0 76 C5 56 73 1E 3B 25 3B E5 8B 8F AD D4 A9 0A 24 B3 42 F6 13 A5 E2 AC 13 CE 07 53 0A 00 A9 8C 1E E2 A2 AF C0 E0 30 66 30 1F 06 08 2A 85 03 07 01 01 01 01 30 13 06 07 2A 85 03 02 02 24 00 06 08 2A 85 03 07 01 01 02 02 03 43 00 04 40 93 07 E0 98 C1 71 88 F1 F1 47 7F EF B8 7F AE F1 BB CD 95 67 3B 1B 8F 97 03 A2 62 D2 63 6D F3 A8 87 F8 14 1F EA C2 5A 17 CC B5 96 04 61 ED 16 B0 F8 B1 BE 93 59 43 95 A1 0E 64 85 44 6B 5D CA 34")
    data = {
        "exchange_keys": bytes.fromhex("30819204289EC3E076C556731E3B253BE58B8FADD4A90A24B342F613A5E2AC13CE07530A00A98C1EE2A2AFC0E03066301F06082A85030701010101301306072A85030202240006082A8503070101020203430004409307E098C17188F1F1477FEFB87FAEF1BBCD95673B1B8F9703A262D2636DF3A887F8141FEAC25A17CCB5960461ED16B0F8B1BE93594395A10E6485446B5DCA34")
    }

    def test_to_bytes(self):
        result = CLIENT_KEY_EXCHANGE_MESSAGE .to_bytes(self.data)
        self.assertTrue(self.bytes_str == result)

    def test_parse_bytes(self):
        result = CLIENT_KEY_EXCHANGE_MESSAGE .parse_bytes(self.bytes_str)
        self.assertDictEqual(result, self.data)


if __name__ == '__main__':
    unittest.main()
