import unittest
import sys
import os

handshake_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(handshake_dir, '../../'))

from TLS.handshake.message_structures import SERVER_HELLO_MESSAGE, CLIENT_HELLO_MESSAGE
from TLS.handshake.message_structures import CERTIFICATE_MESSAGE, CLIENT_KEY_EXCHANGE_MESSAGE
from TLS.handshake.message_structures import CERTIFICATE_REQUEST_MESSAGE, SERVER_HELLO_DONE_MESSAGE
from TLS.handshake.message_structures import CERTIFICATE_VERIFY_MESSAGE, FINISHED_MESSAGE
from TLS.handshake.message_structures import get_history_record


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
        result = SERVER_HELLO_MESSAGE.to_bytes(self.data)
        self.assertTrue(self.bytes_str == result)

    def test_parse_bytes(self):
        result = SERVER_HELLO_MESSAGE.parse_bytes(self.bytes_str)
        self.assertDictEqual(result, self.data)


class TestClientHello(unittest.TestCase):
    bytes_str = bytes.fromhex("01 00 00 3C 03 03 93 3E A2 1E C3 80 2A 56 15 50 EC 78 D6 ED 51 AC 24 39 D7 E7 49 C3 1B C3 A3 45 61 65 88 96 84 CA 00 00 04 FF 88 FF 89 01 00 00 0F 00 0D 00 06 00 04 EE EE EF EF FF 01 00 01 00")
    data = {
        'client_version': {'major': b'\x03', 'minor': b'\x03'},
        'random': bytes.fromhex('933EA21EC3802A561550EC78D6ED51AC2439D7E749C31BC3A3456165889684CA'),
        'session_id': b'',
        'cipher_suites': [{'CipherSuite': bytes.fromhex('FF88')}, {'CipherSuite': bytes.fromhex('FF89')}],
        'compression_methods': [{'CompressionMethod': b'\x00'}],
        'extensions': [
            {'Extention': {
                'extension_type': bytes.fromhex('000D'),
                'extension_data': {
                    'supported_signature_algorithms': [
                        {'SignatureAndHashAlgorithm': {'hash': b'\xee', 'signature': b'\xee'}},
                        {'SignatureAndHashAlgorithm': {'hash': b'\xef', 'signature': b'\xef'}}
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
        result = CLIENT_HELLO_MESSAGE.to_bytes(self.data)
        self.assertTrue(self.bytes_str == result)

    def test_parse_bytes(self):
        result = CLIENT_HELLO_MESSAGE.parse_bytes(self.bytes_str)
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


class TestCertificate(unittest.TestCase):
    cert = "30 82 02 42 30 82 01 AE A0 03 02 01 02 02 01 01 30 0A 06 08 2A 85 03 07 01 01 03 03 30 42 31 2C 30 2A 06 09 2A 86 48 86 F7 0D 01 09 01 16 1D 74 6C 73 31 32 5F 73 65 72 76 65 72 35 31 32 43 40 63 72 79 70 74 6F 70 72 6F 2E 72 75 31 12 30 10 06 03 55 04 03 13 09 53 65 72 76 65 72 35 31 32 30 1E 17 0D 31 37 30 35 32 35 30 39 32 35 31 38 5A 17 0D 33 30 30 35 30 31 30 39 32 35 31 38 5A 30 42 31 2C 30 2A 06 09 2A 86 48 86 F7 0D 01 09 01 16 1D 74 6C 73 31 32 5F 73 65 72 76 65 72 35 31 32 43 40 63 72 79 70 74 6F 70 72 6F 2E 72 75 31 12 30 10 06 03 55 04 03 13 09 53 65 72 76 65 72 35 31 32 30 81 AA 30 21 06 08 2A 85 03 07 01 01 01 02 30 15 06 09 2A 85 03 07 01 02 01 02 03 06 08 2A 85 03 07 01 01 02 03 03 81 84 00 04 81 80 3A 83 EB 1D F1 B8 39 FD E4 D2 5B B3 52 27 2D C2 10 33 7E 7C 0D 9F 23 4E 9B 3C 70 67 B2 06 97 7A 24 97 3E 13 C3 F6 9F CD 47 F4 8B 28 0A A3 E6 92 80 F5 3F 9B 66 63 65 C6 72 D9 9A 47 DA 89 45 F1 EA F4 11 7A 58 BE 6A B1 EB 67 D5 B3 E3 E1 78 BD E6 2B 61 1D A0 A7 01 41 CB 1C 5E 6A E6 DF F2 99 F2 13 04 3B B5 DD DF B1 04 2C 3A 7F 72 95 7C FC 0B B3 0A B2 9F 05 A1 60 4E 2D 50 36 5B E9 05 F3 A3 43 30 41 30 1D 06 03 55 1D 0E 04 16 04 14 87 9C C6 5A 0F 4A 89 CB 4A 58 49 DF 05 61 56 9B AA DC 11 69 30 0B 06 03 55 1D 0F 04 04 03 02 03 28 30 13 06 03 55 1D 25 04 0C 30 0A 06 08 2B 06 01 05 05 07 03 01 30 0A 06 08 2A 85 03 07 01 01 03 03 03 81 81 00 35 BE 38 51 EC B6 E9 2D 32 40 01 81 0F 8C 89 03 52 42 F4 05 46 9F 4C 4E CB 05 02 7C 57 E2 71 52 12 AF D7 CD BB 0C ED 7A 8B 4D 33 42 CC 50 1A BD 99 99 75 A5 8A DE 0E 58 4F CA 35 F5 2E 45 58 B7 31 1D 49 D0 A0 51 32 79 F7 39 37 1A F8 3C 5B C5 8B 36 6D FE FA 73 45 D5 03 17 86 7C 17 7A C8 4A C0 7E E8 61 21 64 62 9A B7 BD C4 8A A0 F6 4A 74 1F E7 29 8E 82 C5 BF CE 86 72 02 9F 87 53 91 F7"
    bytes_str = bytes.fromhex("0B 00 02 4C 00 02 49 00 02 46 " + cert)
    data = {'certificate_list': [{'ASN.1Cert': bytes.fromhex(cert)}]}

    def test_to_bytes(self):
        result = CERTIFICATE_MESSAGE.to_bytes(self.data)
        self.assertTrue(self.bytes_str == result)

    def test_parse_bytes(self):
        result = CERTIFICATE_MESSAGE.parse_bytes(self.bytes_str)
        self.assertDictEqual(result, self.data)


class TestCertificateRequest(unittest.TestCase):
    bytes_str = bytes.fromhex("0D 00 00 0B 02 EE EF 00 04 EE EE EF EF 00 00")
    data = {
        'certificate_types': [{'ClientCertificateType': b'\xEE'}, {'ClientCertificateType': b'\xEF'}],
        'supported_signature_algorithms': [
            {'SignatureAndHashAlgorithm': {'hash': b'\xee', 'signature': b'\xee'}},
            {'SignatureAndHashAlgorithm': {'hash': b'\xef', 'signature': b'\xef'}}
        ],
        'certificate_authorities': b''
    }

    def test_to_bytes(self):
        result = CERTIFICATE_REQUEST_MESSAGE.to_bytes(self.data)
        self.assertTrue(self.bytes_str == result)

    def test_parse_bytes(self):
        result = CERTIFICATE_REQUEST_MESSAGE.parse_bytes(self.bytes_str)
        self.assertDictEqual(result, self.data)


class TestServerHelloDone(unittest.TestCase):
    bytes_str = bytes.fromhex("0E 00 00 00")
    data = b''

    def test_to_bytes(self):
        result = SERVER_HELLO_DONE_MESSAGE.to_bytes(self.data)
        self.assertTrue(self.bytes_str == result)

    def test_parse_bytes(self):
        result = SERVER_HELLO_DONE_MESSAGE.parse_bytes(self.bytes_str)
        self.assertEqual(result, self.data)


class TestFinished(unittest.TestCase):
    bytes_str = bytes.fromhex('14 00 00 20 20 45 BB 78 3A A5 81 13 2F 90 95 2E 98 90 D8 6E F1 51 41 C8 17 DD C1 67 E9 97 2D 99 52 B3 00 5B')
    data = {'verify_data': bytes.fromhex('2045BB783AA581132F90952E9890D86EF15141C817DDC167E9972D9952B3005B')}

    def test_to_bytes(self):
        result = FINISHED_MESSAGE.to_bytes(self.data)
        self.assertTrue(self.bytes_str == result)

    def test_parse_bytes(self):
        result = FINISHED_MESSAGE.parse_bytes(self.bytes_str)


class TestCertificateVerify(unittest.TestCase):
    bytes_str = bytes.fromhex("0F 00 00 44 EE EE 00 40 02 F6 8F 7C 79 D9 57 B2 24 76 2E 48 17 27 B3 00 EC 88 82 01 AF 8F 9A A8 5B C5 5B 45 62 43 1F F7 38 A8 13 57 8A B8 02 CE D7 B1 D3 FA D1 39 A2 33 DB 43 33 69 4C 4C 7F E1 B3 97 BB 45 BB 5B DE 94")
    data = {
        'algorithm': {'hash': b'\xee', 'signature': b'\xee'},
        'signature': bytes.fromhex("02F68F7C79D957B224762E481727B300EC888201AF8F9AA85BC55B4562431FF738A813578AB802CED7B1D3FAD139A233DB4333694C4C7FE1B397BB45BB5BDE94")
    }

    def test_to_bytes(self):
        result = CERTIFICATE_VERIFY_MESSAGE.to_bytes(self.data)
        self.assertTrue(self.bytes_str == result)

    def test_parse_bytes(self):
        result = CERTIFICATE_VERIFY_MESSAGE.parse_bytes(self.bytes_str)
        self.assertDictEqual(result, self.data)


class TestGetHistoryRecord(unittest.TestCase):
    def test(self):
        messages = [
            '0200003D0303933EA21E49C31BC3A3456165889684CAA5576CE7924A24F58113808DBD9EF85610C3802A561550EC78D6ED51AC2439D7E7FF88000005FF01000100',
            '0100003C0303933EA21EC3802A561550EC78D6ED51AC2439D7E749C31BC3A3456165889684CA000004FF88FF890100000F000D00060004EEEEEFEFFF01000100',
        ]
        answers = [
            "16 03 03 00 41 02 00 00 3D 03 03 93 3E A2 1E 49 C3 1B C3 A3 45 61 65 88 96 84 CA A5 57 6C E7 92 4A 24 F5 81 13 80 8D BD 9E F8 56 10 C3 80 2A 56 15 50 EC 78 D6 ED 51 AC 24 39 D7 E7 FF 88 00 00 05 FF 01 00 01 00",
            "16 03 03 00 40 01 00 00 3C 03 03 93 3E A2 1E C3 80 2A 56 15 50 EC 78 D6 ED 51 AC 24 39 D7 E7 49 C3 1B C3 A3 45 61 65 88 96 84 CA 00 00 04 FF 88 FF 89 01 00 00 0F 00 0D 00 06 00 04 EE EE EF EF FF 01 00 01 00",
        ]
        for ans, mes in zip(answers, messages):
            ans = bytes.fromhex(ans)
            mes = bytes.fromhex(mes)
            self.assertEqual(ans, get_history_record(mes))


if __name__ == '__main__':
    unittest.main()
