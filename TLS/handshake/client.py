import sys
import os

handshake_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(handshake_dir, '../../'))

from TLS.record.tls_network import HANDSHAKE_TYPE, CCS_TYPE
from TLS.record.tls_network import KEY_MAC_TYPE, KEY_ENC_TYPE, IV_TYPE
from TLS.elliptic.elliptic_curve import Point
from TLS.certificate.public_keys import public_keys
from TLS.PRF.prf import prf256
from TLS.hash.hash import hash256
from TLS.certificate.certificate import get_private_key_bytes, verify_certificate, get_public_key
from TLS.signature.signature import Signer
from TLS.elliptic.elliptic_curve import EllipticCurve
from TLS.kexp_kimp.kexp import expand_key as KExp15
from keg import KEG
from constants import KEY_LENGTH, BLOCK_LENGTH
from message_structures import SERVER_HELLO_MESSAGE, CLIENT_HELLO_MESSAGE
from message_structures import CERTIFICATE_MESSAGE, CLIENT_KEY_EXCHANGE_MESSAGE
from message_structures import CERTIFICATE_REQUEST_MESSAGE, SERVER_HELLO_DONE_MESSAGE
from message_structures import CERTIFICATE_VERIFY_MESSAGE, FINISHED_MESSAGE
from message_structures import CHANGE_CIPHER_SPEC
from message_structures import get_history_record


class HandshakeClient:
    def __init__(self, network, user_id):
        self._id = user_id
        self._network = network
        self._hm = ''

    def _receive(self, record_msg_type=HANDSHAKE_TYPE):
        assert record_msg_type in [HANDSHAKE_TYPE, CCS_TYPE]
        message_type, message = self._network.receive()
        return message

    def _send(self, message_data, message_structures=None, record_msg_type=HANDSHAKE_TYPE):
        if message_structures is not None:
            byte_message = message_structures.to_bytes(message_data)
        else:
            byte_message = message_data
        self._network.send(record_msg_type, byte_message)
        self._hm += get_history_record(byte_message)

    def handshake(self):
        self._send_hello()
        self._receive_hello()
        self._receive_certificate()
        self._receive_certificate_request()
        self._receive_hello_done()
        self._send_certificate()
        self._send_key_exchange()
        self._send_certificate_verify()
        self._generate_keys()
        self._send_change_cipher_spec()
        self._send_finished()
        self._receive_change_cipher_spec()
        self._receive_finished()

    def _receive_hello(self):
        bytes_str = self._receive()
        server_hello_message = SERVER_HELLO_MESSAGE.parse_bytes(bytes_str)
        self._r_s = server_hello_message["random"]
        self._hm += get_history_record(bytes_str)

    def _send_hello(self):
        self._r_c = int.to_bytes(int(time.time()), 4, byteorder='big') + os.urandom(28)

        # if work with several connections in one session more logic is required
        self._session_id = os.urandom(16)
        data = {
            'server_version': {'major': b'\x03', 'minor': b'\x03'},
            'random': self._r_c,
            'session_id': self._session_id,
            'cipher_suites': [{'CipherSuite': bytes.fromhex('FF88')}, {'CipherSuite': bytes.fromhex('FF89')}],
            'compression_methods': [{'CompressionMethod': b'\x00'}],
            'extensions': [{
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
            }],
        }
        byte_message = CLIENT_HELLO_MESSAGE.to_bytes(data)
        self._send(byte_message)

    def _send_certificate(self):
        key = public_keys[self._id]
        cert = int.to_bytes(self._certificate['id']) + Point(key[0], key[1]).to_bytes()
        data = {'certificate_list': [{'ASN.1Cert': bytes.fromhex(cert)}]}
        byte_message = CERTIFICATE_MESSAGE.to_bytes(data)
        self._send(byte_message)

    def _receive_certificate(self):
        byte_certificate_message = self._receive()
        certificate_message = CERTIFICATE_MESSAGE.parse_bytes(byte_certificate_message)
        self._server_certificate = certificate_message['certificate_list'][0]['ASN.1Cert']
        assert verify_certificate(self._server_certificate), 'Wrong cert'
        self._server_pub = get_public_key(self._server_certificate)
        self._hm += get_history_record(byte_certificate_message)

    def _receive_certificate_request(self):
        byte_certificate_request = self._receive()
        self._certificate_request = CERTIFICATE_REQUEST_MESSAGE.parse_bytes(byte_certificate_request)
        self._hm += get_history_record(byte_certificate_request)

    def _receive_hello_done(self):
        done = self._receive()
        self._hm += get_history_record(done)

    def _send_key_exchange(self):
        K_eph = os.urandom(28)
        Q_eph = EllipticCurve.multiply_by_number(EllipticCurve.get_forming(), K_eph)
        PS = os.urandom(32)
        H = hash256(self._r_c + self._r_s)
        keg_res = KEG(K_eph, self._server_pub, H)
        k_exp_mac = keg_res[:len(keg_res) // 2]
        k_exp_enc = keg_res[len(keg_res) // 2:]
        IV = H[25:(24 + len(H) // 2)]
        PMSEXP = KExp15(PS, k_exp_enc, k_exp_mac, IV)

        algorithm = "best_algorithm"
        parameters = "best_params"
        subjectPublicKey = Q_eph
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter()
        encoder.write(PMSEXP)
        encoder.enter()
        encoder.enter()
        encoder.write(algorithm)
        encoder.write(parameters)
        encoder.leave()
        encoder.write(subjectPublicKey)
        encoder.leave()
        encoder.leave()

        encoded_bytes = encoder.output()
        self._send(encoded_bytes)

    def _send_certificate_verify(self):
        signer = Signer(EllipticCurve("C"))
        signed_message = signer.sign(self._hm)
        certificate_verify_message = CERTIFICATE_VERIFY_MESSAGE.to_bytes(signed_message)
        self._send(certificate_verify_message)

    def _send_change_cipher_spec(self):
        self._change_cipher_spec('write')
        self._send(CHANGE_CIPHER_SPEC, record_msg_type=CCS_TYPE)

    def _receive_change_cipher_spec(self):
        self._receive(record_msg_type=CCS_TYPE)
        self._change_cipher_spec('reader')
        self._hm += get_history_record("\x01")

    def _send_finished(self):
        server_verify_data = prf256(self._ms, bytes("client_finished", 'utf-8'), hash256(self._hm), 1)
        self._send({'verify_data': server_verify_data}, FINISHED_MESSAGE)

    def _receive_finished(self):
        bytes_str = self._receive()
        finished_message = FINISHED_MESSAGE.parse_bytes(bytes_str)
        client_verify_data = finished_message['verify_data']
        expected_client_verify_data = prf256(self._ms, bytes("server_finished", 'utf-8'), hash256(self._hm), 1)
        assert client_verify_data == expected_client_verify_data
        self._hm += get_history_record(bytes_str)

    def _generate_keys(self):
        self._ms = prf256(self._pms, bytes("extended master secret", 'utf-8'), hash256(self._hm), 2)[:48]
        keys = prf256(
            self._ms,
            bytes("key expansion", 'utf-8'),
            self._r_s + self._r_c,
            int(ceil((4 * KEY_LENGTH + BLOCK_LENGTH) / 32))
        )
        self._k_read_mac_s = keys[:KEY_LENGTH]
        self._k_write_mac_s = keys[KEY_LENGTH:2*KEY_LENGTH]
        self._k_read_enc_s = keys[2*KEY_LENGTH:3*KEY_LENGTH]
        self._k_write_enc_s = keys[3*KEY_LENGTH:4*KEY_LENGTH]
        self._iv_read_s = keys[4*KEY_LENGTH:4*KEY_LENGTH + BLOCK_LENGTH // 2]
        self._iv_write_s = keys[4*KEY_LENGTH + BLOCK_LENGTH // 2:4*KEY_LENGTH + BLOCK_LENGTH]