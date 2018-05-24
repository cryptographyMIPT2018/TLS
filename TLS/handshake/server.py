import sys
import os

handshake_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(handshake_dir, '../../'))

from TLS.record.tls_network import HANDSHAKE_TYPE, CCS_TYPE
from TLS.record.tls_network import KEY_MAC_TYPE, KEY_ENC_TYPE, IV_TYPE
from TLS.elliptic.elliptic_curve import Point
from TLS.certificate.public_keys import public_keys
import time
import random
from message_structures import SERVER_HELLO_MESSAGE, CLIENT_HELLO_MESSAGE
from message_structures import CERTIFICATE_MESSAGE, CLIENT_KEY_EXCHANGE_MESSAGE
from message_structures import CERTIFICATE_REQUEST_MESSAGE, SERVER_HELLO_DONE_MESSAGE
from message_structures import CERTIFICATE_VERIFY_MESSAGE, FINISHED_MESSAGE
from message_structures import CHANGE_CIPHER_SPEC


class HandshakeServer:
    def __init__(self, network, user_id):
        self._id = user_id
        self._network = network

    def _receive(self):
        message_type, message = self._network.receive()
        if message_type != HANDSHAKE_TYPE:
            raise ValueError(
                'message_type should be {}. Got {}.'.format(
                    HANDSHAKE_TYPE,
                    message_type
                )
            )
        return self._decode(message)

    def _send(self, message_data, message_structures=None, record_msg_type=HANDSHAKE_TYPE):
        if message_structures is None:
            byte_message = message_structures.to_bytes(message_data)
        else:
            byte_message = message_data
        self._network.send(record_msg_type, byte_message)

    def handshake(self):
        self._receive_hello()
        self._send_hello()
        self._send_certificate()
        self._send_certificate_request()
        self._send_hello_done()
        self._receive_certificate()
        self._receive_key_exchange()
        self._receive_certificate_verify()
        self._receive_change_chipher_spec()
        self._receive_finished()
        self._send_change_cipher_spec()
        self._send_finished()

    def receive_hello(self):
        hello_message = self._receive()
        self._r_c = hello_message["r_c"]

    def _send_hello(self):
        self._r_s = int.to_bytes(int(time.time()), 4, byteorder='big') + os.urandom(28)

        # if work with several connections in one session more logic is required
        self._session_id = os.urandom(16)
        data = {
            'server_version': {'major': b'\x03', 'minor': b'\x03'},
            'random': self._r_s,
            'session_id': self._session_id,
            'cipher_suite': bytes.fromhex('FF89'),
            'compression_method': b'\x00',
            'extensions': [{
                'Extention': {
                    'extension_type': bytes.fromhex('FF01'),
                    'extension_data': {'renegotiated_connection': b''}
                }
            }],
        }
        self._send(data, SERVER_HELLO_MESSAGE)

    def _send_certificate(self):
        key = public_keys[self._id]
        cert = int.to_bytes(self._certificate['id']) + Point(key[0], key[1]).to_bytes()
        data = {'certificate_list': [{'ASN.1Cert': bytes.fromhex(cert)}]}
        self._send(data, CERTIFICATE_MESSAGE)

    def _send_certificate_request(self):
        data = {
            'certificate_types': [{'ClientCertificateType': b'\xEE'}, {'ClientCertificateType': b'\xEF'}],
            'supported_signature_algorithms': [
                {'SignatureAndHashAlgorithm': {'hash': b'\xee', 'signature': b'\xee'}},
                {'SignatureAndHashAlgorithm': {'hash': b'\xef', 'signature': b'\xef'}}
            ],
            'certificate_authorities': b''
        }
        self._send(data, CERTIFICATE_REQUEST_MESSAGE)

    def _send_hello_done(self):
        self._send(b'', SERVER_HELLO_DONE_MESSAGE)

    def _send_change_cipher_spec(self):
        self._change_cipher_spec('write')
        self._send(CHANGE_CIPHER_SPEC, record_msg_type=CCS_TYPE)

    def _change_cipher_spec(self, record_type):
        """
        Args:
            record_type: str
                'reader' or 'writer'
        """
        allowed = ['reader', 'writer']
        assert record_type in allowed, 'record_type should be in {}, got {}'.format(allowed, record_type)
        if record_type == 'reader':
            key_type = 'read'
        else:
            key_type = 'write'

        record = getattr(self._network, record_type)
        record.update_key(KEY_MAC_TYPE, getattr(self, '_k_' + key_type + '_mac_s'))
        record.update_key(KEY_ENC_TYPE, getattr(self, '_k_' + key_type + '_enc_s'))
        record.update_key(IV_TYPE, getattr(self, '_iv_' + key_type + '_s'))
