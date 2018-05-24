import sys
import os
import asn1

handshake_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(handshake_dir, '../../'))

from TLS.record.tls_network import HANDSHAKE_TYPE, CCS_TYPE
from TLS.record.tls_network import KEY_MAC_TYPE, KEY_ENC_TYPE, IV_TYPE
from TLS.elliptic.elliptic_curve import Point
from TLS.certificate.public_keys import public_keys
from TLS.PRF.prf import prf256
from TLS.hash.hash import hash256
from TLS.certificate.certificate import get_private_key_bytes, verify_certificate
from TLS.signature.signature import Signer
from TLS.elliptic.elliptic_curve import EllipticCurve
from TLS.kexp_kimp.kexp import expand_key as KExp15
import time
import random
from keg import KEG
from message_structures import SERVER_HELLO_MESSAGE, CLIENT_HELLO_MESSAGE
from message_structures import CERTIFICATE_MESSAGE, CLIENT_KEY_EXCHANGE_MESSAGE
from message_structures import CERTIFICATE_REQUEST_MESSAGE, SERVER_HELLO_DONE_MESSAGE
from message_structures import CERTIFICATE_VERIFY_MESSAGE, FINISHED_MESSAGE
from message_structures import CHANGE_CIPHER_SPEC
from message_structures import get_history_record


class HandshakeServer:
    def __init__(self, network, user_id):
        self._id = user_id
        self._network = network

    def _receive(self, record_msg_type=HANDSHAKE_TYPE):
        assert record_msg_type in [HANDSHAKE_TYPE, CCS_TYPE]
        message_type, message = self._network.receive()
        return message

    def _send(self, message_data, message_structures=None, record_msg_type=HANDSHAKE_TYPE):
        if message_structures is None:
            byte_message = message_structures.to_bytes(message_data)
        else:
            byte_message = message_data
        self._network.send(record_msg_type, byte_message)
        self._hm += get_history_record(byte_message)

    def handshake(self):
        self._receive_hello()
        self._send_hello()
        self._send_certificate()
        self._send_certificate_request()
        self._send_hello_done()
        self._receive_certificate()
        self._receive_key_exchange()
        self._receive_certificate_verify()
        self._generate_keys()
        self._receive_change_chipher_spec()
        self._receive_finished()
        self._send_change_cipher_spec()
        self._send_finished()

    def _receive_hello(self):
        bytes_str = self._receive()
        client_hello_message = CLIENT_HELLO_MESSAGE.parse_bytes(bytes_str)
        self._r_c = client_hello_message["random"]
        self._HM += get_history_record(bytes_str)

    def _receive_certificate(self):
        bytes_str = self._receive()
        certificate_message = CERTIFICATE_MESSAGE.parse_bytes(bytes_str)
        cert = certificate_message["certificate_list"][0]['ASN.1Cert']
        if not verify_certificate(cert):
            raise ValueError("Wrong cert")
        self._HM += get_history_record(bytes_str)

    def _receive_key_exchange(self):
        bytes_str = self._receive()
        key_exchange_message = CLIENT_KEY_EXCHANGE_MESSAGE.parse_bytes(bytes_str)
        exchange_keys = key_exchange_message['exchange_keys']
        decoder = asn1.Decoder()
        decoder.start(exchange_keys)
        '''
        decoder.enter() (
            tag, PMSEXP = decoder.read()
            decoder.enter() (
                decoder.enter() (
                    tag, algorithm = decoder.read()
                    tag, parameters = decoder.read()
                ) decoder.leave()
                tag, subjectPublicKey = decoder.read()
            ) decoder.leave()
        ) decoder.leave()
        '''
        decoder.enter()
        tag, PMSEXP = decoder.read()
        decoder.enter()
        decoder.enter()
        tag, algorithm = decoder.read()
        tag, parameters = decoder.read()
        decoder.leave()
        tag, subjectPublicKey = decoder.read()
        decoder.leave()
        decoder.leave()

        Q_eph = subjectPublicKey
        H = hash256(self._r_c + self._r_s)
        k_s = get_private_key_bytes()
        keg_res = KEG(k_s, Q_eph, H)
        k_exp_mac = keg_res[:len(keg_res) // 2]
        k_exp_enc = keg_res[len(keg_res) // 2:]
        IV = H[25:(24 + BLOCK_LENGTH // 2)]
        self._PMS = KExp15(PMSEXP, k_exp_mac, k_exp_enc, IV)
        self._HM += get_history_record(bytes_str)

    def _receive_certificate_verify(self):
        bytes_str = self._receive()
        certificate_verify_message = CERTIFICATE_VERIFY_MESSAGE.parse_bytes(bytes_str)
        sign = certificate_verify_message.signature
        signer = Signer(EllipticCurve("C"))
        if not signer.check(self._HM, sign):
            raise ValueError("Wrong sign")
        self._HM += get_history_record(bytes_str)

    def _receive_change_chipher_spec(self):
        self._receive(record_msg_type=CCS_TYPE)
        self._change_cipher_spec('read')

    def _generate_keys(self):
        self._ms = prf256(self._pms, bytes("extended master secret"), hash256(self._hm))

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
        record.enable_cipher_mode()

    def _send_finished(self):
        pass
