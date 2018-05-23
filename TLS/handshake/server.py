import sys
import os

handshake_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(handshake_dir, '../../'))

from TLS.record.record import HANDSHAKE_TYPE
from json import dumps, loads

class HandshakeServer:
    def __init__(self, network):
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
        return message

    def _send(self, message):
        self._network.send(HANDSHAKE_TYPE, message)

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

    def receive_message(self, message):
        """
        message: bytes
        """
        message_type = bytes(message[0])
        header = bytes(message[1:3])
        json = loads(message[3:])
        print(message_type, header, json)
