import sys
import asn1
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
        return self._decode(message)

    def _send(self, message):
        self._network.send(HANDSHAKE_TYPE, message)

    def _decode(self, bytes_string):
        decoder = asn1.Decoder()
        while not decoder.eof():
            tag = input_stream.peek()
            if tag.typ == asn1.TypePrimitive:
                tag, value = input_stream.read()
                output_stream.write(' ' * indent)
                output_stream.write('[{}] {}: {}\n'.format(
                    class_id_to_string(tag.cls),
                    tag_id_to_string(tag.nr),
                    value_to_string(tag.nr, value)
                ))
            elif tag.typ == asn1.TypeConstructed:
                output_stream.write(' ' * indent)
                output_stream.write('[{}] {}\n'.format(
                    class_id_to_string(tag.cls),
                    tag_id_to_string(tag.nr)
                ))
                input_stream.enter()
                pretty_print(input_stream, output_stream, indent + 2)
                input_stream.leave()

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

    def receive_hello():
        hello_message =  self._receive()
        self._r_c = hello_message["r_c"]
