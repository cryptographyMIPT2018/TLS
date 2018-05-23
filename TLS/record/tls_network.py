import socket
from ..kuznyechik.mac import CMAC
from ..kuznyechik.block_cipher import Kuznyechik
from ..kuznyechik.block_cipher_mode import CTR_ACPKM
from ..KDF.kdf import KDF_TREE_256

HANDSHAKE_TYPE = 'Handshake'
ALERT_TYPE = 'Alert'
CCS_TYPE = 'ChangeCipherSpec'
APP_DATA_TYPE = 'ApplicationData'

KEY_MAC_TYPE = 'key_mac'
KEY_ENC_TYPE = 'key_enc'
IV_TYPE = 'iv'
SEED_TYPE = 'seed'

KEY_TYPES = [KEY_MAC_TYPE, KEY_ENC_TYPE, IV_TYPE, SEED_TYPE]


class TLSBasetext:
    def __init__(self, msg_type, protocol, message):
        self.msg_type = msg_type
        self.protocol = protocol
        self.message = message
        self.length = len(message)

    def to_bytes(self):
        return self.msg_type + self.protocol + str.encode(str(self.length)) + self.message


class TLSPlaintext(TLSBasetext):
    pass


class TLSCiphertext(TLSBasetext):
    pass


class Record:
    def __init__(self):
        self._PROTOCOL = b'\x03\x03'  # tls 1.2
        self._MAX_FRAGMENT_SIZE = 2 ** 14
        self._seqnum = -1
        self._is_cipher_mode = False
        self._key_mac = None
        self._key_enc = None
        self._iv = None
        self._seed = None

    def update_key(self, key_type, value):
        if key_type not in KEY_TYPES:
            raise ValueError('unknown type of key: {}'.format(key_type))
        setattr(self, '_' + key_type, value)

    def enable_cipher_mode(self):
        for key_type in KEY_TYPES:
            if getattr(self, '_' + key_type) is None:
                raise AttributeError('{} has not been set'.format(key_type))
        self._is_cipher_mode = True

    def disable_cipher_mode(self):
        for key_type in KEY_TYPES:
            setattr(self, '_' + key_type, None)
        self._is_cipher_mode = False

    def _evaluate_mac(self, rec):
        seqnum_bytes = self._seqnum.to_bytes(8, byteorder='big')
        mac_data = seqnum_bytes + rec.to_bytes()
        key_mac_seqnum = self._tlstree(self._key_mac, self._seqnum)
        block_cipher = Kuznyechik()
        cmac = CMAC(block_cipher, len(mac_data))
        return cmac.calculate(mac_data, key_mac_seqnum)

    def _encrypt(self, fragment, rec_mac):
        enc_data = fragment + rec_mac
        key_enc_seqnum = self._tlstree(self._key_mac, self._seqnum)
        iv_seqnum = (int.from_bytes(self._iv) + self._seqnum) % (2 ** 64)
        iv_seqnum = iv_seqnum.to_bytes(8, byteorder='big')
        block_cipher = Kuznyechik()
        enc = CTR_ACPKM(block_cipher, 32, 16)
        return enc.encrypt(enc_data, key_enc_seqnum, iv_seqnum)

    def _diver(self, level, K, D):
        R = 1
        L = 256
        return KDF_TREE_256(K, str.encode('level' + str(level)), self._seed, R, L, self._seqnum + 1)

    def _tlstree(self, key, i):
        C1 = int.from_bytes(b'\xff\xff\xff\xff\x00\x00\x00\x00')
        C2 = int.from_bytes(b'\xff\xff\xff\xff\xff\xf8\x00\x00')
        C3 = int.from_bytes(b'\xff\xff\xff\xff\xff\xff\xff\xc0')
        return self._diver(3,
            self._diver(
                2, self._diver(1, key, (i & C1).to_bytes(8, byteorder='big')),
                (i & C2).to_bytes(8, byteorder='big')
            ),
            (i & C3).to_bytes(8, byteorder='big')
        )


class Writer(Record):
    def create_messages(self, msg_type, message):
        fragment_generator = self._make_fragments_generator(message)
        messages = []
        for fragment in fragment_generator:
            plaintext = self._create_plaintext(msg_type, fragment)
            self._seqnum += 1
            if self._is_cipher_mode:
                mac = self._evaluate_mac(plaintext)
                encrypted_fragment = self._encrypt(fragment, mac)
                plaintext = self._create_plaintext(msg_type, encrypted_fragment, 'cipher')
            messages.append(plaintext.to_bytes())
        return messages

    def _create_plaintext(self, msg_type, fragment, text_type='plain'):
        type2byte = {CCS_TYPE: b'\x14',
                     ALERT_TYPE: b'\x15',
                     HANDSHAKE_TYPE: b'\x16',
                     APP_DATA_TYPE: b'\x17'}

        if msg_type not in type2byte:
            raise ValueError('unknown message type: {}'.format(msg_type))

        if text_type == 'plain':
            return TLSPlaintext(type2byte[msg_type], self._PROTOCOL, fragment)
        elif text_type == 'cipher':
            return TLSCiphertext(type2byte[msg_type], self._PROTOCOL, fragment)
        else:
            raise ValueError('unknown text type: {}'.format(text_type))

    def _make_fragments_generator(self, message):
        length = len(message)
        n_iter = length // self._MAX_FRAGMENT_SIZE
        residual = length % self._MAX_FRAGMENT_SIZE
        if residual > 0:
            n_iter += 1

        for i in range(n_iter):
            if i == n_iter - 1:
                fragment = message[i * self._MAX_FRAGMENT_SIZE:]
            else:
                fragment = message[i * self._MAX_FRAGMENT_SIZE: (i + 1) * self._MAX_FRAGMENT_SIZE]
            yield fragment


class Reader(Record):
    def parse_header(self, header):
        byte2type = {b'\x14': CCS_TYPE,
                     b'\x15': ALERT_TYPE,
                     b'\x16': HANDSHAKE_TYPE,
                     b'\x17': APP_DATA_TYPE}
        msg_type = byte2type[header[0]]
        length = int.from_bytes(header[3:], byteorder='big')
        return msg_type, length

    def parse_fragment(self, fragment):
        self._seqnum += 1



class TLSNetwork:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self._writer = Writer()
        self._reader = Reader()
        self._socket = socket.socket()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._socket.close()

    def send(self, msg_type, message):
        messages = self._writer.create_messages(msg_type, message)
        for msg in messages:
            ### send magic

    def recieve(self):
        ### recieve magic


class TLSNetworkServer(TLSNetwork):
    def __init__(self, host, port):
        TLSNetwork.__init__(host, port)
        self._socket.bind((host, port))

    def listen(self):
        self._socket.listen(1)

    def accept(self):
        return self._socket.accept()


class TLSNetworkClient(TLSNetwork):
    def __init__(self, host, port):
        TLSNetwork.__init__(host, port)

    def connect(self):
        self.connect((self.host, self.port))