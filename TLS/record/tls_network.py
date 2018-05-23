import socket

HANDSHAKE_TYPE = 'Handshake'
ALERT_TYPE = 'Alert'
CCS_TYPE = 'ChangeCipherSpec'
APP_DATA_TYPE = 'ApplicationData'

KEY_MAC_TYPE = 'key_mac'
KEY_ENC_TYPE = 'key_enc'
IV_TYPE = 'iv'

KEY_TYPES = [KEY_MAC_TYPE, KEY_ENC_TYPE, IV_TYPE]


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

    def update_key(self, key_type, value):
        if key_type not in KEY_TYPES:
            raise ValueError('unknown type of key: {}'.format(key_type))
        setattr(self, '_' + key_type, value)

    def enable_cipher_mode(self):
        if self._key_mac is None or self._key_enc is None or self._iv is None:
            raise AttributeError('keys have not been set')
        self._is_cipher_mode = True

    def disable_cipher_mode(self):
        self._is_cipher_mode = False

    def _evaluate_mac(self, rec):
        seqnum_bytes = self._seqnum.to_bytes(8, byteorder='big')
        mac_data = seqnum_bytes + rec.to_bytes()
        key_mac_seqnum = self._tlstree_mac()
        #TODO MAC
        return MAC(key_mac_seqnum, mac_ata)

    def _encrypt(self, fragment, rec_mac):
        enc_data = fragment + rec_mac
        key_enc_seqnum = _tlstree_enc()
        iv_seqnum = (int.from_bytes(self._iv) + self._seqnum) % (2 ** 64)
        iv_seqnum = iv_seqnum.to_bytes(8, byteorder='big')
        #TODO ENC
        return ENC(key_enc_seqnum, iv_seqnum, enc_data)

    def _tlstree_mac(self):
        #TODO
        pass

    def _tlstree_enc(self):
        #TODO
        pass


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
    pass



class TLSNetwork:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self._writer = Writer()
        self._reader = Sender()
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
        
