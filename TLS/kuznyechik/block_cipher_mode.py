import os
import sys

block_cipher_mode_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(block_cipher_mode_dir, '../../'))

from TLS.kuznyechik.block_cipher import *


class BlockCipherMode:
    def __init__(self, block_cipher: BlockCipher):
        self.cipher = block_cipher

    def encrypt(self, plain_text: bytes, key: bytes, **kwargs) -> bytes:
        return plain_text

    def decrypt(self, cipher_text: bytes, key: bytes, **kwargs) -> bytes:
        return cipher_text


class CTR_ACPKM(BlockCipherMode):
    def __init__(self, block_cipher: BlockCipher, section_size: int, gamma_block_size: int):
        """
        section_size, gamma_block_size - parameters in bytes
        """
        assert(block_cipher.key_size == 32)
        assert(block_cipher.block_size % 2 == 0)
        assert(block_cipher.key_size % block_cipher.block_size == 0)
        assert(section_size % block_cipher.block_size == 0)
        assert(block_cipher.block_size % gamma_block_size == 0)

        BlockCipherMode.__init__(self, block_cipher)
        self.section_size = section_size
        self.gamma_block_size = gamma_block_size

    def _acpkm(self) -> bytes:
        key = list(range(128, 128 + 32))
        offset = 0
        while offset < len(key):
            next_offset = offset + self.cipher.block_size
            key[offset : next_offset] = self.cipher.encrypt(bytes(key[offset : next_offset]))
            offset = next_offset
        self.cipher.set_key(bytes(key))

    def _inc(self, vector: bytes) -> bytes:
        vector = list(vector)
        for i in range(len(vector)):
            if vector[-i - 1] == 255:
                vector[-i - 1] = 0
            else:
                vector[-i - 1] += 1
                break
        return bytes(vector)

    def _xor(self, u: bytes, v: bytes) -> bytes:
        res = []
        for a, b in zip(u, v):
            res.append(a ^ b)
        return bytes(res)

    def encrypt(self, plain_text: bytes, key: bytes, initialization_vector: bytes) -> bytes:
        assert(len(initialization_vector) == self.cipher.block_size / 2)

        cipher_text = []
        offset = 0
        section_count = (len(plain_text) + self.section_size - 1) // self.section_size
        gamma_block_count = self.section_size // self.gamma_block_size
        ctr = initialization_vector + bytes([0 for _ in initialization_vector])
        self.cipher.set_key(key)
        for i in range(section_count):
            for j in range(gamma_block_count):
                block_size = min(self.gamma_block_size, len(plain_text) - offset)
                cipher_text += self._xor(plain_text[offset : offset + block_size], self.cipher.encrypt(ctr)[:block_size])
                offset += block_size
                ctr = self._inc(ctr)
            self._acpkm()
        return bytes(cipher_text)

    def decrypt(self, cipher_text: bytes, key: bytes, initialization_vector: bytes) -> bytes:
        return self.encrypt(cipher_text, key, initialization_vector)
