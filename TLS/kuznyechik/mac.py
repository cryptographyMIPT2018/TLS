from copy import copy
from block_cipher import *


class MAC:
    def __init__(self, block_cipher: BlockCipher, code_size: int):
        """
        code_size - size of authentication code in bytes
        """
        self.cipher = block_cipher
        self.code_size = code_size
    
    def calculate(self, plain_text: bytes, key: bytes) -> bytes:
        return bytes([0] * self.code_size)
    
class CMAC(MAC):
    def __init__(self, block_cipher: BlockCipher, code_size: int):
        assert(block_cipher.block_size == 8 or block_cipher.block_size == 16)
        
        MAC.__init__(self, block_cipher, code_size)
        
    def _shift(self, vector: bytes) -> bytes:
        vector = list(vector)
        remainder = 0
        for i in range(len(vector)):
            if (vector[-i - 1] & 128):
                vector[-i - 1] = (((vector[-i - 1] ^ 128) << 1) ^ remainder)
                remainder = 1
            else:
                vector[-i - 1] = ((vector[-i - 1] << 1) ^ remainder)
                remainder = 0
        return bytes(vector)
    
    def _xor(self, u: bytes, v: bytes) -> bytes:
        res = []
        for a, b in zip(u, v):
            res.append(a ^ b)
        return bytes(res)
        
    def _generate_key(self, key: bytes):
        B8 = bytes([0] * 7 + [0b00011011])
        B16 = bytes([0] * 15 + [0b10000111])
        
        new_key = self._shift(copy(bytes(key)))
        if (key[0] & 128):
            if self.cipher.block_size == 8:
                new_key = self._xor(new_key, B8)
            if self.cipher.block_size == 16:
                new_key = self._xor(new_key, B16)
                
        return new_key
            
    def calculate(self, plain_text: bytes, key: bytes) -> bytes:
        self.cipher.set_key(key)
        R = self.cipher.encrypt(bytes([0] * self.cipher.block_size))
        key1 = self._generate_key(R)
        key2 = self._generate_key(key1)
        
        code = bytes([0] * self.cipher.block_size)
        block_count = (len(plain_text) + self.cipher.block_size - 1) // self.cipher.block_size
        offset = 0
        for i in range(block_count - 1):
            next_offset = offset + self.cipher.block_size
            code = self.cipher.encrypt(self._xor(code, bytes(plain_text[offset: next_offset])))
            offset = next_offset
        
        if len(plain_text) - offset == self.cipher.block_size:
            xor = self._xor(code, bytes(plain_text[offset:]))
            xor = self._xor(xor, key1)
            code = self.cipher.encrypt(xor)
        else:
            block = list(plain_text[offset:]) + [0b10000000]
            block += [0b00000000] * (self.cipher.block_size + offset - len(plain_text) - 1)
            xor = self._xor(code, bytes(block))
            xor = self._xor(xor, key2)
            code = self.cipher.encrypt(xor)
            
        return code[:self.code_size]        
