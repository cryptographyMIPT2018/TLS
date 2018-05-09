import typing

class BlockCipher:
    def __init__(self, block_size, key_size):
        """
        block_size, key_size - parameters of the cipher in bytes.
        """
        self.block_size = block_size
        self.key_size = key_size
        self.key = None
        
    def set_key(self, key: bytes):
        assert(len(key) == self.key_size)
        self.key = key
    
    def encrypt(self, plain_text: bytes) -> bytes:
        return plain_text
    
    def decrypt(self, cipher_text: bytes) -> bytes:
        return cipher_text
    
class StupidBlockCipher(BlockCipher):
    def __init__(self):
        BlockCipher.__init__(self, 16, 32)
        
    def encrypt(self, plain_text: bytes) -> bytes:
        assert(len(plain_text) == self.block_size)
        
        cipher_text = []
        for i in range(len(plain_text)):
            cipher_text.append(plain_text[i] ^ self.key[i])
        return bytes(cipher_text)
    
    def decrypt(self, cipher_text: bytes) -> bytes:
        return self.encrypt(cipher_text)
    
class Kuznyechik(BlockCipher):
    """
    Implement me
    """
    def __init__(self):
        BlockCipher.__init__(self, 16, 32)
        
    def encrypt(self, plain_text: bytes) -> bytes:
        assert(len(plain_text) == self.block_size)
        
        return plain_text
    
    def decrypt(self, cipher_text: bytes) -> bytes:
        assert(len(cipher_text) == self.block_size)
        
        return cipher_text
