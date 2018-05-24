from libcpp.pair cimport pair

ctypedef unsigned char uchar

cdef extern from "src/kusnyechik_impl.h":
    void init()
    
    cdef cppclass Block:
        Block(const uchar* ptr)

    ctypedef pair[Block, Block] BlockPair

    cdef cppclass Encryptor:
        Encryptor(BlockPair key)
        void encrypt(const uchar* src, uchar* dest)
        void decrypt(const uchar* src, uchar* dest)

init()

cdef class CKuznyechik:
    cdef Encryptor* enc

    def set_key(self, key: bytes):
         self.enc = new Encryptor(BlockPair(Block(key[:16]), Block(key[16:])))

    def encrypt(self, plain_text: bytes) -> bytes:
        cipher_text = bytes([0 for _ in plain_text])
        self.enc.encrypt(plain_text, cipher_text)
        return cipher_text

    def decrypt(self, cipher_text: bytes) -> bytes:
        plain_text = bytes([0 for _ in cipher_text])
        self.enc.decrypt(cipher_text, plain_text)
        return plain_text

