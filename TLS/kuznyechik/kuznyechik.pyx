ctypedef unsigned char byte

cdef extern from "src/Kuznechik.h":
    void BuildTransformTable(byte keys[10][16], byte output[9][256][16])
    void ExpandKey(byte* primary_key, byte keys[10][16])
    void EncryptBlock(byte keys[10][16], byte XLS_transform_table[9][256][16], byte* block, byte* output)


cdef class CKuznyechik:
    cdef byte key[32]
    cdef byte keys[10][16]
    cdef byte XLS_transform_table[9][256][16];

    def set_key(self, key: bytes):
         self.key = key
         ExpandKey(self.key, self.keys)
         BuildTransformTable(self.keys, self.XLS_transform_table)
        
    def encrypt(self, plain_text: bytes) -> bytes:
        cipher_text = bytes([0 for _ in plain_text])
        EncryptBlock(self.keys, self.XLS_transform_table, plain_text, cipher_text)
        return cipher_text
    
    def decrypt(self, cipher_text: bytes) -> bytes:
        return cipher_text

