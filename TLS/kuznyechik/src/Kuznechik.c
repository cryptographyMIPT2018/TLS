#include <stdio.h>
#include "Kuznechik.h"
#include "table.h"
#include <time.h>

#pragma simd


void X_Transform(const byte* key, const byte* block, byte* output) {
    ((__uint64_t*) output)[0] = ((__uint64_t*) block)[0] ^ ((__uint64_t*) key)[0];
    ((__uint64_t*) output)[1] = ((__uint64_t*) block)[1] ^ ((__uint64_t*) key)[1];
}


void BuildTransformTable(byte keys[10][16]) {
    for (int i = 0; i < 9; ++i) {
        for (int j = 0; j < 256; ++j) {
            X_Transform(keys[i + 1], LS_transform_table[0][j], XLS_transform_table[i][j]);
        }
    }
}


void LS_Transform(const byte* block, byte* output) {
    memset(output, 0, 16);
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j) {
            output[j] ^= LS_transform_table[i][block[i]][j];
        }
    }
}


void LSX_Transform(const byte* key, byte* block, byte* output) {
    byte X_res[16];
    X_Transform(key, block, X_res);
    LS_Transform(X_res, output);
}


void F_Transform(const byte* key, byte* a1, byte* a0, byte* b1, byte* b0) {
    LSX_Transform(key, a1, b1);
    X_Transform(b1, a0, b1);
    memcpy(b0, a1, 16);
}


void ExpandKey(byte* primary_key, byte keys[10][16]) {
    memcpy(keys[0], primary_key, 16);
    memcpy(keys[1], primary_key + 16, 16);

    for (int i = 1; i < 5; ++i) {
        byte src1[2][16];
        byte src2[2][16];
        memcpy(src1[0], keys[2 * i - 2], 16);
        memcpy(src2[0], keys[2 * i - 1], 16);
        for (int j = (i - 1) * 8 + 1; j < i * 8 + 1; ++j) {
            F_Transform(C_generator[j - 1], src1[(j + 1) % 2], src2[(j + 1) % 2],
                        src1[j % 2], src2[j % 2]);
        }
        memcpy(keys[2 * i], src1[0], 16);
        memcpy(keys[2 * i + 1], src2[0], 16);
    }
}


void EncryptBlock(byte keys[10][16], byte* block, byte* output) {
    byte src[2][16];
    X_Transform(keys[0], block, src[0]);
    for (int i = 0; i < 9; ++i) {
        memcpy(src[1], XLS_transform_table[i][src[0][0]], 16);
        for (int j = 1; j < 16; ++j) {
            X_Transform(src[1], LS_transform_table[j][src[0][j]], src[1]);
        }
        memcpy(src[0], src[1], 16);
    }
    memcpy(output, src[1], 16);
}


void EncryptFile(const char* filename, byte* primary_key) {
    byte keys[10][16];
    ExpandKey(primary_key, keys);
    BuildTransformTable(keys);

    int file = open(filename, O_RDONLY);
    int encrypted_file = open("encrypted.txt", O_WRONLY);


    byte blocks[16000];
    byte encrypted[16000];
    ssize_t n_bytes = 0;
    while ((n_bytes = read(file, blocks, 16000)) > 0) {
        if (n_bytes < 16000) {
            for (ssize_t i = n_bytes; i < 16000; ++i) {
                blocks[i] = 0x00;
            }
        }
        for (int i = 0; i < 1000; ++i) {

            EncryptBlock(keys, blocks + 16 * i, encrypted + 16 * i);
        }
        ssize_t written = write(encrypted_file, encrypted, 16000);
    }
}

void ReadKey(const char* filename, byte* primary_key) {
    int file = open(filename, O_RDONLY);

    ssize_t n_bytes = read(file, primary_key, 32);
}
