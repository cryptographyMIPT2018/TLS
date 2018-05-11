#ifndef CRYPTOGRAPHY_KUZNECHIK_H
#define CRYPTOGRAPHY_KUZNECHIK_H

#include <string.h>
#include <fcntl.h>
#include <unistd.h>


typedef __uint8_t byte;


void BuildTransformTable(byte keys[10][16], byte output[9][256][16]);

void X_Transform(const byte* key, const byte* block, byte* output);
void LS_Transform(const byte* block, byte* output);
void LSX_Transform(const byte* key, byte* block, byte* output);
void F_Transform(const byte* key, byte* a1, byte* a0, byte* b1, byte* b0);

void ExpandKey(byte* primary_key, byte keys[10][16]);

void EncryptBlock(byte keys[10][16], byte XLS_transform_table[9][256][16], byte* block, byte* output);

#endif
