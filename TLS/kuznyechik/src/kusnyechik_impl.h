#include <cstring>
#include <vector>
#include <tuple>

typedef unsigned char uchar;
typedef unsigned int uint;

namespace KusnyechikPrivate {

    constexpr uchar PI[1 << 8] = {
        252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233,
        119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101,
        90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143,
        160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42,
        104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156,
        183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178,
        177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223,
        245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236,
        222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0,
        98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163,
        165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136,
        217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133,
        97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
        116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
    };


    static uchar PIinv[1 << 8];

    void PI_init() {
        for (size_t i = 0; i < 256; i++) {
            PIinv[PI[i]] = i;
        }
    }

    uchar multiply_as_poly(uint a, uint b) {
        constexpr uint poly_mask = 0b111000011;
        uint result = 0;
        for (int i = 0; i < 8; i++) {
            if ((a >> i) & 1) {
                result ^= (b << i);
            }
        }
        for (int i = 7; i >= 0; i--) {
            if ((result >> (i + 8)) & 1) {
                result ^= poly_mask << i;
            }
        }
        return result;
    }

    static uchar l_data[16][256];

    void l_init() {
        uint k_arr[16] = {148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1};
        for (int part = 0; part < 16; part++) {
            uint k = k_arr[part];
            for (uint value = 0; value < 256; value++) {
                l_data[part][value] = multiply_as_poly(value, k);
            }
        }
    }

    // a - pointer to uchar array with length = 16
    uchar l(uchar* a) {
        uchar res = l_data[0][a[0]];
        for (int i = 1; i < 16; i++) {
            res ^= l_data[i][a[i]];
        }
        return res;
    }

}

struct Block {
    union {
        uchar data0;
        uchar data[16];
        uint16_t data16[8];
        uint64_t data64[2];
    };

    Block() {}

    Block(int) {
       memset(data, 0, 16);
    }

    Block(const uchar* ptr) {
        memcpy(data, ptr, 16);
    }

    operator uchar*() {
        return data;
    }

    void operator^=(Block block) {
        data64[0] ^= block.data64[0];
        data64[1] ^= block.data64[1];
    }

    Block operator^(Block block) const {
        block ^= (*this);
        return block;
    }

    bool operator==(Block b) const {
        return data64[0] == b.data64[0] && data64[1] == b.data64[1];
    }

    void copyTo(uchar* dest) const {
        memcpy(dest, data, 16);
    }
};

typedef std::pair<Block, Block> BlockPair;

namespace KusnyechikPrivate {
    void L(uchar* src, uchar* dest) {
        uchar m[32];
        memcpy(m + 16, src, 16);
        for (int i = 15; i >= 0; i--) {
            m[i] = l(m + i + 1);
        }
        memcpy(dest, m, 16);
    }

    Block Lb(Block t) {
        Block res;
        L(t, res);
        return res;
    }

    void Linv(uchar* src, uchar* dest) {
        uchar m[32];
        memcpy(m, src, 16);
        memcpy(m + 16, src, 16);
        for (int i = 0; i < 16; i++) {
            m[i + 16] = l(m + i + 1);
        }
        memcpy(dest, m + 16, 16);
    }

    Block Linvb(Block t) {
        Block res;
        Linv(t, res);
        return res;
    }

    static Block L_data[16][256];
    static Block Linv_data[16][256];

    void Lfast_init() {
        for (int ph = 0; ph < 2; ph++) {
            auto lt = ph ? Lb : Linvb;
            auto data = ph ? L_data : Linv_data;

            for (size_t i = 0; i < 16; i++) {
                for (uint byte = 0; byte < 256; byte++) {
                    Block e(0);
                    e.data[i] = byte;
                    data[i][byte] = lt(e);
                }
            }
        }
    }
}

static Block S(Block t) {
    Block res;
    for (int i = 0; i < 16; i++) {
        res.data[i] = KusnyechikPrivate::PI[t.data[i]];
    }
    return res;
}

static Block Sinv(Block t) {
    Block res;
    for (int i = 0; i < 16; i++) {
        res.data[i] = KusnyechikPrivate::PIinv[t.data[i]];
    }
    return res;
}

static Block L(Block t) {
    Block res = KusnyechikPrivate::L_data[0][t.data[0]];
    for (int i = 1; i < 16; i++) {
        res ^= KusnyechikPrivate::L_data[i][t.data[i]];
    }
    return res;
}

static Block Linv(Block t) {
    Block res = KusnyechikPrivate::Linv_data[0][t.data[0]];
    for (int i = 1; i < 16; i++) {
        res ^= KusnyechikPrivate::Linv_data[i][t.data[i]];
    }
    return res;
}


namespace KusnyechikPrivate {
    static Block LS_data[16][256];
    static Block LSinv_data[16][256];

    void LS_init() {
        for (int i = 0; i < 16; ++i) {
            for (int byte = 0; byte < 256; ++byte) {
                LS_data[i][byte] = KusnyechikPrivate::L_data[i][KusnyechikPrivate::PI[byte]];
                LSinv_data[i][byte] = KusnyechikPrivate::Linv_data[i][KusnyechikPrivate::PIinv[byte]];
            }
        }
    }
};


static Block LS(Block t) {
    Block res = KusnyechikPrivate::LS_data[0][t.data[0]];
    for (int i = 1; i < 16; ++i) {
        res ^= KusnyechikPrivate::LS_data[i][t.data[i]];
    }
    return res;
}

static Block LSinv(Block t) {
    Block res = KusnyechikPrivate::LSinv_data[0][t.data[0]];
    for (int i = 1; i < 16; ++i) {
        res ^= KusnyechikPrivate::LSinv_data[i][t.data[i]];
    }
    return res;
}


static Block LSX(const Block k, Block x) {
    return LS(x ^ k);
}

static Block LSXinv(const Block k, Block x) {
    return k ^ Sinv(Linv(x));
}

void F(Block k, Block a1, Block a2, Block& res1, Block& res2) {
    res1 = LSX(k, a1) ^ a2;
    res2 = a1;
}

BlockPair F(Block k, BlockPair a) {
    BlockPair res;
    F(k, a.first, a.second, res.first, res.second);
    return res;
}

namespace KusnyechikPrivate {

    Block C[32];

    void C_init() {
        for (size_t i = 0; i < 32; i++) {
            Block b;
            memset(b, 0, 16);
            b[15] = i + 1;
            C[i] = Lb(b);
        }
    }

}


class Encryptor {
public:
    Block K[10];
    Block LS0k[9][256];
    Block LSinv0k[9][256];

    Encryptor(BlockPair key) {
        std::tie(K[0], K[1]) = key;
        for (int i = 1; i <= 4; i++) {
            F(KusnyechikPrivate::C[8 * (i - 1)], K[i * 2 - 2], K[i * 2 - 1], K[i * 2], K[i * 2 + 1]);
            for (int j = 1; j < 8; j++) {
                F(KusnyechikPrivate::C[8 * (i - 1) + j], K[i * 2], K[i * 2 + 1], K[i * 2], K[i * 2 + 1]);
            }
        }
        for (int i = 0; i < 9; i++) {
            for (int byte = 0; byte < 256; byte++) {
                LS0k[i][byte] = KusnyechikPrivate::LS_data[0][byte] ^ K[i + 1];
            }
        }

        for (int i = 0; i < 9; i++) {
            for (int byte = 0; byte < 256; byte++) {
                LSinv0k[i][byte] = KusnyechikPrivate::LSinv_data[0][byte] ^ Linv(K[i + 1]);
            }
        }
    }

    void encrypt(const uchar* src, uchar* dest) {
        encrypt(*(const Block*)src).copyTo(dest);
    }

    void encrypt(const uchar* first, const uchar* last, uchar* dest) {
        int64_t sz = last - first;
        for (unsigned long long i = 0; i < sz; i += 16) {
            encrypt(first + i, dest + i);
        }
    }

    void encryptF(const uchar* first, const uchar* last, uchar* dest) {
        auto firstBlockPtr = (const Block*)first;
        auto lastBlockPtr = (const Block*)last;
        size_t sz = lastBlockPtr - firstBlockPtr;
        std::vector<Block> srcData(sz);
        Block* src = srcData.data();
        const Block* blockPtr;
        Block* blockPtr2;
        for (blockPtr = firstBlockPtr, blockPtr2 = src; blockPtr < lastBlockPtr; ++blockPtr, ++blockPtr2) {
            *blockPtr2 = *blockPtr ^ K[0];
        }
        encryptBr(src, (Block*)dest, sz);
    }

    void encryptBr(Block* src, Block* dest, size_t sz) {
        // it's 2 times faster than in loop, it's magic
        encryptP(src, dest, sz, 0);
        std::swap(src, dest);
        encryptP(src, dest, sz, 1);
        std::swap(src, dest);
        encryptP(src, dest, sz, 2);
        std::swap(src, dest);
        encryptP(src, dest, sz, 3);
        std::swap(src, dest);
        encryptP(src, dest, sz, 4);
        std::swap(src, dest);
        encryptP(src, dest, sz, 5);
        std::swap(src, dest);
        encryptP(src, dest, sz, 6);
        std::swap(src, dest);
        encryptP(src, dest, sz, 7);
        std::swap(src, dest);
        encryptP(src, dest, sz, 8);
    }

    void encryptP(Block* src, Block* dest, size_t sz, int round) {
        Block* iSrc = src;
        Block* iDest = dest;
        Block* iSrcFinal = src + sz;
        Block* LS0 = LS0k[round];
        for (; iSrc < iSrcFinal; ++iDest, ++iSrc) {
            Block bSrc = *iSrc;
            Block res = LS0[bSrc.data[0]];
            for (int i = 1; i < 16; i++) {
                res ^= KusnyechikPrivate::LS_data[i][bSrc.data[i]];
            }
            *iDest = res;
        }
    }

    Block encrypt(Block x) {
        for (int i = 0; i < 9; i++) {
            x = LSX(K[i], x);
        }
        x ^= K[9];
        return x;
    }

    void decrypt(const uchar* src, uchar* dest) {
        decrypt(Block(src)).copyTo(dest);
    }

    void decryptF(const uchar* first, const uchar* last, uchar* dest_) {
        auto firstBlockPtr = (const Block*)first;
        auto lastBlockPtr = (const Block*)last;
        size_t sz = lastBlockPtr - firstBlockPtr;
        std::vector<Block> tmp(sz);
        Block* dest = (Block*)dest_;
        Block* lastDest = dest + sz;
        const Block* blockPtr = firstBlockPtr;
        Block* blockPtr2 = dest;
        for (; blockPtr < lastBlockPtr; ++blockPtr, ++blockPtr2) {
            Block bSrc = *blockPtr;
            bSrc ^= K[9];
            Block res = KusnyechikPrivate::Linv_data[0][bSrc.data[0]];
            for (int i = 1; i < 16; i++) {
                res ^= KusnyechikPrivate::Linv_data[i][bSrc.data[i]];
            }

            *blockPtr2 = res;
        }

        decryptBr(dest, (Block*)tmp.data(), sz);

        for (Block* blockPtr2 = dest; blockPtr2 < lastDest; ++blockPtr2) {
            Block res = *blockPtr2;

            for (int i = 0; i < 16; i++) {
                res.data[i] = KusnyechikPrivate::PIinv[res.data[i]];
            }

            res ^= K[0];
            *blockPtr2 = res;
        }
    }

    void decryptBr(Block* src, Block* dest, const size_t sz) {
        decryptP(src, dest, sz, 7);
        std::swap(src, dest);
        decryptP(src, dest, sz, 6);
        std::swap(src, dest);
        decryptP(src, dest, sz, 5);
        std::swap(src, dest);
        decryptP(src, dest, sz, 4);
        std::swap(src, dest);
        decryptP(src, dest, sz, 3);
        std::swap(src, dest);
        decryptP(src, dest, sz, 2);
        std::swap(src, dest);
        decryptP(src, dest, sz, 1);
        std::swap(src, dest);
        decryptP(src, dest, sz, 0);
        std::swap(src, dest);
    }

    void decryptP(Block* src, Block* dest, size_t sz, int round) {
        Block* iSrc = src;
        Block* iDest = dest;
        Block* iSrcFinal = src + sz;
        Block* LSinv0 = LSinv0k[round];
        for (; iSrc < iSrcFinal; ++iDest, ++iSrc) {
            Block bSrc = *iSrc;
            Block res = LSinv0[bSrc.data[0]];
            for (int i = 1; i < 16; i++) {
                res ^= KusnyechikPrivate::LSinv_data[i][bSrc.data[i]];
            }
            *iDest = res;
        }
    }

    Block decrypt(Block x) {
        x ^= K[9];
        x = Linv(x);
        for (int i = 7; i >= 0; i--) {
            x = Sinv(x);
            x = Linv(x);
            x ^= Linv(K[i + 1]);
        }
        x = Sinv(x);
        x ^= K[0];
        return x;
    }

    void decrypt(const uchar* first, const uchar* last, uchar* dest) {
        int64_t sz = last - first;
        for (unsigned long long i = 0; i < sz; i += 16) {
            decrypt(first + i, dest + i);
        }
    }
};


void init() {
    KusnyechikPrivate::PI_init();
    KusnyechikPrivate::l_init();
    KusnyechikPrivate::C_init();
    KusnyechikPrivate::Lfast_init();
    KusnyechikPrivate::LS_init();
}

