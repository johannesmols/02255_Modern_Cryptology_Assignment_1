// Sample implementation given by the lecturer

#include "AES.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Calculate the round keys for the AES version.
void keyschedule128(AES* aes);
void keyschedule192(AES* aes);
void keyschedule256(AES* aes);

// Construct the round keys for decryption from the round keys.
void set_invroundkeys(AES* aes);

// The SubBytes step for a block.
void SubBytes(word* m);
// The invSubBytes step for a block.
void invSubBytes(word* m);
// The ShiftRows step.
void ShiftRows(word* m);
// The invShiftRows step.
void invShiftRows(word* m);
// The MixColumns step.
void MixColumns(word* m);
// The invMixColumns step.
void invMixColumns(word* m);

// Set INVSBOX to the inverse of SBOX.
void set_invsbox(void);

// Calculate the T-tables using SBOX.
void calc_tables(void);

// Calculate the inverse T-tables using INVSBOX.
void calc_invtables(void);

// The standard Rijndael S-box
const word SBOX[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
        0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
        0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
        0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
        0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
        0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
        0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
        0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
        0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
        0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
        0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
        0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
        0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
        0xB0, 0x54, 0xBB, 0x16};

// Stores the inverse S-box
word INVSBOX[256];

// T-tables for fast 32-bit encryption
static word T0[256];
static word T1[256];
static word T2[256];
static word T3[256];

// T-tables for fast 32-bit decryption
static word INVT0[256];
static word INVT1[256];
static word INVT2[256];
static word INVT3[256];

// The constants for the Rijndael key schedule
const word ROUND_CONSTANTS[256] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
        0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
        0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
        0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
        0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
        0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e,
        0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
        0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
        0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
        0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
        0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb,
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
        0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
        0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d};

AES* create_aes_instance(word* key, size_t key_size) {
    if (key_size != 4 && key_size != 6 && key_size != 8) {
        fprintf(stderr, "Error: Invalid keysize. Setting it to 128.\n");
        fflush(stderr);
        return NULL;
    }
    AES* aes = malloc(sizeof(AES));
    aes->key_size = key_size;
    aes->key = malloc(key_size * sizeof(word));
    memcpy(aes->key, key, key_size * sizeof(word));
    set_invsbox();
    calc_tables();
    calc_invtables();
    if (key_size == 4) {
        aes->rounds = 10;
        keyschedule128(aes);
    } else if (key_size == 6) {
        aes->rounds = 12;
        keyschedule192(aes);
    } else {
        aes->rounds = 14;
        keyschedule256(aes);
    }
    set_invroundkeys(aes);
    return aes;
}

void delete_aes_instance(AES* aes) {
    free(aes->key);
    free(aes->round_keys);
    free(aes->inv_round_keys);
}

// Encrypt a message.
// The message has to be of length 4 words.
void encrypt(AES* aes, word* m) {
    for (size_t w = 0; w < 4; ++w) {
        m[w] ^= aes->round_keys[0][w];
    }
    word w0, w1, w2, w3;
    for (size_t r = 1; r < aes->rounds; ++r) {
        w0 = T0[(m[0] & 0xff000000) >> 24] ^ T1[(m[1] & 0xff0000) >> 16] ^
             T2[(m[2] & 0xff00) >> 8] ^ T3[m[3] & 0xff] ^ aes->round_keys[r][0];
        w1 = T0[(m[1] & 0xff000000) >> 24] ^ T1[(m[2] & 0xff0000) >> 16] ^
             T2[(m[3] & 0xff00) >> 8] ^ T3[m[0] & 0xff] ^ aes->round_keys[r][1];
        w2 = T0[(m[2] & 0xff000000) >> 24] ^ T1[(m[3] & 0xff0000) >> 16] ^
             T2[(m[0] & 0xff00) >> 8] ^ T3[m[1] & 0xff] ^ aes->round_keys[r][2];
        w3 = T0[(m[3] & 0xff000000) >> 24] ^ T1[(m[0] & 0xff0000) >> 16] ^
             T2[(m[1] & 0xff00) >> 8] ^ T3[m[2] & 0xff] ^ aes->round_keys[r][3];
        m[0] = w0;
        m[1] = w1;
        m[2] = w2;
        m[3] = w3;
    }
    SubBytes(m);
    ShiftRows(m);
    for (size_t w = 0; w < 4; ++w) {
        m[w] ^= aes->round_keys[aes->rounds][w];
    }
}

// Decrypt a message.
// The message has to be of length 4 words.
void decrypt(AES* aes, word* m) {
    for (unsigned w = 0; w < 4; ++w) {
        m[w] ^= aes->inv_round_keys[0][w];
    }
    word w0, w1, w2, w3;
    for (unsigned r = 1; r < aes->rounds; ++r) {
        w0 = INVT0[(m[0] & 0xff000000) >> 24] ^ INVT1[(m[3] & 0xff0000) >> 16] ^
             INVT2[(m[2] & 0xff00) >> 8] ^ INVT3[m[1] & 0xff] ^
             aes->inv_round_keys[r][0];
        w1 = INVT0[(m[1] & 0xff000000) >> 24] ^ INVT1[(m[0] & 0xff0000) >> 16] ^
             INVT2[(m[3] & 0xff00) >> 8] ^ INVT3[m[2] & 0xff] ^
             aes->inv_round_keys[r][1];
        w2 = INVT0[(m[2] & 0xff000000) >> 24] ^ INVT1[(m[1] & 0xff0000) >> 16] ^
             INVT2[(m[0] & 0xff00) >> 8] ^ INVT3[m[3] & 0xff] ^
             aes->inv_round_keys[r][2];
        w3 = INVT0[(m[3] & 0xff000000) >> 24] ^ INVT1[(m[2] & 0xff0000) >> 16] ^
             INVT2[(m[1] & 0xff00) >> 8] ^ INVT3[m[0] & 0xff] ^
             aes->inv_round_keys[r][3];
        m[0] = w0;
        m[1] = w1;
        m[2] = w2;
        m[3] = w3;
    }

    invSubBytes(m);
    invShiftRows(m);
    for (unsigned w = 0; w < 4; ++w) {
        m[w] ^= aes->inv_round_keys[aes->rounds][w];
    }
}

// Calculates the round keys for a key of length 128 bit
void keyschedule128(AES* aes) {
    block round_key;
    memcpy(round_key, aes->key, sizeof(block));
    word tword;
    aes->round_keys = malloc((aes->rounds + 1) * sizeof(block));

    memcpy(aes->round_keys[0], round_key, sizeof(block));
    for (size_t round = 1; round <= aes->rounds; ++round) {
        tword = SBOX[(round_key[3] >> 16) & 0xFF];
        tword <<= 8;
        tword ^= SBOX[(round_key[3] >> 8) & 0xFF];
        tword <<= 8;
        tword ^= SBOX[round_key[3] & 0xFF];
        tword <<= 8;
        tword ^= SBOX[(round_key[3] >> 24) & 0xFF];
        tword ^= ROUND_CONSTANTS[round] << 24;

        round_key[0] ^= tword;
        round_key[1] ^= round_key[0];
        round_key[2] ^= round_key[1];
        round_key[3] ^= round_key[2];

        memcpy(aes->round_keys[round], round_key, sizeof(block));
    }

    return;
}

// Calculates the round keys for a key of length 192 bit
void keyschedule192(AES* aes) {
    word round_key[6];
    memcpy(round_key, aes->key, 6 * sizeof(word));
    word tword;
    aes->round_keys = malloc((aes->rounds + 1) * sizeof(block));

    memcpy(aes->round_keys[0], round_key, sizeof(block));

    for (size_t round = 1; round <= aes->rounds; ++round) {
        if (round % 3 == 1) {
            aes->round_keys[round][0] = round_key[4];
            aes->round_keys[round][1] = round_key[5];
        }

        if (round % 3 == 2) {
            aes->round_keys[round][0] = round_key[2];
            aes->round_keys[round][1] = round_key[3];
            aes->round_keys[round][2] = round_key[4];
            aes->round_keys[round][3] = round_key[5];
            continue;
        }

        tword = SBOX[(round_key[5] >> 16) & 0xff];
        tword <<= 8;
        tword ^= SBOX[(round_key[5] >> 8) & 0xff];
        tword <<= 8;
        tword ^= SBOX[round_key[5] & 0xff];
        tword <<= 8;
        tword ^= SBOX[(round_key[5] >> 24) & 0xff];
        tword ^= ROUND_CONSTANTS[(2 * round + 1) / 3] << 24;

        round_key[0] ^= tword;
        round_key[1] ^= round_key[0];
        round_key[2] ^= round_key[1];
        round_key[3] ^= round_key[2];
        round_key[4] ^= round_key[3];
        round_key[5] ^= round_key[4];

        if (round % 3 == 0) {
            aes->round_keys[round][0] = round_key[0];
            aes->round_keys[round][1] = round_key[1];
            aes->round_keys[round][2] = round_key[2];
            aes->round_keys[round][3] = round_key[3];
        } else if (round % 3 == 1) {
            aes->round_keys[round][2] = round_key[0];
            aes->round_keys[round][3] = round_key[1];
        }
    }
    return;
}

// Calculates the round keys for a key of length 256 bit
void keyschedule256(AES* aes) {
    word round_key[8];
    memcpy(round_key, aes->key, 8 * sizeof(word));
    word tword;
    aes->round_keys = malloc((aes->rounds + 1) * sizeof(block));

    memcpy(aes->round_keys[0], round_key, sizeof(block));
    memcpy(aes->round_keys[1], &round_key[4], sizeof(block));

    for (unsigned round = 2; round <= aes->rounds; ++round) {
        if (round % 2 == 0) {
            tword = SBOX[(round_key[7] >> 16) & 0xff];
            tword <<= 8;
            tword ^= SBOX[(round_key[7] >> 8) & 0xff];
            tword <<= 8;
            tword ^= SBOX[round_key[7] & 0xff];
            tword <<= 8;
            tword ^= SBOX[(round_key[7] >> 24) & 0xff];
            tword ^= ROUND_CONSTANTS[round / 2] << 24;

            round_key[0] ^= tword;
            round_key[1] ^= round_key[0];
            round_key[2] ^= round_key[1];
            round_key[3] ^= round_key[2];

            tword = SBOX[(round_key[3] >> 24) & 0xff] << 24;
            tword ^= SBOX[(round_key[3] >> 16) & 0xff] << 16;
            tword ^= SBOX[(round_key[3] >> 8) & 0xff] << 8;
            tword ^= SBOX[round_key[3] & 0xff];

            round_key[4] ^= tword;
            round_key[5] ^= round_key[4];
            round_key[6] ^= round_key[5];
            round_key[7] ^= round_key[6];

            aes->round_keys[round][0] = round_key[0];
            aes->round_keys[round][1] = round_key[1];
            aes->round_keys[round][2] = round_key[2];
            aes->round_keys[round][3] = round_key[3];
        } else {
            aes->round_keys[round][0] = round_key[4];
            aes->round_keys[round][1] = round_key[5];
            aes->round_keys[round][2] = round_key[6];
            aes->round_keys[round][3] = round_key[7];
        }
    }
    return;
}

// Constructs the round keys for decryption from roundkeys
void set_invroundkeys(AES* aes) {
    aes->inv_round_keys = malloc((aes->rounds + 1) * sizeof(block));

    memcpy(aes->inv_round_keys[0], aes->round_keys[aes->rounds], sizeof(block));
    for (size_t r = 1; r < aes->rounds; ++r) {
        memcpy(aes->inv_round_keys[r], aes->round_keys[aes->rounds - r],
               sizeof(block));
        invMixColumns(aes->inv_round_keys[r]);
    }
    memcpy(aes->inv_round_keys[aes->rounds], aes->round_keys[0], sizeof(block));
}

// The SubBytes step for a block.
void SubBytes(word* m) {
    for (unsigned w = 0; w < 4; ++w) {
        m[w] = (SBOX[m[w] >> 24] << 24) ^ (SBOX[(m[w] >> 16) & 0xff] << 16) ^
               (SBOX[(m[w] >> 8) & 0xff] << 8) ^ SBOX[m[w] & 0xff];
    }
}

// The invSubBytes step for a block.
void invSubBytes(word* m) {
    for (unsigned w = 0; w < 4; ++w) {
        m[w] = (INVSBOX[m[w] >> 24] << 24) ^ (INVSBOX[(m[w] >> 16) & 0xff] << 16) ^
               (INVSBOX[(m[w] >> 8) & 0xff] << 8) ^ INVSBOX[m[w] & 0xff];
    }
}

// The ShiftRows step
void ShiftRows(word* m) {
    word w0, w1, w2, w3;
    // Shift the second row
    w0 = m[0] & 0x00ff0000;
    w1 = m[1] & 0x00ff0000;
    w2 = m[2] & 0x00ff0000;
    w3 = m[3] & 0x00ff0000;
    m[0] ^= w0 ^ w1;
    m[1] ^= w1 ^ w2;
    m[2] ^= w2 ^ w3;
    m[3] ^= w3 ^ w0;

    // Shift the third row
    w0 = m[0] & 0x0000ff00;
    w1 = m[1] & 0x0000ff00;
    w2 = m[2] & 0x0000ff00;
    w3 = m[3] & 0x0000ff00;
    m[0] ^= w0 ^ w2;
    m[1] ^= w1 ^ w3;
    m[2] ^= w2 ^ w0;
    m[3] ^= w3 ^ w1;

    // Shift the fourth row
    w0 = m[0] & 0x000000ff;
    w1 = m[1] & 0x000000ff;
    w2 = m[2] & 0x000000ff;
    w3 = m[3] & 0x000000ff;
    m[0] ^= w0 ^ w3;
    m[1] ^= w1 ^ w0;
    m[2] ^= w2 ^ w1;
    m[3] ^= w3 ^ w2;
}

// The invShiftRows step
void invShiftRows(word* m) {
    word w0, w1, w2, w3;
    // Shift the second row
    w0 = m[0] & 0x00ff0000;
    w1 = m[1] & 0x00ff0000;
    w2 = m[2] & 0x00ff0000;
    w3 = m[3] & 0x00ff0000;
    m[0] ^= w0 ^ w3;
    m[1] ^= w1 ^ w0;
    m[2] ^= w2 ^ w1;
    m[3] ^= w3 ^ w2;

    // Shift the third row
    w0 = m[0] & 0x0000ff00;
    w1 = m[1] & 0x0000ff00;
    w2 = m[2] & 0x0000ff00;
    w3 = m[3] & 0x0000ff00;
    m[0] ^= w0 ^ w2;
    m[1] ^= w1 ^ w3;
    m[2] ^= w2 ^ w0;
    m[3] ^= w3 ^ w1;

    // Shift the fourth row
    w0 = m[0] & 0x000000ff;
    w1 = m[1] & 0x000000ff;
    w2 = m[2] & 0x000000ff;
    w3 = m[3] & 0x000000ff;
    m[0] ^= w0 ^ w1;
    m[1] ^= w1 ^ w2;
    m[2] ^= w2 ^ w3;
    m[3] ^= w3 ^ w0;
}

// The MixColumns step.
void MixColumns(word* m) {
    block t = {0, 0, 0, 0};
    for (unsigned i = 0; i < 4; ++i) {
        for (unsigned j = 0; j < 4; ++j) {
            // Calculate b1 = S(a)*1, b2 = S(a)*2 and b3 = S(a)*3
            word b1 = (m[i] >> 8 * (3 - j)) & 0xFF;
            word b2;
            if ((b1 & 0x80) == 0x80) {
                b2 = ((b1 << 1) & 0xFF) ^ 0x1b;
            } else {
                b2 = (b1 << 1) & 0xFF;
            }
            word b3 = b1 ^ b2;

            if (j == 0) {
                t[i] ^= (b2 << 24) ^ (b1 << 16) ^ (b1 << 8) ^ b3;
            } else if (j == 1) {
                t[i] ^= (b3 << 24) ^ (b2 << 16) ^ (b1 << 8) ^ b1;
            } else if (j == 2) {
                t[i] ^= (b1 << 24) ^ (b3 << 16) ^ (b2 << 8) ^ b1;
            } else if (j == 3) {
                t[i] ^= (b1 << 24) ^ (b1 << 16) ^ (b3 << 8) ^ b2;
            }
        }
    }
    memcpy(m, t, sizeof(block));
}

// The invMixColumns step.
void invMixColumns(word* m) {
    // 9 = 1001
    // b = 1011
    // d = 1101
    // e = 1110
    block t = {0, 0, 0, 0};
    word w, w9, wb, wd, we;
    for (unsigned i = 0; i < 4; ++i) {
        for (unsigned j = 0; j < 4; ++j) {
            w = w9 = wb = wd = (m[i] >> 8 * (3 - j)) & 0xFF;
            we = 0;
            if (((w & 0x80) == 0x80))
                w = ((w << 1) & 0xFF) ^ 0x1b;
            else
                w = ((w << 1) & 0xFF);
            wb ^= w;
            we ^= w;
            if (((w & 0x80) == 0x80))
                w = ((w << 1) & 0xFF) ^ 0x1b;
            else
                w = ((w << 1) & 0xFF);
            wd ^= w;
            we ^= w;
            if (((w & 0x80) == 0x80))
                w = ((w << 1) & 0xFF) ^ 0x1b;
            else
                w = ((w << 1) & 0xFF);
            w9 ^= w;
            wb ^= w;
            wd ^= w;
            we ^= w;
            if (j == 0) {
                t[i] ^= (we << 24) ^ (w9 << 16) ^ (wd << 8) ^ wb;
            } else if (j == 1) {
                t[i] ^= (wb << 24) ^ (we << 16) ^ (w9 << 8) ^ wd;
            } else if (j == 2) {
                t[i] ^= (wd << 24) ^ (wb << 16) ^ (we << 8) ^ w9;
            } else if (j == 3) {
                t[i] ^= (w9 << 24) ^ (wd << 16) ^ (wb << 8) ^ we;
            }
        }
    }
    memcpy(m, t, sizeof(block));
}

void set_invsbox(void) {
    for (word b = 0; b < 256; ++b) {
        INVSBOX[SBOX[b]] = b;
    }
    return;
}

void calc_tables(void) {
    // Calculate the entries for the T-tables in parallel
    for (word a = 0; a < 256; ++a) {
        // Calculate b1 = S(a)*1, b2 = S(a)*2 and b3 = S(a)*3
        word b1 = SBOX[a];
        word b2;
        if ((b1 & 0x80) == 0x80) {
            b2 = ((b1 << 1) & 0xff) ^ 0x1b;
        } else {
            b2 = (b1 << 1) & 0xff;
        }
        word b3 = b1 ^ b2;

        // Store the combined 32-bit vectors in the T-tables
        T0[a] = (b2 << 24) ^ (b1 << 16) ^ (b1 << 8) ^ b3;
        T1[a] = (b3 << 24) ^ (b2 << 16) ^ (b1 << 8) ^ b1;
        T2[a] = (b1 << 24) ^ (b3 << 16) ^ (b2 << 8) ^ b1;
        T3[a] = (b1 << 24) ^ (b1 << 16) ^ (b3 << 8) ^ b2;
    }
    return;
}

void calc_invtables() {
    // Calculate the entries for the T-tables in parallel
    word w, w9, wb, wd, we;
    for (word a = 0; a < 256; ++a) {
        // Calculate w9 = invS(a)*0x09, wb = invS(a)*0x0b,
        // wd = invS(a)*0x0d and we = invS(a)*0x0e
        w = w9 = wb = wd = INVSBOX[a];
        we = 0;
        if ((w & 0x80) == 0x80) {
            w = ((w << 1) & 0xFF) ^ 0x1b;
        } else {
            w = ((w << 1) & 0xFF);
        }
        wb ^= w;
        we ^= w;
        if ((w & 0x80) == 0x80) {
            w = ((w << 1) & 0xFF) ^ 0x1b;
        } else {
            w = ((w << 1) & 0xFF);
        }
        wd ^= w;
        we ^= w;
        if ((w & 0x80) == 0x80) {
            w = ((w << 1) & 0xFF) ^ 0x1b;
        } else {
            w = ((w << 1) & 0xFF);
        }
        w9 ^= w;
        wb ^= w;
        wd ^= w;
        we ^= w;

        // Store the combined 32-bit vectors in the T-tables
        INVT0[a] = (we << 24) ^ (w9 << 16) ^ (wd << 8) ^ wb;
        INVT1[a] = (wb << 24) ^ (we << 16) ^ (w9 << 8) ^ wd;
        INVT2[a] = (wd << 24) ^ (wb << 16) ^ (we << 8) ^ w9;
        INVT3[a] = (w9 << 24) ^ (wd << 16) ^ (wb << 8) ^ we;
    }
    return;
}
