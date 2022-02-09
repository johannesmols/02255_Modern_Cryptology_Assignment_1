// Sample implementation given by the lecturer

#ifndef AES_H_
#define AES_H_

#include <stddef.h>  // For size_t.
#include <stdint.h>  // For uint8_t, uint32_t.

typedef uint32_t word;  // A word is an unsigned of 32-bit size.
typedef word block[4];  // A block is an array of 4 words.

typedef struct AES {
    size_t key_size;
    word* key;
    size_t rounds;
    block* round_keys;
    block* inv_round_keys;
} AES;

AES* create_aes_instance(word* key, size_t key_size);
void delete_aes_instance(AES* aes);
void encrypt(AES* aes, word* m);
void decrypt(AES* aes, word* m);

extern const word SBOX[256];
extern word INVSBOX[256];
extern const word ROUND_CONSTANTS[256];

#endif
