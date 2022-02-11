#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES/aes.h"

const unsigned char DEFAULT_INPUT[] = {0x32, 0x88, 0x31, 0xe0,
                                       0x43, 0x5a, 0x31, 0x37,
                                       0xf6, 0x30, 0x98, 0x07,
                                       0xa8, 0x8d, 0xa2, 0x34};

const unsigned char DEFAULT_CIPHER_KEY[] = {0x2b, 0x28, 0xab, 0x09,
                                            0x7e, 0xae, 0xf7, 0xcf,
                                            0x15, 0xd2, 0x15, 0x4f,
                                            0x16, 0xa6, 0x88, 0x3c};

const size_t DEFAULT_ROUNDS = 10;

/// Reads a 32-char long hex string into a 4x4 block, reading row by row
unsigned char* block_from_string(const char* string) {
    unsigned char* block = malloc(BLOCK_SIZE);
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        char sub_string[2], *ptr = sub_string;
        memcpy(sub_string, &string[i * 2], 2);
        sscanf(ptr, "%2hhx", &block[i]);
    }

    return block;
}

int main(int argc, char* argv[])
{
    if (argc != 4) { // first argument is executable name + path
        fprintf(stderr, "WARNING: Provide exactly 3 arguments to the program: 16 bytes of input in hex, 16 bytes of cipher key in hex, and the number of rounds in decimal.\n");
        printf("Continuing with sample values.\n\n");
        unsigned char* encrypted_sample = encrypt(DEFAULT_INPUT, DEFAULT_CIPHER_KEY, 10); // example on p. 34 of FIPS 197
        return 0;
    }

    unsigned char* input = block_from_string(argv[1]);
    unsigned char* key = block_from_string(argv[2]);
    size_t rounds = strtoul(argv[3], NULL, 10);

    unsigned char* encrypted = encrypt(input, key, rounds);

    return 0;
}