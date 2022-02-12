#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES/aes.h"
#include "Helpers/helpers.h"
#include "SquareAttack/square.h"

// Example on p. 34 of FIPS 197
const unsigned char DEFAULT_INPUT[] = {0x32, 0x88, 0x31, 0xe0,
                                       0x43, 0x5a, 0x31, 0x37,
                                       0xf6, 0x30, 0x98, 0x07,
                                       0xa8, 0x8d, 0xa2, 0x34};

// Example on p. 34 of FIPS 197
const unsigned char DEFAULT_CIPHER_KEY[] = {0x2b, 0x28, 0xab, 0x09,
                                            0x7e, 0xae, 0xf7, 0xcf,
                                            0x15, 0xd2, 0x15, 0x4f,
                                            0x16, 0xa6, 0x88, 0x3c};

const size_t DEFAULT_ROUNDS = 4;

int main(int argc, char* argv[])
{
    unsigned char *input;
    unsigned char* key;
    size_t rounds = DEFAULT_ROUNDS;

    if (argc != 4) { // first argument is executable name + path, therefore it is 4 and not 3
        printf("WARNING: Provide exactly 3 arguments to the program: 16 bytes of input in hex, 16 bytes of cipher key in hex, and the number of rounds in decimal.\n");
        printf("Continuing with sample values.\n\n");

        input = malloc(BLOCK_SIZE);
        memcpy(input, DEFAULT_INPUT, BLOCK_SIZE);
        key = malloc(BLOCK_SIZE);
        memcpy(key, DEFAULT_CIPHER_KEY, BLOCK_SIZE);
    } else {
        // Parse the arguments as blocks, and the number of rounds
        input = block_from_string(argv[1]);
        key = block_from_string(argv[2]);
        rounds = strtoul(argv[3], NULL, 10);
    }

    // Encrypt the given input with the given key and number of rounds (should be 4 rounds for Square attack)
    unsigned char* encrypted_input = encrypt(input, key, rounds);

    // Generate a lambda set
    unsigned char** lambda = generate_lambda_set();

    // Encrypt all blocks in the lambda set, with the same number of rounds
    for (size_t i = 0; i < SETS; i++) {
        lambda[i] = encrypt(lambda[i], key, rounds);
        //print_with_msg(lambda[i], format_str("Set %d", i));
    }

    // TODO: Just for testing, needs to be guessed later
    unsigned char last_round_key[] = {0x3d, 0x47, 0x1e, 0x6d,
                                      0x80, 0x16, 0x23, 0x7a,
                                      0x47, 0xfe, 0x7e, 0x88,
                                      0x7d, 0x3e, 0x44, 0x3b};

    for (size_t i = 0; i < SETS; i++) {
        reverse_last_round(lambda[i], last_round_key);
        //print_with_msg(lambda[i], format_str("Reversing round %d", i));
    }

    unsigned char result = lambda[0][0];
    for (size_t i = 1; i < SETS; i++) {
        result ^= lambda[i][0];
    }

    printf("Result: %02x", result);

    // Free up memory
    free(input);
    free(key);
    free(encrypted_input);
    free(lambda);

    return 0;
}