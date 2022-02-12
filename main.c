#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES/aes.h"
#include "Helpers/helpers.h"
#include "SquareAttack/square.h"

//#define DEBUG_MAIN // comment this out to disable debug mode

// Example on p. 34 of FIPS 197
const unsigned char DEFAULT_CIPHER_KEY[] = {0x2b, 0x28, 0xab, 0x09,
                                            0x7e, 0xae, 0xf7, 0xcf,
                                            0x15, 0xd2, 0x15, 0x4f,
                                            0x16, 0xa6, 0x88, 0x3c};

const size_t DEFAULT_ROUNDS = 4;
const size_t LAMBDAS = 3;

int main(int argc, char* argv[])
{
    unsigned char* key;
    size_t rounds = DEFAULT_ROUNDS;

    if (argc != 3) { // first argument is executable name + path, therefore it is 3 and not 2
        printf("WARNING: Provide exactly 2 arguments to the program: 16 bytes of cipher key in hex, and the number of rounds in decimal.\n");
        printf("Continuing with sample values.\n\n");

        key = malloc(BLOCK_SIZE);
        memcpy(key, DEFAULT_CIPHER_KEY, BLOCK_SIZE);
    } else {
        // Parse the arguments as blocks, and the number of rounds
        key = block_from_string(argv[2]);
        rounds = strtoul(argv[3], NULL, 10);
    }

    // Generate multiple lambda sets to ensure that no false-positives are assumed to be correct guesses
    unsigned char*** lambdas = generate_lambda_sets(LAMBDAS);

#ifdef DEBUG_MAIN
    for (size_t l = 0; l < LAMBDAS; l++) {
        printf("Lambda Set %zu:\n", l);
        for (size_t b = 0; b < SETS; b++) {
            print_with_msg(lambdas[l][b], format_str("Block %zu:", b));
        }
    }
#endif

    // Encrypt all blocks in all lambda sets, with the same number of rounds
    for (size_t l = 0; l < LAMBDAS; l++) {
        for (size_t i = 0; i < SETS; i++) {
            lambdas[l][i] = encrypt(lambdas[l][i], key, rounds);
        }
    }

#ifdef DEBUG_MAIN
    for (size_t l = 0; l < LAMBDAS; l++) {
        printf("Lambda Set %zu after encryption:\n", l);
        for (size_t b = 0; b < SETS; b++) {
            print_with_msg(lambdas[l][b], format_str("Block %zu:", b));
        }
    }
#endif

    // Attempt to guess round keys for all lambdas
    // TODO: Currently just attempts to find byte at position 0
    for (size_t l = 0; l < LAMBDAS; l++) {
        size_t no_correct_guesses;
        unsigned char* correct_guesses = guess_round_key(lambdas[l], 0, &no_correct_guesses);
        printf("Found %zu correct guesses for set %zu.\n", no_correct_guesses, l);
        for (size_t i = 0; i < no_correct_guesses; i++) {
            printf("Guess: %02x\n", correct_guesses[i]);
        }
    }

    free(key);
    free(lambdas);

    return 0;
}