#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES/aes.h"
#include "Helpers/helpers.h"
#include "SquareAttack/square.h"

#define DEBUG_MAIN // comment this out to disable debug mode

// Example on p. 34 of FIPS 197
const unsigned char DEFAULT_CIPHER_KEY[] = {0x2b, 0x28, 0xab, 0x09,
                                            0x7e, 0xae, 0xf7, 0xcf,
                                            0x15, 0xd2, 0x15, 0x4f,
                                            0x16, 0xa6, 0x88, 0x3c};

const size_t DEFAULT_ROUNDS = 4;
const size_t LAMBDAS = 3;

bool has_found_entire_last_round_key(const unsigned char* no_of_guesses) {
    bool all_have_exactly_one = true;
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        if (no_of_guesses[i] != 1) {
            all_have_exactly_one = false;
            break;
        }
    }
    return all_have_exactly_one;
}

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

    // Holds an array of potentially correct key bytes for each position in the key. Updated after checking a new lambda set until only candidate is left.
    unsigned char** potentially_correct = malloc(sizeof(unsigned char*) * BLOCK_SIZE);
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        potentially_correct[i] = malloc(sizeof(unsigned char) * SETS); // Allocate space for 256 possible guesses, just in case
    }

    unsigned char* no_of_guesses_in_list = malloc(sizeof(unsigned char) * BLOCK_SIZE); // Keeps track of how many guesses are in each array
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        no_of_guesses_in_list[i] = 0; // Initialize all values to 0
    }

    // Collect guesses from random lambda sets until there is only a single candidate left for all positions
    size_t iter = 0;
    while (!has_found_entire_last_round_key(no_of_guesses_in_list)) {
        iter++;

        // Generate lambda set with increasing values in position 0, and random values in other positions (that are the same across all blocks)
        unsigned char** lambda = generate_lambda_set();
        for (size_t i = 0; i < SETS; i++) {
            lambda[i] = encrypt(lambda[i], key, rounds);
        }

        // For each of the 16 positions, guess the byte of the key corresponding to the position, using the encrypted lambda set
        for (size_t pos = 0; pos < BLOCK_SIZE; pos++) {
            // Guess the possible round keys for each position in the block
            size_t no_of_guesses;
            unsigned char* guesses = guess_round_key(lambda, pos, &no_of_guesses);

            if (no_of_guesses_in_list[pos] == 0) {
                // No guesses have been added yet, just add them all
                for (size_t g = 0; g < no_of_guesses; g++) {
                    potentially_correct[pos][no_of_guesses_in_list[pos]] = guesses[g];
                    no_of_guesses_in_list[pos]++;
                }
            } else if (no_of_guesses_in_list[pos] > 1) {
                // Remove any guesses that are not in the new guesses, because that means they are not correct
#ifdef DEBUG_MAIN
                for (size_t i = 0; i < BLOCK_SIZE; i++) {
                    printf("Guesses for position %zu (%hhu entries):\n", i, no_of_guesses_in_list[i]);
                    for (size_t g = 0; g < no_of_guesses_in_list[i]; g++) {
                        printf("%02x ", potentially_correct[i][g]);
                    }
                    printf("\n");
                }
#endif

                // TODO: Rework this. Is accessing out-of-bounds values and causes segmentation fault.
                for (size_t g = 0; g < no_of_guesses_in_list[pos]; g++) {
                    bool found = false;
                    unsigned char to_find = potentially_correct[pos][g];
                    for (size_t i = 0; i < no_of_guesses; i++) {
                        if (guesses[i] == to_find) {
                            found = true;
                            break;
                        }
                    }

                    if (!found) {
                        // TODO: Basically copy existing list but without element that couldn't be found, and then update the no. of guesses in list array
                        unsigned char* new_list = malloc(sizeof(unsigned char) * (no_of_guesses_in_list[pos] - 1));
                        for (size_t i = 0; i < no_of_guesses_in_list[pos]; i++) {
                            if (potentially_correct[pos][i] != to_find) {
                                new_list[i] = potentially_correct[pos][i];
                                // TODO: This kinda skips an entry, gotta rework
                            }
                        }

                        potentially_correct[pos] = new_list;
                        no_of_guesses_in_list[pos]--;
                    }
                }
            }
        }
    }

    // Print out the values found for each position
    printf("Found last round key by reversing %zu lambda sets.\n", iter);
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        printf("Correct guess for position %zu: %02x.\n", i, potentially_correct[i][0]);
    }

    free(potentially_correct);
    free(no_of_guesses_in_list);

    return 0;

    // TODO: Old code below

    // Generate multiple lambda sets to ensure that no false-positives are assumed to be correct guesses
    unsigned char*** lambdas = generate_lambda_sets(LAMBDAS);

    // Encrypt all blocks in all lambda sets, with the same number of rounds
    for (size_t l = 0; l < LAMBDAS; l++) {
        for (size_t i = 0; i < SETS; i++) {
            lambdas[l][i] = encrypt(lambdas[l][i], key, rounds);
        }
    }

    // Attempt to guess round keys for all lambdas
    // TODO: Currently just attempts to find byte at position 0
    for (size_t l = 0; l < LAMBDAS; l++) {
        size_t no_correct_guesses;
        unsigned char* correct_guesses = guess_round_key(lambdas[l], 6, &no_correct_guesses);
        printf("Found %zu correct guesses for set %zu.\n", no_correct_guesses, l);
        for (size_t i = 0; i < no_correct_guesses; i++) {
            printf("Guess: %02x\n", correct_guesses[i]);
        }
    }

    return 0;

    free(key);
    free(lambdas);

    return 0;
}