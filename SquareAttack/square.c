#include <malloc.h>
#include <limits.h>
#include <string.h>

#include "square.h"
#include "../AES/aes.h"
#include "../AES/constants.h"
#include "../Helpers/helpers.h"

const size_t SETS = 256;

#pragma region Lambdas

unsigned char** generate_lambda_set() {
    unsigned char** lambda = malloc(sizeof(unsigned char*) * SETS);

    unsigned char* arr = generate_random_block(); // Using the same randomized values across all 256 blocks
    for (size_t i = 0; i < SETS; i++) {
        lambda[i] = malloc(sizeof(unsigned char) * BLOCK_SIZE);

        // Assigning index of set to first element of each block so that each set's first value is unique
        lambda[i][0] = i;

        // Assigning index of value in block, which is the same across all sets. Shouldn't just set all to 0 to avoid meaningless results.
        for (size_t j = 1; j < BLOCK_SIZE; j++) {
            lambda[i][j] = arr[j];
        }
    }

    return lambda;
}

unsigned char*** generate_lambda_sets(size_t n) {
    unsigned char*** lambdas = malloc(sizeof(unsigned char*) * n);

    for (size_t i = 0; i < n; i++) {
        lambdas[i] = generate_lambda_set();
    }

    return lambdas;
}

#pragma endregion

#pragma region Reversal

/// Reverse the last round of a block given a single byte of the key, and its corresponding position in the block.
/// Return the reversed byte at the given position.
unsigned char reverse_last_round(const unsigned char* block, unsigned char key, size_t key_pos) {
    unsigned char* copy = malloc(sizeof(unsigned char) * BLOCK_SIZE);
    memcpy(copy, block, BLOCK_SIZE);

    copy[key_pos] ^= key; // Reverse AddRoundKey
    sub_bytes(&copy[key_pos], InverseSBox, 1); // Inverse SubBytes on single byte

    unsigned char value = copy[key_pos];
    free(copy);

    return value;
}

/// Make a guess for a byte of the last round key in the given position, and return the array of best guesses.
unsigned char* guess_round_key(unsigned char** lambda, size_t key_pos, size_t* no_of_guesses) {
    unsigned char* guesses = malloc(sizeof(unsigned char) * SETS);
    unsigned char guesses_count = 0;

    for (unsigned char guess = 0; guess < (unsigned char) UCHAR_MAX; guess++) { // go through all possible guesses
        unsigned char* values = malloc(sizeof(unsigned char) * SETS); // store all 256 reversed values with guess
        for (size_t i = 0; i < SETS; i++) {
            values[i] = reverse_last_round(lambda[i], guess, key_pos);
        }

        // Check whether XOR'ing all 256 reversed values gives 0. If it does, the guess might be correct.
        unsigned char result = values[0];
        for (size_t i = 1; i < SETS; i++) {
            result ^= values[i];
        }

        if (result == 0) {
            guesses[guesses_count] = guess;
            guesses_count++;
        }

        free(values);
    }

    realloc(guesses, sizeof(unsigned char) * guesses_count); // Reallocate memory according to how many correct guesses were made
    *no_of_guesses = guesses_count; // Assign no. of guesses to pointer passed in so that the caller knows the size

    return guesses;
}

#pragma endregion