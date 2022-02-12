#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES/aes.h"
#include "Helpers/helpers.h"
#include "Helpers/set.h"
#include "SquareAttack/square.h"

// Example on p. 34 of FIPS 197
const unsigned char DEFAULT_CIPHER_KEY[] = {0x2b, 0x28, 0xab, 0x09,
                                            0x7e, 0xae, 0xf7, 0xcf,
                                            0x15, 0xd2, 0x15, 0x4f,
                                            0x16, 0xa6, 0x88, 0x3c};

const size_t DEFAULT_ROUNDS = 4;

/// Checks all sets of guesses (one set for each byte position) to see whether there is only one guess.
/// If there is more than one, the search has to be continued until only one candidate is left, which will 100% be the correct one.
bool has_found_entire_last_round_key(SimpleSet guesses[], size_t n) {
    bool all_have_exactly_one = true;
    for (size_t i = 0; i < n; i++) {
        if (set_length(&guesses[i]) != 1) {
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

    print_with_msg(key, "Encrypting lambda sets with the cipher key:");

    SimpleSet all_guesses[BLOCK_SIZE]; // Store all guesses for each position in the key in a set
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        set_init(&all_guesses[i]); // Initialize each set
    }

    // Collect all_guesses from random lambda sets until there is only a single candidate left for all positions
    size_t iter = 0;
    while (!has_found_entire_last_round_key(all_guesses, BLOCK_SIZE)) {
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

            // Create a new set containing the new guesses, and form an intersection with the existing guesses so that only the matching ones remain
            SimpleSet new_guesses;
            set_init(&new_guesses);
            for (size_t i = 0; i < no_of_guesses; i++) {
                set_add(&new_guesses, format_str("%02x", guesses[i])); // Set implementation only supports strings, so we store it as a hex string
            }

            if (set_length(&all_guesses[pos]) == 0) {
                all_guesses[pos] = new_guesses; // No guessed added yet, so an intersection would be the empty set
            } else {
                SimpleSet intersection;
                set_init(&intersection);
                set_intersection(&intersection, &all_guesses[pos], &new_guesses); // The intersection only contains the guesses contained in all iterations
                set_destroy(&all_guesses[pos]); // destroy old set
                all_guesses[pos] = intersection;
            }
        }
    }

    // Print out the last round key that was found
    char* key_guess = malloc(sizeof(char) * BLOCK_SIZE * 2); // 32-char long key in hex format
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        size_t size;
        char** guesses = set_to_array(&all_guesses[i], &size);
        char* correct_guess = guesses[0]; // Impossible that it contains more than 1 item
        key_guess[i * 2] = correct_guess[0]; // First character of 2-char long hex code
        key_guess[i * 2 + 1] = correct_guess[1]; // Second character of 2-char long hex code
    }

    unsigned char* key_block = block_from_string(key_guess);
    print_with_msg(key_block, format_str("Found last round key after reversing %zu lambda sets:", iter));

    // Clear memory
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        set_destroy(&all_guesses[i]);
    }

    free(key);
    free(key_guess);
    free(key_block);
}