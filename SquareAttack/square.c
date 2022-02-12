#include <malloc.h>

#include "square.h"
#include "../AES/aes.h"
#include "../AES/constants.h"
#include "../Helpers/helpers.h"

const size_t SETS = 256;

unsigned char** generate_lambda_set() {
    unsigned char** lambda = malloc(sizeof(unsigned char*) * SETS);

    for (size_t i = 0; i < SETS; i++) {
        lambda[i] = malloc(sizeof(unsigned char) * BLOCK_SIZE);

        // Assigning index of set to first element of each block so that each set's first value is unique
        lambda[i][0] = i;

        // Assigning index of value in block, which is the same across all sets. Shouldn't just set all to 0 to avoid meaningless results.
        for (size_t j = 1; j < BLOCK_SIZE; j++) {
            lambda[i][j] = j;
        }
    }

    return lambda;
}

void reverse_last_round(unsigned char* block, unsigned char* key) {
    xor_blocks(block, key, BLOCK_SIZE);
    sub_bytes(block, InverseSBox, BLOCK_SIZE);
}