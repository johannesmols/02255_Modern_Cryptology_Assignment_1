#include <stdbool.h>
#include <malloc.h>
#include <string.h>

#include "aes.h"
#include "constants.h"
#include "../Helpers/helpers.h"

/// Perform XOR on each byte in the block, and store the results in the first argument.
void xor_blocks(unsigned char* a, const unsigned char* b, size_t n) {
    for (int i = 0; i < n; i++) {
        a[i] ^= b[i];
    }
}

/// Substitute each byte given some S-Box, and store the results in the given argument.
void sub_bytes(unsigned char* block, const unsigned char* s_box, size_t n) {
    for (int i = 0; i < n; i++) {
        block[i] = s_box[block[i]];
    }
}

/// Shift a row in a block to the left, re-adding overflowing entries on the right side again.
/// The start and end parameter define the index range of the operation, and N defines how often to repeat it.
/// Certainly not the most efficient way of doing it, but hey, it works.
void shift_left(unsigned char* block, int start, int end, int n) {
    for (int iter = 0; iter < n; iter++) {
        unsigned char first = block[start];
        for (int i = start; i < end; i++) {
            swap_values(block, i, i + 1);
        }
        block[end] = first; // TODO: Maybe unnecessary?
    }
}

/// Shift a row in a block to the right, re-adding overflowing entries on the left side again.
/// The start and end parameter define the index range of the operation, and N defines how often to repeat it.
/// Certainly not the most efficient way of doing it, but hey, it works.
void shift_right(unsigned char* block, int start, int end, int n) {
    for (int iter = 0; iter < n; iter++) {
        unsigned char last = block[end];
        for (int i = end; i > start; i--) {
            swap_values(block, i, i - 1);
        }
        block[start] = last; // TODO: Maybe unnecessary?
    }
}

/// Perform the ShiftRow operation on a block.
void shift_rows(unsigned char* block) {
    for (int r = 1; r < 4; r++) { // start from 2nd row
        shift_left(block, r * 4, r * 4 + 3, r);
    }
}

/// Perform the inverse ShiftRow operation on a block.
void inv_shift_rows(unsigned char* block) {
    for (int r = 1; r < 4; r++) { // start from 2nd row
        shift_right(block, r * 4, r * 4 + 3, r);
    }
}

/// Perform the MixColumn operation with the help of lookup tables to perform multiplications in Rijndael's finite field.
void mix_columns(unsigned char* block) {
    for (int c = 0; c < 4; c++) {
        unsigned char col[] = {block[c], block[c + 4], block[c + 8], block[c + 12]};
        block[c] = MultiplyBy2[col[0]] ^ MultiplyBy3[col[1]] ^ col[2] ^ col[3];
        block[c + 4] = col[0] ^ MultiplyBy2[col[1]] ^ MultiplyBy3[col[2]] ^ col[3];
        block[c + 8] = col[0] ^ col[1] ^ MultiplyBy2[col[2]] ^ MultiplyBy3[col[3]];
        block[c + 12] = MultiplyBy3[col[0]] ^ col[1] ^ col[2] ^ MultiplyBy2[col[3]];
    }
}

/// Rotate a 4x4 matrix 90 degrees to the left or right
void rotate(unsigned char* block, bool left) {
    unsigned char rot[BLOCK_SIZE];
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            // calculates where the value for the current index is stored, depending on the direction to rotate to
            rot[c + (4 * r)] = block[left
                                   ? (3 - r) + (4 * c)
                                   : (3 - c) * 4 + r];
        }
    }
    memcpy(block, rot, BLOCK_SIZE);
}

/// Derive the next key from the last one, given a round number (starting at 0).
/// This implementation first rotates the matrix to make it easier to work with index ranges.
/// This also reverses the order of the rows, where the last row is now the first, and vice-versa.
/// In the end, the block is rotated back. I know this is not very efficient, but I found it easiest to visualize it like this.
void derive_next_key(unsigned char* key, size_t round) {
    rotate(key, true);

    unsigned char orig_last_row[4];
    memcpy(orig_last_row, &key[0], 4); // Copy last row for later user before modifying it

    shift_left(key, 0, 3, 1); // Shift the last row one to the left
    sub_bytes(&key[0], SBox, 4); // Substitute bytes on last row using the S-Box
    key[0] ^= RoundConstants[round]; // Add round constant to 1st byte of last row

    xor_blocks(&key[12], &key[0], 4); // XOR above derived word with first row
    xor_blocks(&key[8], &key[12], 4); // XOR new first row with second row
    xor_blocks(&key[4], &key[8], 4); // XOR new second row with third row

    unsigned char third_row[4];
    memcpy(third_row, &key[4], 4); // Get copy of 3rd row so as not to modify it in next step
    xor_blocks(third_row, orig_last_row, 4); // XOR new third row with original last row
    memcpy(&key[0], third_row, 4); // Put modified row back into key

    rotate(key, false); // rotate clockwise back into correct position
}

/// Perform a round of AES. The last_round parameter decides whether the MixColumn step should be performed.
void perform_round(unsigned char* block, unsigned char* key, bool last_round)
{
    sub_bytes(block, SBox, BLOCK_SIZE);
    shift_rows(block);
    if (!last_round) {
        mix_columns(block);
    }
    xor_blocks(block, key, BLOCK_SIZE);
}

/// Encrypt a block with a 128-bit key, and a certain number of rounds.
unsigned char* encrypt(const unsigned char* block, const unsigned char* key, size_t rounds) {
    unsigned char* data = malloc(BLOCK_SIZE); // create block on heap so that it can be returned later
    memcpy(data, block, BLOCK_SIZE);

    unsigned char round_key[BLOCK_SIZE];
    memcpy(round_key, key, BLOCK_SIZE);

#ifdef DEBUG_AES
    print_with_msg(data, format_str("Starting AES encryption with %d rounds and input data:", rounds));
    print_with_msg(round_key, "And encryption key:");
#endif

    xor_blocks(data, round_key, BLOCK_SIZE); // initial XOR with key
    derive_next_key(round_key, 0);

#ifdef DEBUG_AES
    print_with_msg(data, "After initial XOR:");
    print_with_msg(round_key, "Derived key for next round:");
#endif

    for (int r = 1; r <= rounds; r++) {
        if (r != rounds) {
            perform_round(data, round_key, false);
            derive_next_key(round_key, r);

#ifdef DEBUG_AES
            print_with_msg(data, format_str("After performing round %d:", r));
            print_with_msg(round_key, "Derived key for next round:");
#endif
        } else {
            perform_round(data, round_key, true);
        }
    }

#ifdef DEBUG_AES
    print_with_msg(data, "Completed encryption with result:");
#endif

    return data;
}