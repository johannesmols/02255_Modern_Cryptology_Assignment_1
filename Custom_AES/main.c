#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <malloc.h>

#include "constants.c"

#pragma region Printing

void print_box(const unsigned char* box) {
    for (int i = 0; i < 16; i++) {
        printf("%02x", box[i]);
        if ((i + 1) % 4 == 0) {
            printf("\n");
        } else {
            printf(" ");
        }
    }
    printf("\n");
}

void print_with_msg(const unsigned char* box, const char* msg) {
    printf("%s\n", msg);
    print_box(box);
}

#pragma endregion

#pragma region Array operations

void apply_xor(unsigned char* a, const unsigned char* b, size_t n) {
    for (int i = 0; i < n; i++) {
        a[i] ^= b[i];
    }
}

void sub_bytes(unsigned char* arr, const unsigned char* s_box, size_t n) {
    for (int i = 0; i < n; i++) {
        arr[i] = s_box[arr[i]];
    }
}

void swap(unsigned char* arr, int i1, int i2) {
    unsigned char tmp = arr[i1];
    arr[i1] = arr[i2];
    arr[i2] = tmp;
}

void shift_left(unsigned char* arr, int start, int end, int n) {
    for (int iter = 0; iter < n; iter++) {
        unsigned char first = arr[start];
        for (int i = start; i < end; i++) {
            swap(arr, i, i + 1);
        }
        arr[end] = first;
    }
}

void shift_rows(unsigned char* arr) {
    for (int r = 0; r < 4; r++) {
        shift_left(arr, r * 4, r * 4 + 3, r);
    }
}

void mix_columns(unsigned char* arr) {
    for (int c = 0; c < 4; c++) {
        unsigned char col[] = {arr[c], arr[c+4], arr[c+8], arr[c+12]};
        arr[c] = MultiplyBy2[col[0]] ^ MultiplyBy3[col[1]] ^ col[2] ^ col[3];
        arr[c + 4] = col[0] ^ MultiplyBy2[col[1]] ^ MultiplyBy3[col[2]] ^ col[3];
        arr[c + 8] = col[0] ^ col[1] ^ MultiplyBy2[col[2]] ^ MultiplyBy3[col[3]];
        arr[c + 12] = MultiplyBy3[col[0]] ^ col[1] ^ col[2] ^ MultiplyBy2[col[3]];
    }
}

/// Rotate a 4x4 matrix 90 degrees to the left or right
unsigned char* rotate(const unsigned char* arr, bool left) {
    unsigned char* rot = malloc(16);
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            // calculates where the value for the current index is stored, depending on the direction to rotate to
            rot[c + (4 * r)] = arr[left
                                   ? (3 - r) + (4 * c)
                                   : (3 - c) * 4 + r];
        }
    }
    return rot;
}

#pragma endregion

#pragma region Key scheduling operations

/// Derive the next key from the current round key and round number.
/// To make it easier to work with columns, the matrix is rotated left before processing, and rotated back afterwards.
unsigned char* derive_next_key(unsigned char* key, size_t round) {
    // Rotate matrix to the left to make it easier to work with. Row order is now reversed (last is 1st, first is last)
    unsigned char* rot = rotate(key, true);

    unsigned char orig_last_row[4];
    memcpy(orig_last_row, &rot[0], 4); // Copy last row for later user before modifying it

    shift_left(rot, 0, 3, 1); // Shift the last row one to the left
    sub_bytes(&rot[0], SBox, 4); // Substitute bytes on last row using the S-Box
    rot[0] ^= RoundConstants[round]; // Add round constant to 1st byte of last row

    apply_xor(&rot[12], &rot[0], 4); // XOR above derived word with first row
    apply_xor(&rot[8], &rot[12], 4); // XOR new first row with second row
    apply_xor(&rot[4], &rot[8], 4); // XOR new second row with third row

    unsigned char third_row[4];
    memcpy(third_row, &rot[4], 4);
    apply_xor(third_row, orig_last_row, 4); // XOR new third row with original last row
    for (int i = 0; i < 4; i++) {
        rot[i] = third_row[i]; // replace values
    }

    return rotate(rot, false);
}

#pragma endregion

#pragma AES operations

void perform_round(unsigned char* arr, unsigned char* round_key, bool last_round)
{
    sub_bytes(arr, SBox, 16);
    shift_rows(arr);
    if (!last_round) {
        mix_columns(arr);
    }
    apply_xor(arr, round_key, 16);
}

#pragma endregion

void test()
{
    unsigned char input[] = {0x32, 0x88, 0x31, 0xe0,
                             0x43, 0x5a, 0x31, 0x37,
                             0xf6, 0x30, 0x98, 0x07,
                             0xa8, 0x8d, 0xa2, 0x34};

    unsigned char cipher_key[] = {0x2b, 0x28, 0xab, 0x09,
                                  0x7e, 0xae, 0xf7, 0xcf,
                                  0x15, 0xd2, 0x15, 0x4f,
                                  0x16, 0xa6, 0x88, 0x3c};

    print_with_msg(input, "Before applying 1st round key:");
    apply_xor(input, cipher_key, 16);
    print_with_msg(input, "After applying 1st round key:");

    unsigned char* derived = derive_next_key(cipher_key, 0);
    print_with_msg(derived, "Next round key:");

    perform_round(input, derived, false);
    print_with_msg(input, "After performing 2nd round:");
}

int main()
{
    test();
    return 0;
}