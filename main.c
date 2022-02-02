#include <stdio.h>

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

#pragma endregion Printing

#pragma region Array operations

void sub_bytes(unsigned char* arr, const unsigned char* s_box) {
    for (int i = 0; i < 16; i++) {
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

#pragma endregion array operations

int main()
{
    unsigned char test_sub_1[] = {0x19, 0xa0, 0x9a, 0xe9,
                                  0x3d, 0xf4, 0xc6, 0xf8,
                                  0xe3, 0xe2, 0x8d, 0x48,
                                  0xbe, 0x2b, 0x2a, 0x08};

    printf("Original:\n");
    print_box(test_sub_1);

    sub_bytes(test_sub_1, SBox);
    printf("After SubBytes:\n");
    print_box(test_sub_1);

    /*sub_bytes(test_sub_1, InverseSBox);
    printf("After Inverse SubBytes:\n");
    print_box(test_sub_1);*/

    printf("After Shift Rows:\n");
    shift_rows(test_sub_1);
    print_box(test_sub_1);

    return 0;
}