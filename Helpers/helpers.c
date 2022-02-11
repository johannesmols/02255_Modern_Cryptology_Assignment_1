#include <malloc.h>
#include <stdio.h>
#include <string.h>

#include "helpers.h"

const size_t BLOCK_SIZE = 16;

/// Reads a 32-char long hex string into a 4x4 block, reading row by row (not column by column!)
unsigned char* block_from_string(const char* string) {
    unsigned char* block = malloc(BLOCK_SIZE);
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        char sub_string[2], *ptr = sub_string;
        memcpy(sub_string, &string[i * 2], 2);
        sscanf(ptr, "%2hhx", &block[i]);
    }

    return block;
}

/// Helper function to create a string with a single parameter in it.
/// Source: https://stackoverflow.com/a/5172154/2102106
char* format_str(char* format, size_t param) {
    char* buf = malloc(256);
    snprintf(buf, 256, format, param);
    return buf;
}

/// Print the block in a 4x4 matrix to stdout.
void print(const unsigned char* block) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        printf("%02x", block[i]);
        if ((i + 1) % 4 == 0) {
            printf("\n");
        } else {
            printf(" ");
        }
    }
    printf("\n");
}

/// Shortcut function to print a block with a message on the line before.
void print_with_msg(const unsigned char* block, const char* msg) {
    printf("%s\n", msg);
    print(block);
}

/// Swap two values in an a block, with the given indices i1 and i2.
void swap_values(unsigned char* block, int i1, int i2) {
    unsigned char tmp = block[i1];
    block[i1] = block[i2];
    block[i2] = tmp;
}
