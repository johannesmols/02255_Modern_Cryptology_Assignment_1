#ifndef INC_02255_HW1_GROUP33_HELPERS_H
#define INC_02255_HW1_GROUP33_HELPERS_H

#include <stddef.h>

extern const size_t BLOCK_SIZE;

char* format_str(char* format, size_t param);
void print(const unsigned char* block);
void print_with_msg(const unsigned char* block, const char* msg);

void swap_values(unsigned char* block, int i1, int i2);

#endif //INC_02255_HW1_GROUP33_HELPERS_H
