#ifndef INC_02255_HW1_GROUP33_AES_H
#define INC_02255_HW1_GROUP33_AES_H

#include <stddef.h>
#include <stdbool.h>

#define DEBUG // comment this out to disable debug mode

extern const size_t BLOCK_SIZE;

void print(const unsigned char* block);
void print_with_msg(const unsigned char* block, const char* msg);

void swap_values(unsigned char* block, int i1, int i2);

void xor_blocks(unsigned char* a, const unsigned char* b, size_t n);
void sub_bytes(unsigned char* block, const unsigned char* s_box, size_t n);
void shift_rows(unsigned char* block);
void mix_columns(unsigned char* block);

void derive_next_key(unsigned char* key, size_t round);
void perform_round(unsigned char* block, unsigned char* key, bool last_round);

unsigned char* encrypt(const unsigned char* block, const unsigned char* key, size_t rounds);

#endif //INC_02255_HW1_GROUP33_AES_H
