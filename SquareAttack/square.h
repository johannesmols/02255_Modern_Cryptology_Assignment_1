#ifndef INC_02255_HW1_GROUP33_SQUARE_H
#define INC_02255_HW1_GROUP33_SQUARE_H

//#define DEBUG_SQUARE // comment this out to disable debug mode

extern const size_t SETS;

unsigned char** generate_lambda_set();
unsigned char*** generate_lambda_sets(size_t n);

unsigned char reverse_last_round(const unsigned char* block, unsigned char key, size_t key_pos);
unsigned char* guess_round_key(unsigned char** lambda, size_t key_pos, size_t* no_of_guesses);

#endif //INC_02255_HW1_GROUP33_SQUARE_H
