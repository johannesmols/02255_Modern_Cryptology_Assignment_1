#include <stdio.h>

#include "aes_s_boxes.c"

void print_box(const unsigned char box[]) {
    for (int i = 0; i < 16; i++) {
        printf("%x", box[i]);
        if ((i + 1) % 4 == 0) {
            printf("\n");
        } else {
            printf(" ");
        }
    }
    printf("\n");
}

void sub_bytes(unsigned char v[], const unsigned char s_box[]) {
    for (int i = 0; i < 16; i++) {
        v[i] = s_box[v[i]];
    }
}

int main()
{
    unsigned char test_sub_1[] = {0x19, 0xa0, 0x9a, 0xe9,
                                  0x3d, 0xf4, 0xc6, 0xf8,
                                  0xe3, 0xe2, 0x8d, 0x48,
                                  0xbe, 0x2b, 0x2a, 0x08};
    print_box(test_sub_1);
    sub_bytes(test_sub_1, SBox);
    print_box(test_sub_1);

    return 0;
}