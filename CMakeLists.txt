cmake_minimum_required(VERSION 3.19)
project(02255_HW1_Group33 C)

set(CMAKE_C_STANDARD 17)

add_executable(02255_HW1_Group33 main.c AES/aes.h AES/aes.c AES/constants.h SquareAttack/square.c SquareAttack/square.h Helpers/helpers.c Helpers/helpers.h)