cmake_minimum_required(VERSION 3.19)
project(02255_HW1_Group33 C)

set(CMAKE_C_STANDARD 17)

add_executable(02255_HW1_Group33 main.c AES/constants.h AES/constants.c Helpers/helpers.h Helpers/helpers.c Helpers/set.h Helpers/set.c AES/aes.h AES/aes.c SquareAttack/square.h SquareAttack/square.c)