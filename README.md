# Square Attack on AES-128

This is a simple implementation of the Square Attack on AES-128, including a custom implementation of AES-128.

## Running the code

Compile it using the CMake file, or use the provided .exe directly.

The program takes an optional parameter to define the cipher key used for encryption and recovery. This key has to be a 128-bit hex string (32 characters). If no parameter is provided, a default key is used. N.b. that the key is parsed in horizontal order, not vertical. 

The results of the attack, including some intermediate steps, are printed to stdout.