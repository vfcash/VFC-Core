gcc -std=gnu99 -Ofast -mrdseed -pthread base58.c crc64.c ecc.c sha3.c main.c -lm -o bin/vfc
