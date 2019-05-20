#ifndef BASE58_H
#define BASE58_H

#include <stddef.h>

int b58tobin(void *bin, size_t *binszp, const char *b58, size_t b58sz);
int b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz);

#endif
