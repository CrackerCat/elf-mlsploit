#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include "key.c"

// TODO: Make patchkit to get header files from code.
// This is hot fix to support both assembly + c code level implementation.
#ifdef CONFIG_C_TEST

#include "rsa.c"

#else

typedef uint32_t bignum_word_t;

#define BIGNUM_WORD_BITS (sizeof(bignum_word_t) * 8)
#define BIGNUM_MAX_BITS 1056
#define BIGNUM_NBYTES (BIGNUM_MAX_BITS / 8)
#define BIGNUM_NWORDS (BIGNUM_NBYTES / sizeof(bignum_word_t))

#endif

bignum_word_t in[BIGNUM_NWORDS] = {0}, out[BIGNUM_NWORDS] = {0};

const char* MSG = "Hello World";

int main(int argc, char** argv)
{
  strcpy((uint8_t*)in, MSG);
  rsaenc(out, in, (bignum_word_t*)n); // Encryption
  write(1, out, sizeof(out));
}
