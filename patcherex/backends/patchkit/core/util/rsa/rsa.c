typedef uint32_t bignum_word_t;

#define BIGNUM_WORD_BITS (sizeof(bignum_word_t) * 8)
#define BIGNUM_MAX_BITS 1056
#define BIGNUM_NBYTES (BIGNUM_MAX_BITS / 8)
#define BIGNUM_NWORDS (BIGNUM_NBYTES / sizeof(bignum_word_t))

static inline void* _memcpy (void *dest, const void *src, size_t len)
{
  char *d = dest;
  const char *s = src;
  while (len--)
    *d++ = *s++;
  return dest;
}

static inline void *
_memset (void *dest, int val, size_t len)
{
  unsigned char *ptr = dest;
  while (len-- > 0)
    *ptr++ = val;
  return dest;
}

static inline uint32_t bt(void *base, uint32_t offset) {
    uint32_t idx1 = offset >> 3;
    uint32_t idx2 = offset & 7;
    uint32_t v;
    v = ((uint8_t *)base)[idx1];
    v = v >> idx2;
    v &= 1;
    return v;
}

void add(bignum_word_t *edi, bignum_word_t *esi) {
    bignum_word_t v, tmp;
    bignum_word_t carry = 0;
    for (bignum_word_t i = 0; i < BIGNUM_NWORDS; i++) {
        tmp = edi[i] + carry;
        v = esi[i] + tmp;
        carry = (esi[i] > v) | (edi[i] > tmp);
        edi[i] = v;
    }
}

static inline bignum_word_t sub(bignum_word_t *edi, bignum_word_t *esi) {
    bignum_word_t v, tmp;
    bignum_word_t borrow = 0;
    for(bignum_word_t i = 0; i < BIGNUM_NWORDS; i++) {
        tmp = edi[i] - borrow;
        v = tmp - esi[i];
        borrow = (tmp > edi[i]) | (v > tmp);
        edi[i] = v;
    }
    return borrow;
}

void modadd(bignum_word_t *edi, bignum_word_t *esi, bignum_word_t *n) {
    add(edi, esi);
    while (!sub(edi, n));
    add(edi, n);
}

void modmul(bignum_word_t *src, bignum_word_t *a, bignum_word_t *b, bignum_word_t *n) {
    bignum_word_t c[BIGNUM_NWORDS];
    bignum_word_t bit_offset = 0;

    _memset(a, 0, BIGNUM_NBYTES);
    _memcpy(c, src, BIGNUM_NBYTES);

    do {
        if (bt(b, bit_offset)) {
            modadd(a, c, n);
        }
        modadd(c, c, n);
        bit_offset++;
    } while(bit_offset >> 3 != BIGNUM_NBYTES);
}

void rsaenc(bignum_word_t final[], bignum_word_t m[], bignum_word_t n[]) {
    bignum_word_t tmp[BIGNUM_NWORDS];
    m[(1024 / 8 / sizeof(bignum_word_t)) - 1] = 0x1;
    modmul(m, tmp, m, n);
    modmul(tmp, final, m, n);
}
