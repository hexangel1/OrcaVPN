#ifndef GFMULT_H_SENTRY
#define GFMULT_H_SENTRY

#include <stdint.h>

extern const uint8_t gfmult_aes[];

#define gfmult(a, b) (gfmult_aes[256*(a) + (b)])

#endif /* GFMULT_H_SENTRY */
