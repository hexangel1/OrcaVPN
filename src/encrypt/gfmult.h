#ifndef GFMULT_H_SENTRY
#define GFMULT_H_SENTRY

#include <stdint.h>

extern const uint8_t gfmult_lookup[65536];

#define gfmult(a, b) (gfmult_lookup[((a) << 8) | (b)])

#endif /* GFMULT_H_SENTRY */
