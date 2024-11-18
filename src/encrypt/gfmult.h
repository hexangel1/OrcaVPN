#ifndef GFMULT_H_SENTRY
#define GFMULT_H_SENTRY

#include <stdint.h>

extern const uint8_t gfmult_lookup[7][256];

#define gfmult(a, b) (gfmult_lookup[(a)][(b)])

#endif /* GFMULT_H_SENTRY */
