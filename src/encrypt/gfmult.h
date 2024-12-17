#ifndef GFMULT_H_SENTRY
#define GFMULT_H_SENTRY

#include <stdint.h>

extern const uint8_t gfmult_lookup[7][256];

#define gfmult(a, b) (gfmult_lookup[(a)][(b)])

#define gfmult_vec0(x0, x1, x2, x3, y0, y1, y2, y3) \
	gfmult(x0, y0) ^ gfmult(x3, y1) ^ gfmult(x2, y2) ^ gfmult(x1, y3);

#define gfmult_vec1(x0, x1, x2, x3, y0, y1, y2, y3) \
	gfmult(x1, y0) ^ gfmult(x0, y1) ^ gfmult(x3, y2) ^ gfmult(x2, y3);

#define gfmult_vec2(x0, x1, x2, x3, y0, y1, y2, y3) \
	gfmult(x2, y0) ^ gfmult(x1, y1) ^ gfmult(x0, y2) ^ gfmult(x3, y3);

#define gfmult_vec3(x0, x1, x2, x3, y0, y1, y2, y3) \
	gfmult(x3, y0) ^ gfmult(x2, y1) ^ gfmult(x1, y2) ^ gfmult(x0, y3);

#define coef_mult0(x0, x1, x2, x3, v) \
	gfmult_vec0(x0, x1, x2, x3, v[0], v[1], v[2], v[3])
#define coef_mult1(x0, x1, x2, x3, v) \
	gfmult_vec1(x0, x1, x2, x3, v[0], v[1], v[2], v[3])
#define coef_mult2(x0, x1, x2, x3, v) \
	gfmult_vec2(x0, x1, x2, x3, v[0], v[1], v[2], v[3])
#define coef_mult3(x0, x1, x2, x3, v) \
	gfmult_vec3(x0, x1, x2, x3, v[0], v[1], v[2], v[3])

#endif /* GFMULT_H_SENTRY */
