#ifndef ENDIANESS_H_SENTRY
#define ENDIANESS_H_SENTRY

#include "fwi_types.h"

#if __STDC_VERSION__ >= 199901L
/* inline keyword is present */
#elif defined(__GNUC__)
/* inline keyword as compiler extention */
#define inline __inline__
#else
/* simply ignore it */
#define inline
#endif

static inline u32 load32_be(const u8 s[4])
{
	return
		((u32)s[0] << 24) |
		((u32)s[1] << 16) |
		((u32)s[2] <<  8) |
		((u32)s[3] <<  0);
}

static inline u32 load32_le(const u8 s[4])
{
	return
		((u32)s[0] <<  0) |
		((u32)s[1] <<  8) |
		((u32)s[2] << 16) |
		((u32)s[3] << 24);
}

static inline u64 load64_le(const u8 s[8])
{
	return load32_le(s) | ((u64)load32_le(s + 4) << 32);
}

static inline void store32_be(u8 out[4], u32 in)
{
	out[0] = (in >> 24) & 0xff;
	out[1] = (in >> 16) & 0xff;
	out[2] = (in >>  8) & 0xff;
	out[3] = (in >>  0) & 0xff;
}

static inline void store32_le(u8 out[4], u32 in)
{
	out[0] = (in      ) & 0xff;
	out[1] = (in >>  8) & 0xff;
	out[2] = (in >> 16) & 0xff;
	out[3] = (in >> 24) & 0xff;
}

static inline void store64_le(u8 out[8], u64 in)
{
	store32_le(out    , (u32)in );
	store32_le(out + 4, in >> 32);
}

static inline void load32_le_buf(u32 *dst, const u8 *src, size_t size)
{
	size_t i;
	for (i = 0; i < size; i++)
		dst[i] = load32_le(src + i * 4);
}

static inline void store32_le_buf(u8 *dst, const u32 *src, size_t size)
{
	size_t i;
	for (i = 0; i < size; i++)
		store32_le(dst + i * 4, src[i]);
}

#undef inline

#endif /* ENDIANESS_H_SENTRY */
