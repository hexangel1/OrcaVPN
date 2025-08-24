#ifndef MEMZERO_H_SENTRY
#define MEMZERO_H_SENTRY

#include <stddef.h>

static void secure_memzero(void *mem, size_t size)
{
#if PARANOIC_MODE == 1
	volatile char *v_mem = (volatile char *)mem;
	size_t i;
	for (i = 0; i < size; i++)
		v_mem[i] = 0;
#else
	/* suppress unused parameter compiler warning */
	(void)mem;
	(void)size;
#endif
}

#endif /* MEMZERO_H_SENTRY */
