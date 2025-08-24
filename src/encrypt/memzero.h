#ifndef MEMZERO_H_SENTRY
#define MEMZERO_H_SENTRY

#include <stddef.h>

#define WIPE_BUFFER(buffer) secure_memzero(buffer, sizeof(buffer))

static void secure_memzero(void *mem, size_t size)
{
	volatile char *v_mem = (volatile char *)mem;
	size_t i;
	for (i = 0; i < size; i++)
		v_mem[i] = 0;
}

#endif /* MEMZERO_H_SENTRY */
