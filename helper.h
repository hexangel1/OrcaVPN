#ifndef HELPER_H_SENTRY
#define HELPER_H_SENTRY

#include <stdlib.h>
#include <stdint.h>

void daemonize(const char *service);

char *hexlify(const void *data, size_t len, int upper, char *out);

uint8_t *to_big_endian32(const uint8_t *block, size_t size, uint8_t *res);

#endif /* HELPER_H_SENTRY */
