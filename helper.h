#ifndef HELPER_H_SENTRY
#define HELPER_H_SENTRY

#include <stdlib.h>

void daemonize(const char *service);

char *hexlify(const void *data, size_t len, int upper, char *out);

#endif /* HELPER_H_SENTRY */
