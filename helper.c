#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "helper.h"

void daemonize(const char *service)
{
	int fd;
	for (fd = 0; fd < 1024; ++fd)
		close(fd);
	open("/dev/null", O_RDWR);
	dup2(0, 1);
	dup2(0, 2);
	umask(0);
	if (chdir("/") < 0)
		exit(1);
	if (fork() > 0)
		exit(0);
	setsid();
	if (fork() > 0)
		exit(0);
	openlog(service, LOG_CONS | LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, "Daemon started, pid == %d", getpid());
	atexit(&closelog);
}

char *hexlify(const void *data, size_t len, int upper, char *res)
{
	const char *hex_digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	const unsigned char *bytes = data;
	size_t i;
	for (i = 0; i < len; ++i) {
		res[i * 2]     = hex_digits[bytes[i] >> 4];
		res[i * 2 + 1] = hex_digits[bytes[i] & 0x0F];
	}
	return res;
}

uint8_t *to_big_endian32(const uint8_t *block, size_t size, uint8_t *res)
{
	size_t i;
	for (i = 0; i < size; i += 4) {
		uint8_t byte0 = block[i];
		uint8_t byte1 = block[i + 1];
		res[i]     = block[i + 3];
		res[i + 1] = block[i + 2];
		res[i + 2] = byte1;
		res[i + 3] = byte0;
	}
	return res;
}
