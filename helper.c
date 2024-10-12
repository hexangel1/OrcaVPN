#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>

#include "helper.h"

int snprintf(char *str, size_t size, const char *format, ...);

static int create_pidfile(const char *pidfile)
{
	char pid_str[16];
	int pid_fd, len, res;
	if (!pidfile)
		return 0;
	pid_fd = creat(pidfile, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
	if (pid_fd == -1)
		return -1;
	len = snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
	res = write(pid_fd, pid_str, len);
	close(pid_fd);
	if (res != len)
		return -1;
	return 0;
}

void daemonize(const char *pidfile)
{
	int fd;
	for (fd = 0; fd < 1024; ++fd)
		close(fd);
	open("/dev/null", O_RDWR);
	dup2(0, 1);
	dup2(0, 2);
	umask(022);
	if (chdir("/") < 0)
		exit(1);
	if (fork() > 0)
		exit(0);
	setsid();
	if (fork() > 0)
		exit(0);
	create_pidfile(pidfile);
}

char *hexlify(const void *bin, size_t len, int upper, char *res)
{
	const char *hex_digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	const unsigned char *bytes = bin;
	size_t i;
	for (i = 0; i < len; ++i) {
		res[i * 2]     = hex_digits[bytes[i] >> 4];
		res[i * 2 + 1] = hex_digits[bytes[i] & 0x0F];
	}
	return res;
}

void *binarize(const char *hex, size_t len, void *res)
{
	size_t i;
	unsigned char *bytes = res;
	for (i = 0; i < len / 2; ++i) {
		if (!isxdigit(hex[2 * i]) || !isxdigit(hex[2 * i + 1]))
			return NULL;
		bytes[i] = (XDIGIT(hex[2 * i]) << 4) | (XDIGIT(hex[2 * i + 1]));
	}
	return bytes;
}
