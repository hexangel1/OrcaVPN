#define _POSIX_C_SOURCE 200112L
#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#include "helper.h"

/* reserve descriptors range for polling with select */
#define CLOSE_FD_GAP 16

static int create_pidfile(const char *pidfile)
{
	char pid_str[16];
	int pid_fd, len, res;

	if (!pidfile)
		return 0;
	pid_fd = open(pidfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (pid_fd < 0)
		return -1;
	len = snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
	res = write(pid_fd, pid_str, len);
	close(pid_fd);
	if (res != len)
		return -1;
	return 0;
}

static void do_fork(void)
{
	pid_t pid = fork();
	if (pid < 0)
		_exit(1); /* fork error */
	if (pid > 0)
		_exit(0); /* parent exit */
	/* child return */
}

void daemonize(const char *pidfile)
{
	int fd;
	for (fd = 0; fd < CLOSE_FD_GAP; fd++)
		close(fd);
	fd = open("/dev/null", O_RDWR);
	if (fd != 0)
		_exit(1);
	dup2(0, 1);
	dup2(0, 2);
	umask(022);
	if (chdir("/") < 0)
		_exit(1);
	do_fork();
	setsid();
	do_fork();
	create_pidfile(pidfile);
}

time_t get_unix_time(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec;
}

char *hexlify(const void *bin, size_t len, int upper, char *res)
{
	const char *xdigits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	const unsigned char *bytes = bin;
	size_t i;

	for (i = 0; i < len; ++i) {
		res[i * 2]     = xdigits[bytes[i] >> 4];
		res[i * 2 + 1] = xdigits[bytes[i] & 0x0f];
	}
	res[len * 2] = 0;
	return res;
}

void *binarize(const char *hex, size_t len, void *res)
{
	unsigned char *bytes = res;
	size_t i;

	if (len % 2)
		return NULL;

	for (i = 0; i < len / 2; ++i) {
		if (!IS_XDIGIT(hex[2 * i]) || !IS_XDIGIT(hex[2 * i + 1]))
			return NULL;
		bytes[i] = (XDIGIT(hex[2 * i]) << 4) | (XDIGIT(hex[2 * i + 1]));
	}
	return bytes;
}
