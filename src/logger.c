#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>

#include "logger.h"

static struct logger_config {
	FILE *log_file;
	const char *log_file_path;
	int enable_syslog;
	int enable_time;
} logger;

static const char *get_timestamp(int local)
{
	static char buffer[64];
	struct tm *now_tm;
	time_t now;

	now = time(NULL);
	now_tm = local ? localtime(&now) : gmtime(&now);
	strftime(buffer, sizeof(buffer), "%d %b %H:%M:%S ", now_tm);
	return buffer;
}

static const char *get_prio_level_name(enum log_mesg_prio_level level)
{
	switch (level) {
	case log_lvl_debug:
		return "debug";
	case log_lvl_info:
		return "info";
	case log_lvl_normal:
		return "notice";
	case log_lvl_warn:
		return "warn";
	case log_lvl_err:
		return "err";
	case log_lvl_fatal:
		return "emerg";
	}
	return "unknown";
}

static int prio_level_to_sys(enum log_mesg_prio_level level)
{
	switch (level) {
	case log_lvl_debug:
		return LOG_DEBUG;
	case log_lvl_info:
		return LOG_INFO;
	case log_lvl_normal:
		return LOG_NOTICE;
	case log_lvl_warn:
		return LOG_WARNING;
	case log_lvl_err:
		return LOG_ERR;
	case log_lvl_fatal:
		return LOG_EMERG;
	}
	return -1;
}

static void open_logfile(void)
{
	logger.log_file = fopen(logger.log_file_path, "a");
	if (!logger.log_file) {
		perror(logger.log_file_path);
		exit(EXIT_FAILURE);
	}
	setbuf(logger.log_file, NULL);
}

static void close_logfile(void)
{
	if (!logger.log_file)
		return;
	fflush(logger.log_file);
	fclose(logger.log_file);
	logger.log_file = NULL;
}

static void limit_filesize(size_t max_size)
{
	struct rlimit rlim;
	if (getrlimit(RLIMIT_FSIZE, &rlim) < 0)
		return;
	if (rlim.rlim_max == RLIM_INFINITY || rlim.rlim_max > max_size) {
		rlim.rlim_cur = max_size;
		setrlimit(RLIMIT_FSIZE, &rlim);
	}
}

void init_logger(const char *service, const char *filename,
	int syslog_on, int time_on)
{
	logger.log_file_path = filename;
	logger.enable_syslog = syslog_on;
	logger.enable_time = time_on;

	if (logger.log_file_path) {
		open_logfile();
		atexit(close_logfile);
		limit_filesize(LOG_FILE_SIZE_LIMIT);
	} else {
		logger.log_file = stderr;
	}
	if (logger.enable_syslog) {
		int logmask = setlogmask(0);
		logmask &= ~(LOG_MASK(LOG_NOTICE) | LOG_MASK(LOG_DEBUG));
		setlogmask(logmask);
		openlog(service, LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
		atexit(closelog);
	}
}

void log_mesg(int level, const char *mesg, ...)
{
	const char *prioname, *ts = "";
	char buffer[1024];
	int len;
	va_list args;

	va_start(args, mesg);
	len = vsnprintf(buffer, sizeof(buffer), mesg, args);
	va_end(args);
	if (len < 0 || (size_t)len > sizeof(buffer)-1)
		return;

	if (logger.enable_time != LOG_NO_DATETIME)
		ts = get_timestamp(logger.enable_time == LOG_LOCAL_DATETIME);
	prioname = get_prio_level_name(level);
	fprintf(logger.log_file, "%s[%s] %s\n", ts, prioname, buffer);
	if (logger.enable_syslog)
		syslog(prio_level_to_sys(level), "%s", buffer);
}

void log_perror(const char *mesg)
{
	int save_errno = errno;
	const char *err = strerror(errno);

	if (!err)
		err = "unknown error occurred";
	log_mesg(log_lvl_err, "%s: %s", mesg, err);
	errno = save_errno;
}

void log_rotate(void)
{
	if (!logger.log_file_path)
		return;
	close_logfile();
	open_logfile();
}
