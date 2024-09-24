#ifndef LOGGER_H_SENTRY
#define LOGGER_H_SENTRY

#include <syslog.h>

#define LOG_NO_DATETIME 0
#define LOG_UTC_DATETIME 1
#define LOG_LOCAL_DATETIME 2

#define LOG_FILE_SIZE_LIMIT 1048576UL /* 1 GB */

void init_logger(const char *service, const char *filename,
	int syslog_on, int time_on);

void log_mesg(int level, const char *msg, ...);

void log_perror(const char *msg);

#endif /* LOGGER_H_SENTRY */
