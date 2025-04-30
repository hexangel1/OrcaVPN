#ifndef LOGGER_H_SENTRY
#define LOGGER_H_SENTRY

#include <syslog.h>

#define LOG_NO_DATETIME 0
#define LOG_UTC_DATETIME 1
#define LOG_LOCAL_DATETIME 2

#define LOG_FILE_SIZE_LIMIT 2147483648UL /* 2 GB */

/* Init logger module */
void init_logger(const char *service, const char *filename,
	int syslog_on, int time_on);

/* Write log formatted message */
void log_mesg(int level, const char *mesg, ...);
/* Write log message with errno string value */
void log_perror(const char *mesg);

/* Reopen logfile */
void log_rotate(void);

#endif /* LOGGER_H_SENTRY */
