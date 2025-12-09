#ifndef LOGGER_H_SENTRY
#define LOGGER_H_SENTRY

#define LOG_NO_DATETIME 0
#define LOG_UTC_DATETIME 1
#define LOG_LOCAL_DATETIME 2

enum log_mesg_prio_level {
	log_lvl_debug,
	log_lvl_info,
	log_lvl_normal,
	log_lvl_warn,
	log_lvl_err,
	log_lvl_fatal
};

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
