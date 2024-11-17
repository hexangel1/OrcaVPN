#ifndef CONFIGPARSER_H_SENTRY
#define CONFIGPARSER_H_SENTRY

#include <stddef.h>

struct config_section {
	char *scope;
	char **keys;
	char **vals;
	size_t vars_count;
	size_t vars_alloc;
	struct config_section *next;
};

struct config_section *read_config(const char *file);

void free_config(struct config_section *cfg);

void debug_config(struct config_section *cfg);

const char *get_var_value(struct config_section *cfg, const char *var);

const char *get_str_var(struct config_section *cfg, const char *var, int len);

int get_int_var(struct config_section *cfg, const char *var);

#endif /* CONFIGPARSER_H_SENTRY */
