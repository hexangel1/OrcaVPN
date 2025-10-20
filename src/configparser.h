#ifndef CONFIGPARSER_H_SENTRY
#define CONFIGPARSER_H_SENTRY

struct config_section {
	char *scope;
	char **keys;
	char **vals;
	int vars_count;
	int vars_alloc;
	struct config_section *next;
};

/* Read config file and parse key-value pair section list */
struct config_section *read_config(const char *file);
/* Free config key-value pair section list */
void free_config(struct config_section *cfg);

/* Get raw value by key from section */
const char *get_var_value(struct config_section *cfg, const char *var);
/* Get string value by key from section */
const char *get_str_var(struct config_section *cfg, const char *var, int max);
/* Get integer value by key from section */
int get_int_var(struct config_section *cfg, const char *var);
/* Get boolean value by key from section */
int get_bool_var(struct config_section *cfg, const char *var);

#endif /* CONFIGPARSER_H_SENTRY */
