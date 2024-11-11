#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>

#include "configparser.h"
#include "logger.h"

static char *extract_str(const char *begin, const char *end)
{
	size_t length = end - begin + 1;
	char *str;

	str = malloc(length + 1);
	memcpy(str, begin, length);
	str[length] = 0;
	return str;
}

#define CONFIG_ERROR(message) \
	do { \
		free_config(head); \
		if (fp) \
			fclose(fp); \
		log_mesg(LOG_ERR, "Read config failed: " message); \
		return NULL; \
	} while (0)

struct config_section *read_config(const char *file)
{
	char buffer[256];
	char *k_begin, *k_end, *v_begin, *v_end, *ptr;
	struct config_section *section = NULL, *head = NULL, **next = &head;

	FILE *fp = fopen(file, "r");
	if (!fp) {
		log_perror(file);
		CONFIG_ERROR("file not opened");
	}
	while (fgets(buffer, sizeof(buffer), fp)) {
		if (buffer[0] == '[') {
			ptr = strchr(buffer, ']');
			if (!ptr)
				CONFIG_ERROR("expected ']', end of line found");
			section = malloc(sizeof(struct config_section));
			memset(section, 0, sizeof(struct config_section));
			section->section_name = extract_str(buffer + 1, ptr - 1);
			*next = section;
			next = &section->next;
			continue;
		}
		if (!section)
			CONFIG_ERROR("expected '[', variable found");

		for (k_begin = buffer; isspace(*k_begin); k_begin++);
		if (!*k_begin) /* blank line */
			continue;
		k_end = strchr(k_begin, '=');
		if (!k_end)
			CONFIG_ERROR("expected '=', end of line found");

		for (v_begin = k_end + 1; isspace(*v_begin); v_begin++);
		v_end = strchr(v_begin, '\n');
		if (!v_end)
			CONFIG_ERROR("expected newline marker, end of line found");

		for (k_end--; isspace(*k_end); k_end--);
		for (v_end--; isspace(*v_end); v_end--);

		if (section->vars_count == section->vars_alloc) {
			size_t new_size;
			section->vars_alloc += 8;
			new_size = section->vars_alloc * sizeof(char *);
			section->keys = realloc(section->keys, new_size);
			section->vals = realloc(section->vals, new_size);
		}
		section->keys[section->vars_count] = extract_str(k_begin, k_end);
		section->vals[section->vars_count] = extract_str(v_begin, v_end);
		section->vars_count++;
	}
	fclose(fp);
	return head;
}

void free_config(struct config_section *cfg)
{
	size_t i;
	struct config_section *tmp;

	while (cfg) {
		tmp = cfg;
		cfg = cfg->next;
		free(tmp->section_name);
		for (i = 0; i < tmp->vars_count; i++) {
			free(tmp->keys[i]);
			free(tmp->vals[i]);
		}
		free(tmp->keys);
		free(tmp->vals);
		free(tmp);
	}
}

void debug_config(struct config_section *cfg)
{
	size_t i;
	struct config_section *tmp;

	for (tmp = cfg; tmp; tmp = tmp->next) {
		fprintf(stderr, "[%s]\n", tmp->section_name);
		for (i = 0; i < tmp->vars_count; i++) {
			fprintf(stderr, "%s = %s\n", tmp->keys[i], tmp->vals[i]);
		}
	}
}

const char *get_var_value(struct config_section *cfg, const char *var)
{
	size_t i;
	for (i = 0; i < cfg->vars_count; i++) {
		if (!strcmp(cfg->keys[i], var))
			return cfg->vals[i];
	}
	return NULL;
}

const char *get_str_var(struct config_section *cfg, const char *var, int len)
{
	const char *value = get_var_value(cfg, var);
	if (!value)
		return NULL;
	return len < 0 || strlen(value) <= (size_t)len ? value : NULL;
}

int get_int_var(struct config_section *cfg, const char *var)
{
	const char *value = get_var_value(cfg, var);
	return value ? atoi(value) : 0;
}
