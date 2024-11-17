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

static struct config_section *new_scope(struct config_section **next, char *s)
{
	struct config_section *section;

	section = malloc(sizeof(struct config_section));
	memset(section, 0, sizeof(struct config_section));
	section->scope = s;
	section->next = NULL;

	*next = section;
	return section;
}

static void add_var(struct config_section *cs, char *key, char *val)
{
	size_t new_size;
	if (cs->vars_count == cs->vars_alloc) {
		cs->vars_alloc += 8;
		new_size = cs->vars_alloc * sizeof(char *);
		cs->keys = realloc(cs->keys, new_size);
		cs->vals = realloc(cs->vals, new_size);
	}
	cs->keys[cs->vars_count] = key;
	cs->vals[cs->vars_count] = val;
	cs->vars_count++;
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
	char buffer[1024];
	char *k_begin, *k_end, *v_begin, *v_end;
	struct config_section *curr = NULL, *head = NULL, **next = &head;

	FILE *fp = fopen(file, "r");
	if (!fp) {
		log_perror(file);
		CONFIG_ERROR("file not opened");
	}
	while (fgets(buffer, sizeof(buffer), fp)) {
		if (buffer[0] == '[') {
			const char *br = strchr(buffer, ']');
			if (!br)
				CONFIG_ERROR("expected ']', end of line found");
			curr = new_scope(next, extract_str(buffer + 1, br - 1));
			next = &curr->next;
			continue;
		}
		if (!curr)
			CONFIG_ERROR("expected '[', variable found");

		for (k_begin = buffer; isspace(*k_begin); k_begin++);
		if (!*k_begin || *k_begin == '#') /* blank line or comment */
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

		add_var(curr,
			extract_str(k_begin, k_end),
			extract_str(v_begin, v_end));
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
		for (i = 0; i < tmp->vars_count; i++) {
			free(tmp->keys[i]);
			free(tmp->vals[i]);
		}
		free(tmp->keys);
		free(tmp->vals);
		free(tmp->scope);
		free(tmp);
	}
}

void debug_config(struct config_section *cfg)
{
	size_t i;
	struct config_section *tmp;

	for (tmp = cfg; tmp; tmp = tmp->next) {
		fprintf(stderr, "[%s]\n", tmp->scope);
		for (i = 0; i < tmp->vars_count; i++)
			fprintf(stderr, "%s = %s\n", tmp->keys[i], tmp->vals[i]);
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
