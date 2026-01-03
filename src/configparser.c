#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "configparser.h"
#include "logger.h"

#define IS_INDENT(c)     ((c) == ' ' || (c) == '\t')
#define IS_WHITESPACE(c) ((c) == ' ' || (c) == '\t' || (c) == '\n')

enum parser_state {
	st_error = -1,
	st_initial,
	st_read_scope,
	st_read_key,
	st_read_val,
	st_wait_equal,
	st_wait_val,
	st_wait_newline,
	st_comment
};

struct config_parser {
	enum parser_state state;
	char buffer[1024];
	char error[256];
	char *save_key;
	int used;
	int line;
	int column;
	struct config_section *head;
	struct config_section *curr;
};

static void new_scope(struct config_parser *fsm, char *s)
{
	struct config_section **head = &fsm->head;
	struct config_section *new_section;

	new_section = malloc(sizeof(struct config_section));
	memset(new_section, 0, sizeof(struct config_section));
	new_section->scope = s;
	new_section->next = NULL;

	while (*head) {
		head = &(*head)->next;
	}
	*head = new_section;
	fsm->curr = new_section;
}

static void add_var(struct config_parser *fsm, char *key, char *val)
{
	struct config_section *cs = fsm->curr;

	if (cs->vars_count == cs->vars_alloc) {
		cs->vars_alloc += 8;
		cs->keys = realloc(cs->keys, cs->vars_alloc * sizeof(char *));
		cs->vals = realloc(cs->vals, cs->vars_alloc * sizeof(char *));
	}
	cs->keys[cs->vars_count] = key;
	cs->vals[cs->vars_count] = val;
	cs->vars_count++;
}

static void set_error(struct config_parser *fsm, const char *mesg)
{
	fsm->state = st_error;
	snprintf(fsm->error, sizeof(fsm->error),
		"%s at line %d, col %d", mesg, fsm->line, fsm->column);
}

#define PARSER_ERROR(fsm) do { \
	set_error(fsm, "unexpected character"); \
	return; \
} while (0)

static void write_buffer(struct config_parser *fsm, int c)
{
	if (fsm->used == sizeof(fsm->buffer)) {
		set_error(fsm, "parser buffer overflow");
		return;
	}
	if (c == '=') {
		set_error(fsm, "unexpected '='");
		return;
	}
	fsm->buffer[fsm->used++] = c;
}

static char *get_buffer_str(struct config_parser *fsm)
{
	char *str = malloc(fsm->used + 1);
	memcpy(str, fsm->buffer, fsm->used);
	str[fsm->used] = '\0';
	fsm->used = 0;
	return str;
}

static void cursor_move(struct config_parser *fsm, int newline)
{
	if (fsm->state == st_error)
		return;

	if (newline) {
		fsm->line++;
		fsm->column = 1;
	} else {
		fsm->column++;
	}
}

static void fsm_parser_init(struct config_parser *fsm)
{
	memset(fsm, 0, sizeof(struct config_parser));
	fsm->state = st_initial;
	fsm->line = 1;
	fsm->column = 1;
}

static void fsm_parser_step(struct config_parser *fsm, int c)
{
	switch (fsm->state) {
	case st_initial:
		if (c == '#') {
			fsm->state = st_comment;
		} else if (c == '[') {
			fsm->state = st_read_scope;
		} else if (!IS_WHITESPACE(c)) {
			fsm->state = st_read_key;
			write_buffer(fsm, c);
		}
		break;
	case st_read_scope:
		if (c == '\n')
			PARSER_ERROR(fsm);
		if (c == ']') {
			fsm->state = st_initial;
			new_scope(fsm, get_buffer_str(fsm));
		} else {
			write_buffer(fsm, c);
		}
		break;
	case st_read_key:
		if (c == '\n')
			PARSER_ERROR(fsm);
		if (IS_INDENT(c) || c == '=') {
			fsm->state = c != '=' ? st_wait_equal : st_wait_val;
			fsm->save_key = get_buffer_str(fsm);
		} else {
			write_buffer(fsm, c);
		}
		break;
	case st_read_val:
		if (IS_WHITESPACE(c)) {
			fsm->state = c != '\n' ? st_wait_newline : st_initial;
			add_var(fsm, fsm->save_key, get_buffer_str(fsm));
			fsm->save_key = NULL;
		} else {
			write_buffer(fsm, c);
		}
		break;
	case st_wait_equal:
		if (!IS_INDENT(c) && c != '=')
			PARSER_ERROR(fsm);
		if (c == '=')
			fsm->state = st_wait_val;
		break;
	case st_wait_val:
		if (c == '\n')
			PARSER_ERROR(fsm);
		if (!IS_INDENT(c)) {
			fsm->state = st_read_val;
			write_buffer(fsm, c);
		}
		break;
	case st_wait_newline:
		if (!IS_WHITESPACE(c))
			PARSER_ERROR(fsm);
		/* fallthrough */
	case st_comment:
		if (c == '\n')
			fsm->state = st_initial;
		break;
	case st_error:
		;
	}
	cursor_move(fsm, c == '\n');
}

static int fsm_parser_check(struct config_parser *fsm)
{
	return fsm->state != st_initial;
}

static const char *fsm_parser_error(struct config_parser *fsm)
{
	if (fsm->state == st_error)
		return fsm->error;
	if (fsm->state != st_initial)
		return "bad parser final state";
	return "";
}

static void fsm_parser_destroy(struct config_parser *fsm)
{
	free_config(fsm->head);
	free(fsm->save_key);
}

struct config_section *read_config(const char *file)
{
	struct config_parser fsm;
	int c;

	FILE *fp = fopen(file, "r");
	if (!fp) {
		log_mesg(log_lvl_err, "config not opened: %s",
			strerror(errno));
		return NULL;
	}

	fsm_parser_init(&fsm);
	while ((c = fgetc(fp)) != EOF)
		fsm_parser_step(&fsm, c);
	fclose(fp);

	if (fsm_parser_check(&fsm)) {
		log_mesg(log_lvl_err, "read config failed: %s",
			fsm_parser_error(&fsm));
		fsm_parser_destroy(&fsm);
		return NULL;
	}

	return fsm.head;
}

void free_config(struct config_section *cfg)
{
	int i;
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

const char *get_var_value(struct config_section *cfg, const char *var)
{
	int i;
	for (i = 0; i < cfg->vars_count; i++) {
		if (!strcmp(cfg->keys[i], var))
			return cfg->vals[i];
	}
	return NULL;
}

const char *get_str_var(struct config_section *cfg, const char *var, int max)
{
	const char *value = get_var_value(cfg, var);
	if (!value)
		return NULL;
	return (max < 0 || strlen(value) < (size_t)max) ? value : NULL;
}

int get_int_var(struct config_section *cfg, const char *var)
{
	const char *value = get_var_value(cfg, var);
	return value ? atoi(value) : 0;
}

int get_bool_var(struct config_section *cfg, const char *var)
{
	static const char *const boolean_vals[] = {
		"on", "off", "true", "false", "1", "0"
	};
	const char *value;
	unsigned int i;

	value = get_var_value(cfg, var);
	if (!value)
		return 0;
	for (i = 0; i < sizeof(boolean_vals) / sizeof(boolean_vals[0]); i++) {
		if (!strcmp(value, boolean_vals[i]))
			return !(i % 2);
	}
	return -1;
}
