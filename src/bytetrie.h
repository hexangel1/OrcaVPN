#ifndef BYTETRIE_H_SENTRY
#define BYTETRIE_H_SENTRY

#include <stddef.h>

#define CHILD_COUNT 0x10
#define MAX_KEY_LENGTH 0x80

typedef size_t trie_uint;

typedef union trie_leaf {
	trie_uint ival;
	void *ptr;
} trie_leaf_t;

struct byte_trie {
	struct byte_trie *childs[CHILD_COUNT];
	struct byte_trie *parent;
	trie_leaf_t leaf;
	unsigned char index;
	unsigned char is_leaf;
};

/* Create trie */
struct byte_trie *make_trie(void);
/* Dispose trie */
void delete_trie(struct byte_trie *bt);
/* Clear trie */
void clear_trie(struct byte_trie *bt);

/* Set key */
trie_leaf_t *trie_set(struct byte_trie *bt, const unsigned char *key, int len);
/* Get key */
trie_leaf_t *trie_get(struct byte_trie *bt, const unsigned char *key, int len);
/* Delete key */
void trie_del(struct byte_trie *bt, const unsigned char *key, int len);

/* Search key */
int trie_search(struct byte_trie *bt, const unsigned char *key, int len);
/* Search prefix */
int trie_has_prefix(struct byte_trie *bt, const unsigned char *key, int len);

/* Traverse trie keys with callback function */
void trie_traverse(struct byte_trie *bt,
	void (*callback)(trie_leaf_t *, const unsigned char *, int));

#endif /* BYTETRIE_H_SENTRY */
