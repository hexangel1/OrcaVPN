#include <stdlib.h>
#include <string.h>

#include "bytetrie.h"

static struct byte_trie *alloc_node(void)
{
	struct byte_trie *node = malloc(sizeof(struct byte_trie));
	memset(node, 0, sizeof(struct byte_trie));
	return node;
}

static struct byte_trie *go_by_key(struct byte_trie *bt,
	const unsigned char *key, int len, int alloc)
{
	register int i, idx;
	struct byte_trie *child;

	for (i = 0; i < len << 1; i++) {
		idx = (i & 1 ? *key : *key >> 4) & 0x0f;
		child = bt->childs[idx];
		if (!child && !alloc)
			return NULL;
		if (!child) {
			child = alloc_node();
			child->parent = bt;
			child->index = idx;
			bt->childs[idx] = child;
		}
		bt = child;
		key += i & 1;
	}
	return bt;
}

static int is_empty_node(const struct byte_trie *bt)
{
	int i;

	if (bt->is_leaf)
		return 0;

	for (i = 0; i < CHILD_COUNT; i++) {
		if (bt->childs[i])
			return 0;
	}
	return 1;
}

struct byte_trie *make_trie(void)
{
	return alloc_node();
}

void delete_trie(struct byte_trie *bt)
{
	int i;

	if (!bt)
		return;
	for (i = 0; i < CHILD_COUNT; i++)
		delete_trie(bt->childs[i]);

	free(bt);
}

void clear_trie(struct byte_trie *bt)
{
	int i;

	if (!bt)
		return;
	for (i = 0; i < CHILD_COUNT; i++)
		delete_trie(bt->childs[i]);

	memset(bt, 0, sizeof(struct byte_trie));
}

trie_leaf_t *trie_set(struct byte_trie *bt, const unsigned char *key, int len)
{
	struct byte_trie *node = go_by_key(bt, key, len, 1);
	node->is_leaf = 1;

	return &node->leaf;
}

trie_leaf_t *trie_get(struct byte_trie *bt, const unsigned char *key, int len)
{
	struct byte_trie *node = go_by_key(bt, key, len, 0);
	if (!node || !node->is_leaf)
		return NULL;

	return &node->leaf;
}

void trie_del(struct byte_trie *bt, const unsigned char *key, int len)
{
	struct byte_trie *node = go_by_key(bt, key, len, 0);
	if (!node || !node->is_leaf)
		return;

	node->is_leaf = 0;
	memset(&node->leaf, 0, sizeof(trie_leaf_t));

	while (node->parent && is_empty_node(node)) {
		struct byte_trie *parent = node->parent;
		parent->childs[node->index] = NULL;
		free(node);
		node = parent;
	}
}

int trie_search(struct byte_trie *bt, const unsigned char *key, int len)
{
	struct byte_trie *node = go_by_key(bt, key, len, 0);
	return node && node->is_leaf;
}

int trie_has_prefix(struct byte_trie *bt, const unsigned char *key, int len)
{
	return go_by_key(bt, key, len, 0) ? 1 : 0;
}

static void trie_traverse_go(struct byte_trie *bt,
	unsigned char *key, int depth,
	void (*callback)(trie_leaf_t *, const unsigned char *, int))
{
	int i, len = depth / 2;

	if (bt->is_leaf)
		callback(&bt->leaf, key, len);

	if (len >= MAX_KEY_LENGTH)
		return;

	if (depth & 1)
		key[len] <<= 4;

	for (i = 0; i < CHILD_COUNT; i++) {
		if (!bt->childs[i])
			continue;
		key[len] |= i & 0x0f;
		trie_traverse_go(bt->childs[i], key, depth + 1, callback);
		key[len] &= 0xf0;
	}
}

void trie_traverse(struct byte_trie *bt,
	void (*callback)(trie_leaf_t *, const unsigned char *, int))
{
	unsigned char buf[MAX_KEY_LENGTH];
	int i;

	memset(buf, 0, sizeof(buf));

	if (bt->is_leaf)
		callback(&bt->leaf, buf, 0);

	for (i = 0; i < CHILD_COUNT; i++) {
		if (!bt->childs[i])
			continue;
		buf[0] = i;
		trie_traverse_go(bt->childs[i], buf, 1, callback);
	}
}
