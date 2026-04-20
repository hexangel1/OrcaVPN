#include <stdio.h>
#include <stdlib.h>

#include "test_common.h"
#include "helper.h"
#include "bytetrie.h"

#define DEBUG_TRIE 0
#define KEY_LENGTH 4
#define INSERT_KEYS_COUNT 1000000

struct test_case {
	void (*fill)(struct byte_trie *);
	int (*check)(struct byte_trie *);
};

uint32_t wang_hash32(uint32_t a)
{
	a = (a ^ 61) ^ (a >> 16);
	a = a + (a << 3);
	a = a ^ (a >> 4);
	a = a * 0x27d4eb2d;
	a = a ^ (a >> 15);
	return a;
}

static void print_leaf(trie_leaf_t *leaf, const unsigned char *key, int len)
{
#if DEBUG_TRIE == 1
	int i;
	for (i = 0; i < len; i++)
		printf("%.2x", key[i]);
	printf(" -> %ld\n", leaf->ival);
#else
	UNUSED(leaf);
	UNUSED(key);
	UNUSED(len);
#endif
}

static void fill_trie(struct byte_trie *bt)
{
	trie_leaf_t *leaf;
	uint32_t i, key;

	for (i = 0; i < INSERT_KEYS_COUNT; i++) {
		key = wang_hash32(i);
		leaf = trie_set(bt, (unsigned char *)&key, sizeof(key));
		leaf->ival = i;
	}

	trie_traverse(bt, print_leaf);

	trie_set(bt, NULL, 0)->ival = 12345;

	for (i = 0; i < INSERT_KEYS_COUNT; i += 2) {
		key = wang_hash32(i);
		trie_del(bt, (unsigned char *)&key, sizeof(key));
	}
}

static int check_trie(struct byte_trie *bt)
{
	trie_leaf_t *leaf;
	uint32_t i, key;

	leaf = trie_get(bt, NULL, 0);
	if (!leaf || leaf->ival != 12345)
		return 0;

	for (i = 0; i < INSERT_KEYS_COUNT; i++) {
		key = wang_hash32(i);
		leaf = trie_get(bt, (unsigned char *)&key, sizeof(key));
		if (i % 2) {
			if (!leaf || leaf->ival != (trie_uint)i)
				return 0;
		} else {
			if (leaf)
				return 0;
		}
	}
	return 1;
}

static void do_test(struct test_case *test, int test_no)
{
	int res;
	struct byte_trie *bt = make_trie();

	test->fill(bt);
	res = test->check(bt);
	if (!res)
		fail_test();
	fprintf(stderr, "[%d] %s\n", test_no, STATUS_PREFIX(res));
	delete_trie(bt);
}

int main(int argc, char **argv)
{
	struct test_case tests[] = {
		{fill_trie, check_trie},
	};

	UNUSED(argc);
	RUN_TESTS(tests);
	return TEST_STATUS;
}
