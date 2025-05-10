#include <stdio.h>
#include <stdlib.h>

#include "test_common.h"
#include "helper.h"
#include "hashmap.h"

#define KEY_LENGTH 20
#define INSERT_KEYS_COUNT 200000
#define RANDOM_SEED 1000

struct hashmap_test_case {
	void (*fill)(hashmap *);
	int (*check)(const hashmap *);
};

static const char *insert_keys[] = {
	"Hello", "world", ",", "this", "is", "very", "simple", "test",
	"for", "orcavpn", "hashmap", "module", "!!!",
};

static void generate_key(char *buffer, int pref)
{
	static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	unsigned int i;

	buffer += sprintf(buffer, "%d_", pref);
	for (i = 0; i < KEY_LENGTH; i++) {
		int index = rand() % (sizeof(charset) - 1);
		buffer[i] = charset[index];
	}
	buffer[i] = '\0';
}

static void fill_hashmap(hashmap *hm)
{
	hashmap_key key;
	unsigned int i;

	for (i = 0; i < sizeof(insert_keys) / sizeof(insert_keys[0]); i++) {
		HASHMAP_KEY_STR(key, insert_keys[i]);
		hashmap_insert(hm, &key, i);
	}
}

static void fill_hashmap2(hashmap *hm)
{
	hashmap_key key;
	unsigned int i;

	fill_hashmap(hm);
	for (i = 0; i < sizeof(insert_keys) / sizeof(insert_keys[0]); i++) {
		if (i % 2 == 0) {
			HASHMAP_KEY_STR(key, insert_keys[i]);
			hashmap_delete(hm, &key);
		}
	}
	HASHMAP_KEY_STR(key, "not existed key");
	hashmap_delete(hm, &key);
	HASHMAP_KEY_STR(key, "new key");
	hashmap_insert(hm, &key, 42);
}

static void fill_hashmap3(hashmap *hm)
{
	hashmap_key key;
	unsigned int i, j;
	char key_buffer[64];

	fill_hashmap(hm);
	srand(RANDOM_SEED);
	for (i = 0; i < INSERT_KEYS_COUNT; i++) {
		generate_key(key_buffer, i);
		HASHMAP_KEY_STR(key, key_buffer);
		for (j = 0; j < 10; j++)
			hashmap_inc(hm, &key, 1);
	}
}

static void fill_hashmap4(hashmap *hm)
{
	hashmap_key key;
	unsigned int i;
	char key_buffer[64];

	fill_hashmap3(hm);
	srand(RANDOM_SEED);
	for (i = 0; i < INSERT_KEYS_COUNT; i++) {
		generate_key(key_buffer, i);
		if (i % 3 == 0) {
			HASHMAP_KEY_STR(key, key_buffer);
			hashmap_delete(hm, &key);
		}
	}
}

static int check_hashmap(const hashmap *hm)
{
	hashmap_key key;
	unsigned int i;

	for (i = 0; i < sizeof(insert_keys) / sizeof(insert_keys[0]); i++) {
		HASHMAP_KEY_STR(key, insert_keys[i]);
		if (hashmap_get(hm, &key) != (hashmap_val)i)
			return 0;
	}
	return 1;
}

static int check_hashmap2(const hashmap *hm)
{
	hashmap_key key;
	unsigned int i;

	for (i = 0; i < sizeof(insert_keys) / sizeof(insert_keys[0]); i++) {
		HASHMAP_KEY_STR(key, insert_keys[i]);
		if (hashmap_get(hm, &key) != (i % 2 ? (hashmap_val)i : HASHMAP_MISS))
			return 0;
	}
	HASHMAP_KEY_STR(key, "new key");
	if (hashmap_get(hm, &key) != 42)
		return 0;
	HASHMAP_KEY_STR(key, "not existed key");
	if (hashmap_get(hm, &key) != HASHMAP_MISS)
		return 0;
	return 1;
}

static int check_hashmap3(const hashmap *hm)
{
	hashmap_key key;
	unsigned int i;
	char key_buffer[64];

	if (!check_hashmap(hm))
		return 0;

	srand(RANDOM_SEED);
	for (i = 0; i < INSERT_KEYS_COUNT; i++) {
		generate_key(key_buffer, i);
		HASHMAP_KEY_STR(key, key_buffer);
		if (hashmap_get(hm, &key) != (hashmap_val)10)
			return 0;
	}
	return 1;
}

static int check_hashmap4(const hashmap *hm)
{
	hashmap_key key;
	unsigned int i;
	char key_buffer[64];

	if (!check_hashmap(hm))
		return 0;

	srand(RANDOM_SEED);
	for (i = 0; i < INSERT_KEYS_COUNT; i++) {
		generate_key(key_buffer, i);
		HASHMAP_KEY_STR(key, key_buffer);
		if (hashmap_get(hm, &key) != (i % 3 ? (hashmap_val)10 : HASHMAP_MISS))
			return 0;
	}
	return 1;
}

static void do_test(struct hashmap_test_case *test, int test_no)
{
	int res;
	hashmap *hm = make_map();

	test->fill(hm);
	res = test->check(hm);
	if (!res)
	   fail_test();
	fprintf(stderr, "[%d] %s\n", test_no, STATUS_PREFIX(res));
	delete_map(hm);
}

int main(int argc, char **argv)
{
	struct hashmap_test_case tests[] = {
		{fill_hashmap,  check_hashmap},
		{fill_hashmap2, check_hashmap2},
		{fill_hashmap3, check_hashmap3},
		{fill_hashmap4, check_hashmap4},
	};

	UNUSED(argc);
	RUN_TESTS(tests);
	return TEST_STATUS;
}
