#include <stdlib.h>
#include <string.h>

#include "hashmap.h"

#define HASH_MULTIPLIER 0x9c406bb5UL
#define HASH_XOR_OP 0x12fade34UL

static uint8_t DELETED;

static const size_t hashmap_sizes[] = {
	11,        /* > 8         */
	17,        /* > 16        */
	37,        /* > 32        */
	67,        /* > 64        */
	131,       /* > 128       */
	257,       /* > 256       */
	521,       /* > 512       */
	1031,      /* > 1024      */
	2053,      /* > 2048      */
	4099,      /* > 4096      */
	8209,      /* > 8192      */
	16411,     /* > 16384     */
	32771,     /* > 32768     */
	65537,     /* > 65536     */
	131101,    /* > 131072    */
	262147,    /* > 262144    */
	524309,    /* > 524288    */
	1048583,   /* > 1048576   */
	2097169,   /* > 2097152   */
	4194319,   /* > 4194304   */
	8388617,   /* > 8388608   */
	16777259,  /* > 16777216  */
	33554467,  /* > 33554432  */
	67108879,  /* > 67108864  */
	134217757, /* > 134217728 */
	0
};

static void *memdup(const void *mem, size_t len)
{
	void *copy = malloc(len);
	return copy ? memcpy(copy, mem, len) : NULL;
}

static int is_key_valid(const hashmap_key *key)
{
	return key->data && key->data != &DELETED;
}

static int keys_differ(const hashmap_key *hmkey, const hashmap_key *key)
{
	if (!is_key_valid(hmkey))
		return 1;
	return hmkey->len != key->len || memcmp(hmkey->data, key->data, key->len);
}

static size_t get_hashmap_size(size_t cur_size)
{
	int i;
	for (i = 0; hashmap_sizes[i] && hashmap_sizes[i] <= cur_size; ++i)
		;
	return hashmap_sizes[i];
}

static size_t hash_function(const hashmap_key *key)
{
	register size_t hash_sum = 15;
	register size_t i;

	for (i = 0; i < key->len; i++)
		hash_sum ^= (((size_t)key->data[i]) << (8 * (i % 4)));

	return HASH_MULTIPLIER * (hash_sum ^ HASH_XOR_OP);
}

static void hashmap_evacuation(hashmap *hm)
{
	size_t idx, new_idx, new_used = 0;
	size_t new_size = get_hashmap_size(hm->size);

	hashmap_key *new_keys = calloc(new_size, sizeof(hashmap_key));
	hashmap_val *new_vals = malloc(new_size * sizeof(hashmap_val));

	for (idx = 0; idx < hm->size; ++idx) {
		hashmap_key *key = &hm->keys[idx];
		if (!is_key_valid(key))
			continue;
		new_idx = hash_function(key) % new_size;
		while (new_keys[new_idx].data)
			new_idx = new_idx ? new_idx - 1 : new_size - 1;
		new_keys[new_idx] = *key;
		new_vals[new_idx] = hm->vals[idx];
		new_used++;
	}

	free(hm->keys);
	free(hm->vals);
	hm->keys = new_keys;
	hm->vals = new_vals;
	hm->size = new_size;
	hm->used = new_used;
}

static hashmap_val *hashmap_get_ptr(const hashmap *hm, const hashmap_key *key)
{
	size_t idx = hash_function(key) % hm->size;

	while (hm->keys[idx].data && keys_differ(&hm->keys[idx], key))
		idx = idx ? idx - 1 : hm->size - 1;

	return is_key_valid(&hm->keys[idx]) ? &hm->vals[idx] : NULL;
}

hashmap *make_map(void)
{
	hashmap *hm = malloc(sizeof(hashmap));
	size_t hash_size = get_hashmap_size(0);

	hm->size = hash_size;
	hm->used = 0;
	hm->keys = calloc(hash_size, sizeof(hashmap_key));
	hm->vals = malloc(hash_size * sizeof(hashmap_val));
	return hm;
}

void delete_map(hashmap *hm)
{
	size_t idx;

	if (!hm)
		return;

	for (idx = 0; idx < hm->size; ++idx) {
		if (is_key_valid(&hm->keys[idx]))
			free(hm->keys[idx].data);
	}

	free(hm->keys);
	free(hm->vals);
	free(hm);
}

void clear_map(hashmap *hm)
{
	size_t idx;

	for (idx = 0; idx < hm->size; ++idx) {
		if (is_key_valid(&hm->keys[idx]))
			free(hm->keys[idx].data);
		hm->keys[idx].data = NULL;
		hm->keys[idx].len = 0;
	}
	hm->used = 0;
}

void hashmap_insert(hashmap *hm, const hashmap_key *key, hashmap_val val)
{
	size_t idx = hash_function(key) % hm->size;

	while (is_key_valid(&hm->keys[idx]) && keys_differ(&hm->keys[idx], key))
		idx = idx ? idx - 1 : hm->size - 1;

	if (!is_key_valid(&hm->keys[idx])) {
		if (!hm->keys[idx].data)
			hm->used++;
		hm->keys[idx].data = memdup(key->data, key->len);
		hm->keys[idx].len = key->len;
	}

	hm->vals[idx] = val;

	if ((float)hm->used / (float)hm->size > 0.75f)
		hashmap_evacuation(hm);
}

void hashmap_delete(hashmap *hm, const hashmap_key *key)
{
	size_t idx = hash_function(key) % hm->size;

	while (hm->keys[idx].data && keys_differ(&hm->keys[idx], key))
		idx = idx ? idx - 1 : hm->size - 1;

	if (!hm->keys[idx].data)
		return;

	free(hm->keys[idx].data);
	hm->keys[idx].data = &DELETED;
	hm->keys[idx].len = 0;
}

hashmap_val hashmap_get(const hashmap *hm, const hashmap_key *key)
{
	hashmap_val *val_ptr = hashmap_get_ptr(hm, key);

	return val_ptr ? *val_ptr : HASHMAP_MISS;
}

hashmap_val hashmap_inc(hashmap *hm, const hashmap_key *key, hashmap_val c)
{
	hashmap_val *val_ptr = hashmap_get_ptr(hm, key);

	if (val_ptr)
		return ++(*val_ptr);

	hashmap_insert(hm, key, c);
	return c;
}

void hashmap_foreach(const hashmap *hm,
	void (*callback)(const hashmap_key *, hashmap_val, void *),
	void *data)
{
	size_t idx;

	for (idx = 0; idx < hm->size; ++idx) {
		if (!is_key_valid(&hm->keys[idx]))
			continue;
		callback(&hm->keys[idx], hm->vals[idx], data);
	}
}
