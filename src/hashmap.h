#ifndef HASHMAP_H_SENTRY
#define HASHMAP_H_SENTRY

#include <stddef.h>
#include <string.h>

#define HASHMAP_MISS ((hashmap_val)-1)

#define HASHMAP_KEY_INT(hmkey, key) do { \
	hmkey.data = (unsigned char *)&key; \
	hmkey.len = sizeof(key); \
} while (0)

#define HASHMAP_KEY_STR(hmkey, key) do { \
	hmkey.data = (unsigned char *)key; \
	hmkey.len = strlen(key); \
} while (0)

typedef size_t hashmap_val;

typedef struct hashmap_key_st {
	unsigned char *data;
	size_t len;
} hashmap_key;

typedef struct hashmap_st {
	size_t size;
	size_t used;
	hashmap_key *keys;
	hashmap_val *vals;
} hashmap;

/* Create hashmap */
hashmap *make_map(void);
/* Delete hashmap */
void delete_map(hashmap *hm);
/* Clear hashmap */
void clear_map(hashmap *hm);

/* Insert key */
void hashmap_insert(hashmap *hm, const hashmap_key *key, hashmap_val val);
/* Delete key */
void hashmap_delete(hashmap *hm, const hashmap_key *key);
/* Get key */
hashmap_val hashmap_get(const hashmap *hm, const hashmap_key *key);
/* Increase key counter */
hashmap_val hashmap_inc(hashmap *hm, const hashmap_key *key, hashmap_val c);

/* Iterate through all keys */
void hashmap_foreach(const hashmap *hm,
	void (*cb)(const hashmap_key *, hashmap_val, void *), void *data);

#endif /* HASHMAP_H_SENTRY */
