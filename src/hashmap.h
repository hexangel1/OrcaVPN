#ifndef HASHMAP_H_SENTRY
#define HASHMAP_H_SENTRY

#include <stddef.h>
#include <stdint.h>

#define HASHMAP_MISS ((hashmap_val)-1)

typedef size_t hashmap_val;

typedef struct hashmap_key_st {
	uint8_t *data;
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

/* Insert key */
void hashmap_insert(hashmap *hm, hashmap_key *key, hashmap_val val);
/* Delete key */
void hashmap_delete(hashmap *hm, hashmap_key *key);
/* Get key */
hashmap_val hashmap_get(hashmap *hm, hashmap_key *key);

/* Iterate through all keys */
void hashmap_foreach(hashmap *hm,
	void (*cb)(hashmap_key *, hashmap_val, void *), void *data);

#endif /* HASHMAP_H_SENTRY */
