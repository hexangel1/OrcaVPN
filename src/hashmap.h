#ifndef HASHMAP_H_SENTRY
#define HASHMAP_H_SENTRY

#include <stddef.h>
#include <stdint.h>

#define HASHMAP_MISS ((uint64_t)-1)

typedef struct hashstring {
	uint8_t *data;
	size_t len;
} hashstring_t;

typedef struct hashmap {
	size_t size;
	size_t used;
	hashstring_t *keys;
	uint64_t *vals;
} hashmap_t;

/* Create hashmap */
struct hashmap *make_map(void);
/* Delete hashmap */
void delete_map(struct hashmap *hm);

/* Insert key */
void hashmap_insert(struct hashmap *hm, hashstring_t *key, uint64_t val);
/* Delete key */
void hashmap_delete(struct hashmap *hm, hashstring_t *key);
/* Get key */
uint64_t hashmap_get(struct hashmap *hm, hashstring_t *key);

/* Iterate through all keys */
void hashmap_foreach(struct hashmap *hm,
	void (*cb)(hashstring_t *, uint64_t, void *), void *data);

#endif /* HASHMAP_H_SENTRY */
