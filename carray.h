#ifndef CARRAY_H_SENTRY
#define CARRAY_H_SENTRY

#include <stddef.h>

typedef struct carray_s {
    size_t item_size;
    size_t nalloc;
    size_t nitems;
    void *items;
} carray_t;

#define create_array_of(type) array_create(0, sizeof(type))

#define array_get(arr, idx) \
    ((idx) < arr->nitems ? ((void *)((char *)arr->items + (idx) * arr->item_size)) : NULL)

carray_t *array_create(size_t nmemb, size_t size);
void array_destroy(carray_t *arr);
void *array_push(carray_t *arr);

#endif
