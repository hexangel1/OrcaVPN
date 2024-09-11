#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "carray.h"

static void array_realloc(carray_t *arr, size_t nmemb)
{
    arr->nalloc = nmemb;
    arr->items = realloc(arr->items, arr->nalloc * arr->item_size);
}

static void array_init(carray_t *arr, size_t nmemb, size_t size)
{
    arr->item_size = size;
    arr->nalloc = nmemb;
    arr->nitems = 0;
    arr->items = NULL;
    array_realloc(arr, nmemb);
}

carray_t *array_create(size_t nmemb, size_t size)
{
    carray_t *arr = malloc(sizeof(carray_t));
    array_init(arr, nmemb ? nmemb : 8, size);
    return arr;
}

void array_destroy(carray_t *arr)
{
    if (!arr)
        return;
    free(arr->items);
    free(arr);
}

void *array_push(carray_t *arr)
{
    void *item;
    if (arr->nitems == arr->nalloc)
        array_realloc(arr, arr->nalloc << 1);
    item = (char *)arr->items + arr->nitems * arr->item_size;
    memset(item, 0, arr->item_size);
    arr->nitems++;
    return item;
}
