
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_LEVEL_HASH_H_INCLUDED_
#define _NXT_LEVEL_HASH_H_INCLUDED_


typedef struct nxt_lvlhsh_query_s  nxt_lvlhsh_query_t;

typedef nxt_int_t (*nxt_lvlhsh_test_t)(nxt_lvlhsh_query_t *lhq, void *data);
typedef void *(*nxt_lvlhsh_alloc_t)(void *ctx, size_t size);
typedef void (*nxt_lvlhsh_free_t)(void *ctx, void *p);


#if (NXT_64BIT)

#define NXT_LVLHSH_DEFAULT_BUCKET_SIZE  128
#define NXT_LVLHSH_ENTRY_SIZE           3
#define NXT_LVLHSH_BATCH_ALLOC          16

/* 3 is shift of 64-bit pointer. */
#define NXT_LVLHSH_MEMALIGN_SHIFT       (NXT_MAX_MEMALIGN_SHIFT - 3)

#else

#define NXT_LVLHSH_DEFAULT_BUCKET_SIZE  64
#define NXT_LVLHSH_ENTRY_SIZE           2
#define NXT_LVLHSH_BATCH_ALLOC          8

/* 2 is shift of 32-bit pointer. */
#define NXT_LVLHSH_MEMALIGN_SHIFT       (NXT_MAX_MEMALIGN_SHIFT - 2)

#endif


#if (NXT_LVLHSH_MEMALIGN_SHIFT < 10)
#define NXT_LVLHSH_MAX_MEMALIGN_SHIFT   NXT_LVLHSH_MEMALIGN_SHIFT
#else
#define NXT_LVLHSH_MAX_MEMALIGN_SHIFT   10
#endif


#define NXT_LVLHSH_BUCKET_END(bucket_size)                                    \
    (((bucket_size) - sizeof(void *))                                         \
        / (NXT_LVLHSH_ENTRY_SIZE * sizeof(uint32_t))                          \
     * NXT_LVLHSH_ENTRY_SIZE)


#define NXT_LVLHSH_BUCKET_SIZE(bucket_size)                                   \
    NXT_LVLHSH_BUCKET_END(bucket_size), bucket_size, (bucket_size - 1)


#define NXT_LVLHSH_DEFAULT                                                    \
    NXT_LVLHSH_BUCKET_SIZE(NXT_LVLHSH_DEFAULT_BUCKET_SIZE),                   \
    { 4, 4, 4, 4, 4, 4, 4, 0 }


#define NXT_LVLHSH_LARGE_SLAB                                                 \
    NXT_LVLHSH_BUCKET_SIZE(NXT_LVLHSH_DEFAULT_BUCKET_SIZE),                   \
    { 10, 4, 4, 4, 4, 4, 4, 0 }


#define NXT_LVLHSH_LARGE_MEMALIGN                                             \
    NXT_LVLHSH_BUCKET_SIZE(NXT_LVLHSH_DEFAULT_BUCKET_SIZE),                   \
    { NXT_LVLHSH_MAX_MEMALIGN_SHIFT, 4, 4, 4, 4, 0, 0, 0 }


typedef struct {
    uint32_t                  bucket_end;
    uint32_t                  bucket_size;
    uint32_t                  bucket_mask;
    uint8_t                   shift[8];

    nxt_lvlhsh_test_t         test;
    nxt_lvlhsh_alloc_t        alloc;
    nxt_lvlhsh_free_t         free;
} nxt_lvlhsh_proto_t;


typedef struct {
    void                      *slot;
} nxt_lvlhsh_t;


struct nxt_lvlhsh_query_s {
    uint32_t                  key_hash;
    uint32_t                  replace;   /* 1 bit */
    nxt_str_t                 key;
    void                      *value;

    const nxt_lvlhsh_proto_t  *proto;
    void                      *pool;

    /* Opaque data passed for the test function. */
    void                      *data;
};


typedef struct {
    const nxt_lvlhsh_proto_t  *proto;
    /*
     * Fields to store current bucket entry position.  They cannot be
     * combined in a single bucket pointer with number of entries in low
     * bits, because entry positions are not aligned.  A current level is
     * stored as key bit path from the root.
     */
    uint32_t                  *bucket;
    uint32_t                  current;
    uint32_t                  entry;
    uint32_t                  entries;
} nxt_lvlhsh_each_t;


#define nxt_lvlhsh_is_empty(lh)                                               \
    ((lh)->slot == NULL)


#define nxt_lvlhsh_init(lh)                                                   \
    (lh)->slot = NULL

/*
 * nxt_lvlhsh_find() finds a hash element.  If the element has been
 * found then it is stored in the lhq->value and nxt_lvlhsh_find()
 * returns NXT_OK.  Otherwise NXT_DECLINED is returned.
 *
 * The required nxt_lvlhsh_query_t fields: key_hash, key, proto.
 */
NXT_EXPORT nxt_int_t nxt_lvlhsh_find(nxt_lvlhsh_t *lh, nxt_lvlhsh_query_t *lhq);

/*
 * nxt_lvlhsh_insert() adds a hash element.  If the element already
 * presents in lvlhsh and the lhq->replace flag is zero, then lhq->value
 * is updated with the old element and NXT_DECLINED is returned.
 * If the element already presents in lvlhsh and the lhq->replace flag
 * is non-zero, then the old element is replaced with the new element.
 * lhq->value is updated with the old element, and NXT_OK is returned.
 * If the element is not present in lvlhsh, then it is inserted and
 * NXT_OK is returned.  The lhq->value is not changed.
 * On memory allocation failure NXT_ERROR is returned.
 *
 * The required nxt_lvlhsh_query_t fields: key_hash, key, proto, replace, value.
 * The optional nxt_lvlhsh_query_t fields: pool.
 */
NXT_EXPORT nxt_int_t nxt_lvlhsh_insert(nxt_lvlhsh_t *lh,
    nxt_lvlhsh_query_t *lhq);

/*
 * nxt_lvlhsh_delete() deletes a hash element.  If the element has been
 * found then it is removed from lvlhsh and is stored in the lhq->value,
 * and NXT_OK is returned.  Otherwise NXT_DECLINED is returned.
 *
 * The required nxt_lvlhsh_query_t fields: key_hash, key, proto.
 * The optional nxt_lvlhsh_query_t fields: pool.
 */
NXT_EXPORT nxt_int_t nxt_lvlhsh_delete(nxt_lvlhsh_t *lh,
    nxt_lvlhsh_query_t *lhq);

/*
 * nxt_lvlhsh_each_init() initializes iterator.
 * It must be called before the first nxt_lvlhsh_each() call.
 */
#define nxt_lvlhsh_each_init(lhe, _proto)                                     \
    do {                                                                      \
        (lhe)->proto = _proto;                                                \
        (lhe)->bucket = NULL;                                                 \
    } while (0)

/*
 * nxt_lvlhsh_each() iterates over a lvlhsh.
 * It returns NULL if there is no more elements.
 */
NXT_EXPORT void *nxt_lvlhsh_each(nxt_lvlhsh_t *lh, nxt_lvlhsh_each_t *lhe);

/*
 * nxt_lvlhsh_peek() is used to iterate over a lvlhsh during the lvlhsh
 * destruction.  The returned hash element should be deleted from the lvlhsh,
 * otherwise it will be returned again by the next nxt_lvlhsh_peek() call.
 * The function returns NULL if there is no more elements in the lvlhsh.
 */
NXT_EXPORT void *nxt_lvlhsh_peek(nxt_lvlhsh_t *lh,
    const nxt_lvlhsh_proto_t *proto);

/*
 * nxt_lvlhsh_retrieve() is used to iterate over a lvlhsh during the lvlhsh
 * destruction.  As opposed to nxt_lvlhsh_peek() the returned hash element
 * is deleted from the lvlhsh.  The function returns NULL if there is no
 * more elements in the lvlhsh.
 */
NXT_EXPORT void *nxt_lvlhsh_retrieve(nxt_lvlhsh_t *lh,
    const nxt_lvlhsh_proto_t *proto, void *pool);


NXT_EXPORT void *nxt_lvlhsh_alloc(void *data, size_t size);
NXT_EXPORT void nxt_lvlhsh_free(void *data, void *p);


#endif /* _NXT_LEVEL_HASH_H_INCLUDED_ */
