
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * The level hash consists of hierarchical levels of arrays of pointers.
 * The pointers may point to another level, a bucket, or NULL.
 * The levels and buckets must be allocated in manner alike posix_memalign()
 * to bookkeep additional information in pointer low bits.
 *
 * A level is an array of pointers.  Its size is a power of 2.  Levels
 * may be different sizes, but on the same level the sizes are the same.
 * Level sizes are specified by number of bits per level in lvlhsh->shift
 * array.  A hash may have up to 7 levels.  There are two predefined
 * shift arrays given by the first two shift array values:
 *
 * 1) [0, 0]:  [4, 4, 4, 4, 4, 4, 4] on a 64-bit platform or
 *             [5, 5, 5, 5, 5, 5, 0] on a 32-bit platform,
 *    so default size of levels is 128 bytes.
 *
 * 2) [0, 10]: [10, 4, 4, 4, 4, 4, 0] on a 64-bit platform or
 *             [10, 5, 5, 5, 5, 0, 0] on a 32-bit platform,
 *    so default size of levels is 128 bytes on all levels except
 *    the first level.  The first level is 8K or 4K on 64-bit or 32-bit
 *    platforms respectively.
 *
 * All buckets in a hash are the same size which is a power of 2.
 * A bucket contains several entries stored and tested sequentially.
 * The bucket size should be one or two CPU cache line size, a minimum
 * allowed size is 32 bytes.  A default 128-byte bucket contains 10 64-bit
 * entries or 15 32-bit entries.  Each entry consists of pointer to value
 * data and 32-bit key.  If an entry value pointer is NULL, the entry is free.
 * On a 64-bit platform entry value pointers are no aligned, therefore they
 * are accessed as two 32-bit integers.  The rest trailing space in a bucket
 * is used as pointer to next bucket and this pointer is always aligned.
 * Although the level hash allows to store a lot of values in a bucket chain,
 * this is non optimal way.  The large data set should be stored using
 * several levels.
 */

#define nxt_lvlhsh_is_bucket(p)                                               \
    ((uintptr_t) (p) & 1)


#define nxt_lvlhsh_count_inc(n)                                               \
    n = (void *) ((uintptr_t) (n) + 2)


#define nxt_lvlhsh_count_dec(n)                                               \
    n = (void *) ((uintptr_t) (n) - 2)


#define nxt_lvlhsh_level_size(proto, nlvl)                                    \
    ((uintptr_t) 1 << proto->shift[nlvl])


#define nxt_lvlhsh_level(lvl, mask)                                           \
    (void **) ((uintptr_t) lvl & (~mask << 2))


#define nxt_lvlhsh_level_entries(lvl, mask)                                   \
    ((uintptr_t) lvl & (mask << 1))


#define nxt_lvlhsh_store_bucket(slot, bkt)                                    \
    slot = (void **) ((uintptr_t) bkt | 2 | 1)


#define nxt_lvlhsh_bucket_size(proto)                                         \
    proto->bucket_size


#define nxt_lvlhsh_bucket(proto, bkt)                                         \
    (uint32_t *) ((uintptr_t) bkt & ~(uintptr_t) proto->bucket_mask)


#define nxt_lvlhsh_bucket_entries(proto, bkt)                                 \
    (((uintptr_t) bkt & (uintptr_t) proto->bucket_mask) >> 1)


#define nxt_lvlhsh_bucket_end(proto, bkt)                                     \
    &bkt[proto->bucket_end]


#define nxt_lvlhsh_free_entry(e)                                              \
    (!(nxt_lvlhsh_valid_entry(e)))


#define nxt_lvlhsh_next_bucket(proto, bkt)                                    \
    ((void **) &bkt[proto->bucket_end])

#if (NXT_64BIT)

#define nxt_lvlhsh_valid_entry(e)                                             \
    (((e)[0] | (e)[1]) != 0)


#define nxt_lvlhsh_entry_value(e)                                             \
    (void *) (((uintptr_t) (e)[1] << 32) + (e)[0])


#define nxt_lvlhsh_set_entry_value(e, n)                                      \
    (e)[0] = (uint32_t)  (uintptr_t) n;                                       \
    (e)[1] = (uint32_t) ((uintptr_t) n >> 32)


#define nxt_lvlhsh_entry_key(e)                                               \
    (e)[2]


#define nxt_lvlhsh_set_entry_key(e, n)                                        \
    (e)[2] = n

#else

#define nxt_lvlhsh_valid_entry(e)                                             \
    ((e)[0] != 0)


#define nxt_lvlhsh_entry_value(e)                                             \
    (void *) (e)[0]


#define nxt_lvlhsh_set_entry_value(e, n)                                      \
    (e)[0] = (uint32_t) n


#define nxt_lvlhsh_entry_key(e)                                               \
    (e)[1]


#define nxt_lvlhsh_set_entry_key(e, n)                                        \
    (e)[1] = n

#endif


#define NXT_LVLHSH_BUCKET_DONE  ((void *) -1)


typedef struct {
    const nxt_lvlhsh_proto_t  *proto;
    void                      *pool;
    uint32_t                  retrieve;  /* 1 bit */
} nxt_lvlhsh_peek_t;


static nxt_int_t nxt_lvlhsh_level_find(nxt_lvlhsh_query_t *lhq, void **lvl,
    uint32_t key, nxt_uint_t nlvl);
static nxt_int_t nxt_lvlhsh_bucket_find(nxt_lvlhsh_query_t *lhq, void **bkt);
static nxt_int_t nxt_lvlhsh_new_bucket(nxt_lvlhsh_query_t *lhq, void **slot);
static nxt_int_t nxt_lvlhsh_level_insert(nxt_lvlhsh_query_t *lhq,
    void **slot, uint32_t key, nxt_uint_t nlvl);
static nxt_int_t nxt_lvlhsh_bucket_insert(nxt_lvlhsh_query_t *lhq,
    void **slot, uint32_t key, nxt_int_t nlvl);
static nxt_int_t nxt_lvlhsh_convert_bucket_to_level(nxt_lvlhsh_query_t *lhq,
    void **slot, nxt_uint_t nlvl, uint32_t *bucket);
static nxt_int_t nxt_lvlhsh_level_convertion_insert(nxt_lvlhsh_query_t *lhq,
    void **parent, uint32_t key, nxt_uint_t nlvl);
static nxt_int_t nxt_lvlhsh_bucket_convertion_insert(nxt_lvlhsh_query_t *lhq,
    void **slot, uint32_t key, nxt_int_t nlvl);
static nxt_int_t nxt_lvlhsh_free_level(nxt_lvlhsh_query_t *lhq, void **level,
    nxt_uint_t size);
static nxt_int_t nxt_lvlhsh_level_delete(nxt_lvlhsh_query_t *lhq, void **slot,
    uint32_t key, nxt_uint_t nlvl);
static nxt_int_t nxt_lvlhsh_bucket_delete(nxt_lvlhsh_query_t *lhq, void **bkt);
static void *nxt_lvlhsh_level_each(nxt_lvlhsh_each_t *lhe, void **level,
    nxt_uint_t nlvl, nxt_uint_t shift);
static void *nxt_lvlhsh_bucket_each(nxt_lvlhsh_each_t *lhe);
static void *nxt_lvlhsh_level_peek(nxt_lvlhsh_peek_t *peek, void **level,
    nxt_uint_t nlvl);
static void *nxt_lvlhsh_bucket_peek(nxt_lvlhsh_peek_t *peek, void **bkt);


nxt_int_t
nxt_lvlhsh_find(nxt_lvlhsh_t *lh, nxt_lvlhsh_query_t *lhq)
{
    void  *slot;

    slot = lh->slot;

    if (nxt_fast_path(slot != NULL)) {

        if (nxt_lvlhsh_is_bucket(slot)) {
            return nxt_lvlhsh_bucket_find(lhq, slot);
        }

        return nxt_lvlhsh_level_find(lhq, slot, lhq->key_hash, 0);
    }

    return NXT_DECLINED;
}


static nxt_int_t
nxt_lvlhsh_level_find(nxt_lvlhsh_query_t *lhq, void **lvl, uint32_t key,
    nxt_uint_t nlvl)
{
    void        **slot;
    uintptr_t   mask;
    nxt_uint_t  shift;

    shift = lhq->proto->shift[nlvl];
    mask = ((uintptr_t) 1 << shift) - 1;

    lvl = nxt_lvlhsh_level(lvl, mask);
    slot = lvl[key & mask];

    if (slot != NULL) {

        if (nxt_lvlhsh_is_bucket(slot)) {
            return nxt_lvlhsh_bucket_find(lhq, slot);
        }

        return nxt_lvlhsh_level_find(lhq, slot, key >> shift, nlvl + 1);
    }

    return NXT_DECLINED;
}


static nxt_int_t
nxt_lvlhsh_bucket_find(nxt_lvlhsh_query_t *lhq, void **bkt)
{
    void        *value;
    uint32_t    *bucket, *e;
    nxt_uint_t  n;

    do {
        bucket = nxt_lvlhsh_bucket(lhq->proto, bkt);
        n = nxt_lvlhsh_bucket_entries(lhq->proto, bkt);
        e = bucket;

        do {
            if (nxt_lvlhsh_valid_entry(e)) {
                n--;

                if (nxt_lvlhsh_entry_key(e) == lhq->key_hash) {

                    value = nxt_lvlhsh_entry_value(e);

                    if (lhq->proto->test(lhq, value) == NXT_OK) {
                        lhq->value = value;

                        return NXT_OK;
                    }
                }
            }

            e += NXT_LVLHSH_ENTRY_SIZE;

        } while (n != 0);

        bkt = *nxt_lvlhsh_next_bucket(lhq->proto, bucket);

    } while (bkt != NULL);

    return NXT_DECLINED;
}


nxt_int_t
nxt_lvlhsh_insert(nxt_lvlhsh_t *lh, nxt_lvlhsh_query_t *lhq)
{
    uint32_t  key;

    if (nxt_fast_path(lh->slot != NULL)) {

        key = lhq->key_hash;

        if (nxt_lvlhsh_is_bucket(lh->slot)) {
            return nxt_lvlhsh_bucket_insert(lhq, &lh->slot, key, -1);
        }

        return nxt_lvlhsh_level_insert(lhq, &lh->slot, key, 0);
    }

    return nxt_lvlhsh_new_bucket(lhq, &lh->slot);
}


static nxt_int_t
nxt_lvlhsh_new_bucket(nxt_lvlhsh_query_t *lhq, void **slot)
{
    uint32_t  *bucket;

    bucket = lhq->proto->alloc(lhq->pool, nxt_lvlhsh_bucket_size(lhq->proto));

    if (nxt_fast_path(bucket != NULL)) {

        nxt_lvlhsh_set_entry_value(bucket, lhq->value);
        nxt_lvlhsh_set_entry_key(bucket, lhq->key_hash);

        *nxt_lvlhsh_next_bucket(lhq->proto, bucket) = NULL;

        nxt_lvlhsh_store_bucket(*slot, bucket);

        return NXT_OK;
    }

    return NXT_ERROR;
}


static nxt_int_t
nxt_lvlhsh_level_insert(nxt_lvlhsh_query_t *lhq, void **parent, uint32_t key,
    nxt_uint_t nlvl)
{
    void        **slot, **lvl;
    nxt_int_t   ret;
    uintptr_t   mask;
    nxt_uint_t  shift;

    shift = lhq->proto->shift[nlvl];
    mask = ((uintptr_t) 1 << shift) - 1;

    lvl = nxt_lvlhsh_level(*parent, mask);
    slot = &lvl[key & mask];

    if (*slot != NULL) {
        key >>= shift;

        if (nxt_lvlhsh_is_bucket(*slot)) {
            return nxt_lvlhsh_bucket_insert(lhq, slot, key, nlvl);
        }

        return nxt_lvlhsh_level_insert(lhq, slot, key, nlvl + 1);
    }

    ret = nxt_lvlhsh_new_bucket(lhq, slot);

    if (nxt_fast_path(ret == NXT_OK)) {
        nxt_lvlhsh_count_inc(*parent);
    }

    return ret;
}


static nxt_int_t
nxt_lvlhsh_bucket_insert(nxt_lvlhsh_query_t *lhq, void **slot, uint32_t key,
    nxt_int_t nlvl)
{
    void                      **bkt, **vacant_bucket, *value;
    uint32_t                  *bucket, *e, *vacant_entry;
    nxt_int_t                 ret;
    uintptr_t                 n;
    const void                *new_value;
    const nxt_lvlhsh_proto_t  *proto;

    bkt = slot;
    vacant_entry = NULL;
    vacant_bucket = NULL;
    proto = lhq->proto;

    /* Search for duplicate entry in bucket chain. */

    do {
        bucket = nxt_lvlhsh_bucket(proto, *bkt);
        n = nxt_lvlhsh_bucket_entries(proto, *bkt);
        e = bucket;

        do {
            if (nxt_lvlhsh_valid_entry(e)) {

                if (nxt_lvlhsh_entry_key(e) == lhq->key_hash) {

                    value = nxt_lvlhsh_entry_value(e);

                    if (proto->test(lhq, value) == NXT_OK) {

                        new_value = lhq->value;
                        lhq->value = value;

                        if (lhq->replace) {
                            nxt_lvlhsh_set_entry_value(e, new_value);

                            return NXT_OK;
                        }

                        return NXT_DECLINED;
                    }
                }

                n--;

            } else {
                /*
                 * Save a hole vacant position in bucket
                 * and continue to search for duplicate entry.
                 */
                if (vacant_entry == NULL) {
                    vacant_entry = e;
                    vacant_bucket = bkt;
                }
            }

            e += NXT_LVLHSH_ENTRY_SIZE;

        } while (n != 0);

        if (e < nxt_lvlhsh_bucket_end(proto, bucket)) {
            /*
             * Save a vacant position on incomplete bucket's end
             * and continue to search for duplicate entry.
             */
            if (vacant_entry == NULL) {
                vacant_entry = e;
                vacant_bucket = bkt;
            }
        }

        bkt = nxt_lvlhsh_next_bucket(proto, bucket);

    } while (*bkt != NULL);

    if (vacant_entry != NULL) {
        nxt_lvlhsh_set_entry_value(vacant_entry, lhq->value);
        nxt_lvlhsh_set_entry_key(vacant_entry, lhq->key_hash);
        nxt_lvlhsh_count_inc(*vacant_bucket);

        return NXT_OK;
    }

    /* All buckets are full. */

    nlvl++;

    if (nxt_fast_path(proto->shift[nlvl] != 0)) {

        ret = nxt_lvlhsh_convert_bucket_to_level(lhq, slot, nlvl, bucket);

        if (nxt_fast_path(ret == NXT_OK)) {
            return nxt_lvlhsh_level_insert(lhq, slot, key, nlvl);
        }

        return ret;
    }

    /* The last allowed level, only buckets may be allocated here. */

    return nxt_lvlhsh_new_bucket(lhq, bkt);
}


static nxt_int_t
nxt_lvlhsh_convert_bucket_to_level(nxt_lvlhsh_query_t *lhq, void **slot,
    nxt_uint_t nlvl, uint32_t *bucket)
{
    void                      *lvl, **level;
    uint32_t                  *e, *end, key;
    nxt_int_t                 ret;
    nxt_uint_t                i, shift, size;
    nxt_lvlhsh_query_t        q;
    const nxt_lvlhsh_proto_t  *proto;

    proto = lhq->proto;
    size = nxt_lvlhsh_level_size(proto, nlvl);

    lvl = proto->alloc(lhq->pool, size * (sizeof(void *)));

    if (nxt_slow_path(lvl == NULL)) {
        return NXT_ERROR;
    }

    nxt_memzero(lvl, size * (sizeof(void *)));

    level = lvl;
    shift = 0;

    for (i = 0; i < nlvl; i++) {
        /*
         * Using SIMD operations in this trivial loop with maximum
         * 8 iterations may increase code size by 170 bytes.
         */
        nxt_pragma_loop_disable_vectorization;

        shift += proto->shift[i];
    }

    end = nxt_lvlhsh_bucket_end(proto, bucket);

    for (e = bucket; e < end; e += NXT_LVLHSH_ENTRY_SIZE) {

        q.proto = proto;
        q.pool = lhq->pool;
        q.value = nxt_lvlhsh_entry_value(e);
        key = nxt_lvlhsh_entry_key(e);
        q.key_hash = key;

        ret = nxt_lvlhsh_level_convertion_insert(&q, &lvl, key >> shift, nlvl);

        if (nxt_slow_path(ret != NXT_OK)) {
            return nxt_lvlhsh_free_level(lhq, level, size);
        }
    }

    *slot = lvl;

    proto->free(lhq->pool, bucket);

    return NXT_OK;
}


static nxt_int_t
nxt_lvlhsh_level_convertion_insert(nxt_lvlhsh_query_t *lhq, void **parent,
    uint32_t key, nxt_uint_t nlvl)
{
    void        **slot, **lvl;
    nxt_int_t   ret;
    uintptr_t   mask;
    nxt_uint_t  shift;

    shift = lhq->proto->shift[nlvl];
    mask = ((uintptr_t) 1 << shift) - 1;

    lvl = nxt_lvlhsh_level(*parent, mask);
    slot = &lvl[key & mask];

    if (*slot == NULL) {
        ret = nxt_lvlhsh_new_bucket(lhq, slot);

        if (nxt_fast_path(ret == NXT_OK)) {
            nxt_lvlhsh_count_inc(*parent);
        }

        return ret;
    }

    /* Only backets can be here. */

    return nxt_lvlhsh_bucket_convertion_insert(lhq, slot, key >> shift, nlvl);
}


/*
 * The special bucket insertion procedure is required because during
 * convertion lhq->key contains garbage values and the test function
 * cannot be called.  Besides, the procedure can be simpler because
 * a new entry is inserted just after occupied entries.
 */

static nxt_int_t
nxt_lvlhsh_bucket_convertion_insert(nxt_lvlhsh_query_t *lhq, void **slot,
    uint32_t key, nxt_int_t nlvl)
{
    void                      **bkt;
    uint32_t                  *bucket, *e;
    nxt_int_t                 ret;
    uintptr_t                 n;
    const nxt_lvlhsh_proto_t  *proto;

    bkt = slot;
    proto = lhq->proto;

    do {
        bucket = nxt_lvlhsh_bucket(proto, *bkt);
        n = nxt_lvlhsh_bucket_entries(proto, *bkt);
        e = bucket + n * NXT_LVLHSH_ENTRY_SIZE;

        if (nxt_fast_path(e < nxt_lvlhsh_bucket_end(proto, bucket))) {

            nxt_lvlhsh_set_entry_value(e, lhq->value);
            nxt_lvlhsh_set_entry_key(e, lhq->key_hash);
            nxt_lvlhsh_count_inc(*bkt);

            return NXT_OK;
        }

        bkt = nxt_lvlhsh_next_bucket(proto, bucket);

    } while (*bkt != NULL);

    /* All buckets are full. */

    nlvl++;

    if (nxt_fast_path(proto->shift[nlvl] != 0)) {

        ret = nxt_lvlhsh_convert_bucket_to_level(lhq, slot, nlvl, bucket);

        if (nxt_fast_path(ret == NXT_OK)) {
            return nxt_lvlhsh_level_insert(lhq, slot, key, nlvl);
        }

        return ret;
    }

    /* The last allowed level, only buckets may be allocated here. */

    return nxt_lvlhsh_new_bucket(lhq, bkt);
}


static nxt_int_t
nxt_lvlhsh_free_level(nxt_lvlhsh_query_t *lhq, void **level, nxt_uint_t size)
{
    nxt_uint_t                i;
    const nxt_lvlhsh_proto_t  *proto;

    proto = lhq->proto;

    for (i = 0; i < size; i++) {

        if (level[i] != NULL) {
            /*
             * Chained buckets are not possible here, since even
             * in the worst case one bucket cannot be converted
             * in two chained buckets but remains the same bucket.
             */
            proto->free(lhq->pool, nxt_lvlhsh_bucket(proto, level[i]));
        }
    }

    proto->free(lhq->pool, level);

    return NXT_ERROR;
}


nxt_int_t
nxt_lvlhsh_delete(nxt_lvlhsh_t *lh, nxt_lvlhsh_query_t *lhq)
{
    if (nxt_fast_path(lh->slot != NULL)) {

        if (nxt_lvlhsh_is_bucket(lh->slot)) {
            return nxt_lvlhsh_bucket_delete(lhq, &lh->slot);
        }

        return nxt_lvlhsh_level_delete(lhq, &lh->slot, lhq->key_hash, 0);
    }

    return NXT_DECLINED;
}


static nxt_int_t
nxt_lvlhsh_level_delete(nxt_lvlhsh_query_t *lhq, void **parent, uint32_t key,
    nxt_uint_t nlvl)
{
    void        **slot, **lvl;
    uintptr_t   mask;
    nxt_int_t   ret;
    nxt_uint_t  shift;

    shift = lhq->proto->shift[nlvl];
    mask = ((uintptr_t) 1 << shift) - 1;

    lvl = nxt_lvlhsh_level(*parent, mask);
    slot = &lvl[key & mask];

    if (*slot != NULL) {

        if (nxt_lvlhsh_is_bucket(*slot)) {
            ret = nxt_lvlhsh_bucket_delete(lhq, slot);

        } else {
            key >>= shift;
            ret = nxt_lvlhsh_level_delete(lhq, slot, key, nlvl + 1);
        }

        if (*slot == NULL) {
            nxt_lvlhsh_count_dec(*parent);

            if (nxt_lvlhsh_level_entries(*parent, mask) == 0) {
                *parent = NULL;
                lhq->proto->free(lhq->pool, lvl);
            }
        }

        return ret;
    }

    return NXT_DECLINED;
}


static nxt_int_t
nxt_lvlhsh_bucket_delete(nxt_lvlhsh_query_t *lhq, void **bkt)
{
    void                      *value;
    uint32_t                  *bucket, *e;
    uintptr_t                 n;
    const nxt_lvlhsh_proto_t  *proto;

    proto = lhq->proto;

    do {
        bucket = nxt_lvlhsh_bucket(proto, *bkt);
        n = nxt_lvlhsh_bucket_entries(proto, *bkt);
        e = bucket;

        do {
            if (nxt_lvlhsh_valid_entry(e)) {

                if (nxt_lvlhsh_entry_key(e) == lhq->key_hash) {

                    value = nxt_lvlhsh_entry_value(e);

                    if (proto->test(lhq, value) == NXT_OK) {

                        if (nxt_lvlhsh_bucket_entries(proto, *bkt) == 1) {
                            *bkt = *nxt_lvlhsh_next_bucket(proto, bucket);
                            proto->free(lhq->pool, bucket);

                        } else {
                            nxt_lvlhsh_count_dec(*bkt);
                            nxt_lvlhsh_set_entry_value(e, NULL);
                        }

                        lhq->value = value;

                        return NXT_OK;
                    }
                }

                n--;
            }

            e += NXT_LVLHSH_ENTRY_SIZE;

        } while (n != 0);

        bkt = nxt_lvlhsh_next_bucket(proto, bucket);

    } while (*bkt != NULL);

    return NXT_DECLINED;
}


void *
nxt_lvlhsh_each(nxt_lvlhsh_t *lh, nxt_lvlhsh_each_t *lhe)
{
    void  **slot;

    if (lhe->bucket == NXT_LVLHSH_BUCKET_DONE) {
        slot = lh->slot;

        if (nxt_lvlhsh_is_bucket(slot)) {
            return NULL;
        }

    } else {
        if (nxt_slow_path(lhe->bucket == NULL)) {

            /* The first iteration only. */

            slot = lh->slot;

            if (slot == NULL) {
                return NULL;
            }

            if (!nxt_lvlhsh_is_bucket(slot)) {
                lhe->current = 0;
                goto level;
            }

            lhe->bucket = nxt_lvlhsh_bucket(lhe->proto, slot);
            lhe->entries = nxt_lvlhsh_bucket_entries(lhe->proto, slot);
            lhe->entry = 0;
        }

        return nxt_lvlhsh_bucket_each(lhe);
    }

level:

    return nxt_lvlhsh_level_each(lhe, slot, 0, 0);
}


static void *
nxt_lvlhsh_level_each(nxt_lvlhsh_each_t *lhe, void **level, nxt_uint_t nlvl,
    nxt_uint_t shift)
{
    void        **slot, *value;
    uintptr_t   mask;
    nxt_uint_t  n, level_shift;

    level_shift = lhe->proto->shift[nlvl];
    mask = ((uintptr_t) 1 << level_shift) - 1;

    level = nxt_lvlhsh_level(level, mask);

    do {
        n = (lhe->current >> shift) & mask;
        slot = level[n];

        if (slot != NULL) {
            if (nxt_lvlhsh_is_bucket(slot)) {

                if (lhe->bucket != NXT_LVLHSH_BUCKET_DONE) {

                    lhe->bucket = nxt_lvlhsh_bucket(lhe->proto, slot);
                    lhe->entries = nxt_lvlhsh_bucket_entries(lhe->proto, slot);
                    lhe->entry = 0;

                    return nxt_lvlhsh_bucket_each(lhe);
                }

                lhe->bucket = NULL;

            } else {
                value = nxt_lvlhsh_level_each(lhe, slot, nlvl + 1,
                                              shift + level_shift);
                if (value != NULL) {
                    return value;
                }
            }
        }

        lhe->current &= ~(mask << shift);
        n = ((n + 1) & mask) << shift;
        lhe->current |= n;

    } while (n != 0);

    return NULL;
}


static nxt_noinline void *
nxt_lvlhsh_bucket_each(nxt_lvlhsh_each_t *lhe)
{
    void      *value, **next;
    uint32_t  *bucket;

    /* At least one valid entry must present here. */
    do {
        bucket = &lhe->bucket[lhe->entry];
        lhe->entry += NXT_LVLHSH_ENTRY_SIZE;

    } while (nxt_lvlhsh_free_entry(bucket));

    value = nxt_lvlhsh_entry_value(bucket);

    lhe->entries--;

    if (lhe->entries == 0) {
        next = *nxt_lvlhsh_next_bucket(lhe->proto, lhe->bucket);

        lhe->bucket = (next == NULL) ? NXT_LVLHSH_BUCKET_DONE
                                     : nxt_lvlhsh_bucket(lhe->proto, next);

        lhe->entries = nxt_lvlhsh_bucket_entries(lhe->proto, next);
        lhe->entry = 0;
    }

    return value;
}


void *
nxt_lvlhsh_peek(nxt_lvlhsh_t *lh, const nxt_lvlhsh_proto_t *proto)
{
    void               **slot;
    nxt_lvlhsh_peek_t  peek;

    slot = lh->slot;

    if (slot != NULL) {

        peek.proto = proto;
        peek.retrieve = 0;

        if (nxt_lvlhsh_is_bucket(slot)) {
            return nxt_lvlhsh_bucket_peek(&peek, &lh->slot);
        }

        return nxt_lvlhsh_level_peek(&peek, &lh->slot, 0);
    }

    return NULL;
}


static void *
nxt_lvlhsh_level_peek(nxt_lvlhsh_peek_t *peek, void **parent, nxt_uint_t nlvl)
{
    void        **slot, **level, *value;
    uintptr_t   mask;
    nxt_uint_t  n, shift;

    shift = peek->proto->shift[nlvl];
    mask = ((uintptr_t) 1 << shift) - 1;

    level = nxt_lvlhsh_level(*parent, mask);

    n = 0;

    /* At least one valid level slot must present here. */

    for ( ;; ) {
        slot = &level[n];

        if (*slot != NULL) {

            if (nxt_lvlhsh_is_bucket(*slot)) {
                value = nxt_lvlhsh_bucket_peek(peek, slot);

            } else {
                value = nxt_lvlhsh_level_peek(peek, slot, nlvl + 1);
            }

            /*
             * Checking peek->retrieve is not required here because
             * there can not be empty slots during peeking.
             */
            if (*slot == NULL) {
                nxt_lvlhsh_count_dec(*parent);

                if (nxt_lvlhsh_level_entries(*parent, mask) == 0) {
                    *parent = NULL;
                    peek->proto->free(peek->pool, level);
                }
            }

            return value;
        }

        n++;
    }
}


static nxt_noinline void *
nxt_lvlhsh_bucket_peek(nxt_lvlhsh_peek_t *peek, void **bkt)
{
    void                      *value;
    uint32_t                  *bucket, *entry;
    const nxt_lvlhsh_proto_t  *proto;

    bucket = nxt_lvlhsh_bucket(peek->proto, *bkt);

    /* At least one valid entry must present here. */

    for (entry = bucket;
         nxt_lvlhsh_free_entry(entry);
         entry += NXT_LVLHSH_ENTRY_SIZE)
    {
        /* void */
    }

    value = nxt_lvlhsh_entry_value(entry);

    if (peek->retrieve) {
        proto = peek->proto;

        if (nxt_lvlhsh_bucket_entries(proto, *bkt) == 1) {
            *bkt = *nxt_lvlhsh_next_bucket(proto, bucket);
            proto->free(peek->pool, bucket);

        } else {
            nxt_lvlhsh_count_dec(*bkt);
            nxt_lvlhsh_set_entry_value(entry, NULL);
        }
    }

    return value;
}


void *
nxt_lvlhsh_retrieve(nxt_lvlhsh_t *lh, const nxt_lvlhsh_proto_t *proto,
    void *pool)
{
    void               **slot;
    nxt_lvlhsh_peek_t  peek;

    slot = lh->slot;

    if (slot != NULL) {

        peek.proto = proto;
        peek.pool = pool;
        peek.retrieve = 1;

        if (nxt_lvlhsh_is_bucket(slot)) {
            return nxt_lvlhsh_bucket_peek(&peek, &lh->slot);
        }

        return nxt_lvlhsh_level_peek(&peek, &lh->slot, 0);
    }

    return NULL;
}
