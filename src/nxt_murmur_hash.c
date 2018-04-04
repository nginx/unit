
/*
 * The code is based on the code by Austin Appleby,
 * released to the public domain.
 */

#include <nxt_main.h>


uint32_t
nxt_murmur_hash2(const void *data, size_t len)
{
    uint32_t        h, k;
    const u_char    *p;
    const uint32_t  m = 0x5BD1E995;

    p = data;
    h = 0 ^ (uint32_t) len;

    while (len >= 4) {
        k  = p[0];
        k |= p[1] << 8;
        k |= p[2] << 16;
        k |= p[3] << 24;

        k *= m;
        k ^= k >> 24;
        k *= m;

        h *= m;
        h ^= k;

        p += 4;
        len -= 4;
    }

    switch (len) {
    case 3:
        h ^= p[2] << 16;
        /* Fall through. */
    case 2:
        h ^= p[1] << 8;
        /* Fall through. */
    case 1:
        h ^= p[0];
        h *= m;
    }

    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return h;
}


/* The MurmurHash2 for fixed 4 byte length. */

uint32_t
nxt_murmur_hash2_uint32(const void *data)
{
    uint32_t        h, k;
    const u_char    *p;
    const uint32_t  m = 0x5BD1E995;

    p = data;

    k  = p[0];
    k |= p[1] << 8;
    k |= p[2] << 16;
    k |= p[3] << 24;

    k *= m;
    k ^= k >> 24;
    k *= m;

    h = 0 ^ 4;
    h *= m;
    h ^= k;

    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return h;
}
