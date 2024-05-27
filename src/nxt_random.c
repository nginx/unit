
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */


#include <nxt_main.h>


/*
 * The pseudorandom generator based on OpenBSD arc4random.  Although it is
 * usually stated that arc4random uses RC4 pseudorandom generation algorithm
 * they are actually different in nxt_random_add().
 */


#define NXT_RANDOM_KEY_SIZE  128


nxt_inline void nxt_random_start_schedule(nxt_random_t *r);
static void nxt_random_stir(nxt_random_t *r);
static void nxt_random_add(nxt_random_t *r, const u_char *key, uint32_t len);
nxt_inline uint8_t nxt_random_byte(nxt_random_t *r);


void
nxt_random_init(nxt_random_t *r)
{
    nxt_random_start_schedule(r);

    nxt_random_stir(r);
}


nxt_inline void
nxt_random_start_schedule(nxt_random_t *r)
{
    nxt_uint_t  i;

    r->i = 0;
    r->j = 0;

    for (i = 0; i < 256; i++) {
        r->s[i] = i;
    }
}


static void
nxt_random_stir(nxt_random_t *r)
{
    int             fd;
    ssize_t         n;
    struct timeval  tv;
    union {
        uint32_t    value[4];
        u_char      bytes[NXT_RANDOM_KEY_SIZE];
    } key;

#if (NXT_HAVE_GETRANDOM)

    n = getrandom(&key, NXT_RANDOM_KEY_SIZE, 0);

#elif (NXT_HAVE_LINUX_SYS_GETRANDOM)

    /* Linux 3.17 SYS_getrandom. */

    n = syscall(SYS_getrandom, &key, NXT_RANDOM_KEY_SIZE, 0);

#elif (NXT_HAVE_GETENTROPY || NXT_HAVE_GETENTROPY_SYS_RANDOM)

    n = 0;

    if (getentropy(&key, NXT_RANDOM_KEY_SIZE) == 0) {
        n = NXT_RANDOM_KEY_SIZE;
    }

#else

    n = 0;

#endif

    if (n != NXT_RANDOM_KEY_SIZE) {
        fd = open("/dev/urandom", O_RDONLY);

        if (fd >= 0) {
            n = read(fd, &key, NXT_RANDOM_KEY_SIZE);
            (void) close(fd);
        }
    }

    if (n != NXT_RANDOM_KEY_SIZE) {
        (void) gettimeofday(&tv, NULL);

        /* XOR with stack garbage. */

        key.value[0] ^= tv.tv_usec;
        key.value[1] ^= tv.tv_sec;
        key.value[2] ^= nxt_pid;
        key.value[3] ^= (uintptr_t) nxt_thread_tid(nxt_thread());
    }

    nxt_random_add(r, key.bytes, NXT_RANDOM_KEY_SIZE);

    /* Drop the first 3072 bytes. */
    for (n = 3072; n != 0; n--) {
        (void) nxt_random_byte(r);
    }

    /* Stir again after 1,600,000 bytes. */
    r->count = 400000;
}


static void
nxt_random_add(nxt_random_t *r, const u_char *key, uint32_t len)
{
    uint8_t   val;
    uint32_t  n;

    for (n = 0; n < 256; n++) {
        val = r->s[r->i];
        r->j += val + key[n % len];

        r->s[r->i] = r->s[r->j];
        r->s[r->j] = val;

        r->i++;
    }

    /* This index is not decremented in RC4 algorithm. */
    r->i--;

    r->j = r->i;
}


uint32_t
nxt_random(nxt_random_t *r)
{
    uint32_t  val;

    r->count--;

    if (r->count <= 0) {
        nxt_random_stir(r);
    }

    val  = (uint32_t) nxt_random_byte(r) << 24;
    val |= (uint32_t) nxt_random_byte(r) << 16;
    val |= (uint32_t) nxt_random_byte(r) << 8;
    val |= (uint32_t) nxt_random_byte(r);

    return val;
}


nxt_inline uint8_t
nxt_random_byte(nxt_random_t *r)
{
    uint8_t  si, sj;

    r->i++;
    si = r->s[r->i];
    r->j += si;

    sj = r->s[r->j];
    r->s[r->i] = sj;
    r->s[r->j] = si;

    si += sj;

    return r->s[si];
}


#if (NXT_TESTS)

nxt_int_t
nxt_random_test(nxt_thread_t *thr)
{
    nxt_uint_t    n;
    nxt_random_t  r;

    nxt_random_start_schedule(&r);

    r.count = 400000;

    nxt_random_add(&r, (u_char *) "arc4random", nxt_length("arc4random"));

    /*
     * Test arc4random() numbers.
     * RC4 pseudorandom numbers would be 0x4642AFC3 and 0xBAF0FFF0.
     */

    if (nxt_random(&r) == 0xD6270B27) {

        for (n = 100000; n != 0; n--) {
            (void) nxt_random(&r);
        }

        if (nxt_random(&r) == 0x6FCAE186) {
            nxt_log_error(NXT_LOG_NOTICE, thr->log, "arc4random test passed");

            return NXT_OK;
        }
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "arc4random test failed");

    return NXT_ERROR;
}

#endif
