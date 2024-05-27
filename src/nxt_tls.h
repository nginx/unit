
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_TLS_H_INCLUDED_
#define _NXT_TLS_H_INCLUDED_


#include <nxt_conf.h>


/*
 * The SSL/TLS libraries lack vector I/O interface yet add noticeable
 * overhead to each SSL/TLS record so buffering allows to decrease the
 * overhead.  The typical overhead size is about 30 bytes, however, TLS
 * supports also random padding up to 255 bytes.  The maximum SSLv3/TLS
 * record size is 16K.  However, large records increase decryption latency.
 * 4K is good compromise between 1-6% of SSL/TLS overhead and the latency.
 * 4K buffer allows to send one SSL/TLS record (4096-bytes data and up to
 * 224-bytes overhead) in three 1440-bytes TCP/IPv4 packets with timestamps
 * and compatible with tunnels.
 */

#define NXT_TLS_BUFFER_SIZE       4096


typedef struct nxt_tls_conf_s         nxt_tls_conf_t;
typedef struct nxt_tls_bundle_conf_s  nxt_tls_bundle_conf_t;
typedef struct nxt_tls_init_s         nxt_tls_init_t;
typedef struct nxt_tls_ticket_s       nxt_tls_ticket_t;
typedef struct nxt_tls_tickets_s      nxt_tls_tickets_t;

typedef struct {
    nxt_int_t                     (*library_init)(nxt_task_t *task);
    void                          (*library_free)(nxt_task_t *task);

    nxt_int_t                     (*server_init)(nxt_task_t *task, nxt_mp_t *mp,
                                      nxt_tls_init_t *tls_init,
                                      nxt_bool_t last);
    void                          (*server_free)(nxt_task_t *task,
                                      nxt_tls_conf_t *conf);
} nxt_tls_lib_t;


typedef struct {
    nxt_tls_bundle_conf_t         *bundle;

    nxt_str_t                     name;
} nxt_tls_bundle_hash_item_t;


struct nxt_tls_bundle_conf_s {
    void                          *ctx;

    nxt_fd_t                      chain_file;
    nxt_str_t                     name;

    nxt_tls_bundle_conf_t         *next;
};


struct nxt_tls_conf_s {
    nxt_tls_bundle_conf_t         *bundle;
    nxt_lvlhsh_t                  bundle_hash;

    nxt_tls_tickets_t             *tickets;

    void                          (*conn_init)(nxt_task_t *task,
                                      nxt_tls_conf_t *conf, nxt_conn_t *c);

    const nxt_tls_lib_t           *lib;

    char                          *ciphers;

    char                          *ca_certificate;

    size_t                        buffer_size;

    uint8_t                       no_wait_shutdown;  /* 1 bit */
};


struct nxt_tls_init_s {
    size_t                        cache_size;
    nxt_time_t                    timeout;
    nxt_conf_value_t              *conf_cmds;
    nxt_conf_value_t              *tickets_conf;

    nxt_tls_conf_t                *conf;
};


#if (NXT_HAVE_OPENSSL)
extern const nxt_tls_lib_t        nxt_openssl_lib;

void nxt_cdecl nxt_openssl_log_error(nxt_task_t *task, nxt_uint_t level,
    const char *fmt, ...);
u_char *nxt_openssl_copy_error(u_char *p, u_char *end);
#endif

#if (NXT_HAVE_GNUTLS)
extern const nxt_tls_lib_t        nxt_gnutls_lib;
#endif

#if (NXT_HAVE_CYASSL)
extern const nxt_tls_lib_t        nxt_cyassl_lib;
#endif

#if (NXT_HAVE_POLARSSL)
extern const nxt_tls_lib_t        nxt_polar_lib;
#endif


#endif /* _NXT_TLS_H_INCLUDED_ */
