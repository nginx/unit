
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_TLS_H_INCLUDED_
#define _NXT_TLS_H_INCLUDED_


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


typedef struct nxt_tls_conf_s     nxt_tls_conf_t;


typedef struct {
    nxt_int_t                     (*library_init)(nxt_task_t *task);
    void                          (*library_free)(nxt_task_t *task);

    nxt_int_t                     (*server_init)(nxt_task_t *task,
                                      nxt_tls_conf_t *conf);
    void                          (*server_free)(nxt_task_t *task,
                                      nxt_tls_conf_t *conf);
} nxt_tls_lib_t;


struct nxt_tls_conf_s {
    void                          *ctx;
    void                          (*conn_init)(nxt_task_t *task,
                                      nxt_tls_conf_t *conf, nxt_conn_t *c);

    const nxt_tls_lib_t           *lib;

    nxt_fd_t                      chain_file;
    char                          *ciphers;

    char                          *ca_certificate;

    size_t                        buffer_size;
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
