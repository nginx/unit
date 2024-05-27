
/*
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_conf.h>
#include <nxt_cert.h>

#include <dirent.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/err.h>


struct nxt_cert_s {
    EVP_PKEY          *key;
    nxt_uint_t        count;
    X509              *chain[];
};


typedef struct {
    nxt_str_t         name;
    nxt_conf_value_t  *value;
    nxt_mp_t          *mp;
} nxt_cert_info_t;


typedef struct {
    nxt_str_t         name;
    nxt_fd_t          fd;
} nxt_cert_item_t;


static nxt_cert_t *nxt_cert_fd(nxt_task_t *task, nxt_fd_t fd);
static nxt_cert_t *nxt_cert_bio(nxt_task_t *task, BIO *bio);
static int nxt_nxt_cert_pem_suffix(char *pem_str, const char *suffix);

static nxt_conf_value_t *nxt_cert_details(nxt_mp_t *mp, nxt_cert_t *cert);
static nxt_conf_value_t *nxt_cert_name_details(nxt_mp_t *mp, X509 *x509,
    nxt_bool_t issuer);
static nxt_conf_value_t *nxt_cert_alt_names_details(nxt_mp_t *mp,
    STACK_OF(GENERAL_NAME) *alt_names);
static void nxt_cert_buf_completion(nxt_task_t *task, void *obj, void *data);


static nxt_lvlhsh_t  nxt_cert_info;


nxt_cert_t *
nxt_cert_mem(nxt_task_t *task, nxt_buf_mem_t *mbuf)
{
    BIO         *bio;
    nxt_cert_t  *cert;

    bio = BIO_new_mem_buf(mbuf->pos, nxt_buf_mem_used_size(mbuf));
    if (nxt_slow_path(bio == NULL)) {
        nxt_openssl_log_error(task, NXT_LOG_ALERT, "BIO_new_mem_buf() failed");
        return NULL;
    }

    cert = nxt_cert_bio(task, bio);

    BIO_free(bio);

    return cert;
}


static nxt_cert_t *
nxt_cert_fd(nxt_task_t *task, nxt_fd_t fd)
{
    BIO         *bio;
    nxt_cert_t  *cert;

    bio = BIO_new_fd(fd, 0);
    if (nxt_slow_path(bio == NULL)) {
        nxt_openssl_log_error(task, NXT_LOG_ALERT, "BIO_new_fd() failed");
        return NULL;
    }

    cert = nxt_cert_bio(task, bio);

    BIO_free(bio);

    return cert;
}


static nxt_cert_t *
nxt_cert_bio(nxt_task_t *task, BIO *bio)
{
    int                         ret, suffix, key_id;
    long                        length, reason;
    char                        *type, *header;
    X509                        *x509;
    EVP_PKEY                    *key;
    nxt_uint_t                  nalloc;
    nxt_cert_t                  *cert, *new_cert;
    u_char                      *data;
    const u_char                *data_copy;
    PKCS8_PRIV_KEY_INFO         *p8inf;
    const EVP_PKEY_ASN1_METHOD  *ameth;

    nalloc = 4;

    cert = nxt_zalloc(sizeof(nxt_cert_t) + nalloc * sizeof(X509 *));
    if (cert == NULL) {
        return NULL;
    }

    for ( ;; ) {
        ret = PEM_read_bio(bio, &type, &header, &data, &length);

        if (ret == 0) {
            reason = ERR_GET_REASON(ERR_peek_last_error());
            if (reason != PEM_R_NO_START_LINE) {
                nxt_openssl_log_error(task, NXT_LOG_ALERT,
                                      "PEM_read_bio() failed");
                goto fail;
            }

            ERR_clear_error();
            break;
        }

        nxt_debug(task, "PEM type: \"%s\"", type);

        key = NULL;
        x509 = NULL;
/*
        EVP_CIPHER_INFO  cipher;

        if (PEM_get_EVP_CIPHER_INFO(header, &cipher) != 0) {
            nxt_alert(task, "encrypted PEM isn't supported");
            goto done;
        }
*/
        if (nxt_strcmp(type, PEM_STRING_PKCS8) == 0) {
            nxt_alert(task, "PEM PKCS8 isn't supported");
            goto done;
        }

        if (nxt_strcmp(type, PEM_STRING_PKCS8INF) == 0) {
            data_copy = data;

            p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &data_copy, length);

            if (p8inf == NULL) {
                nxt_openssl_log_error(task, NXT_LOG_ALERT,
                                      "d2i_PKCS8_PRIV_KEY_INFO() failed");
                goto done;
            }

            key = EVP_PKCS82PKEY(p8inf);

            PKCS8_PRIV_KEY_INFO_free(p8inf);
            goto done;
        }

        suffix = nxt_nxt_cert_pem_suffix(type, PEM_STRING_PKCS8INF);

        if (suffix != 0) {

            ameth = EVP_PKEY_asn1_find_str(NULL, type, suffix);
            if (ameth == NULL) {
                nxt_openssl_log_error(task, NXT_LOG_ALERT,
                                      "EVP_PKEY_asn1_find_str() failed");
                goto done;
            }

            EVP_PKEY_asn1_get0_info(&key_id, NULL, NULL, NULL, NULL, ameth);

            data_copy = data;

            key = d2i_PrivateKey(key_id, NULL, &data_copy, length);
            goto done;
        }

        if (nxt_strcmp(type, PEM_STRING_X509) == 0
            || nxt_strcmp(type, PEM_STRING_X509_OLD) == 0)
        {
            data_copy = data;

            x509 = d2i_X509(NULL, &data_copy, length);
            if (x509 == NULL) {
                nxt_openssl_log_error(task, NXT_LOG_ALERT,
                                      "d2i_X509() failed");
            }

            goto done;
        }

        if (nxt_strcmp(type, PEM_STRING_X509_TRUSTED) == 0) {
            data_copy = data;

            x509 = d2i_X509_AUX(NULL, &data_copy, length);
            if (x509 == NULL) {
                nxt_openssl_log_error(task, NXT_LOG_ALERT,
                                      "d2i_X509_AUX() failed");
            }

            goto done;
        }

        nxt_alert(task, "unsupported PEM type: \"%s\"", type);

    done:

        OPENSSL_free(data);
        OPENSSL_free(header);
        OPENSSL_free(type);

        if (key != NULL) {
            if (cert->key != NULL) {
                EVP_PKEY_free(key);
                nxt_alert(task, "multiple private keys in PEM");
                goto fail;
            }

            cert->key = key;
            continue;
        }

        if (x509 != NULL) {

            if (cert->count == nalloc) {
                nalloc += 4;

                new_cert = nxt_realloc(cert, sizeof(nxt_cert_t)
                                             + nalloc * sizeof(X509 *));
                if (new_cert == NULL) {
                    X509_free(x509);
                    goto fail;
                }

                cert = new_cert;
            }

            cert->chain[cert->count++] = x509;
            continue;
        }

        goto fail;
    }

    if (cert->key == NULL) {
        nxt_alert(task, "no key found");
        goto fail;
    }

    if (cert->count == 0) {
        nxt_alert(task, "no certificates found");
        goto fail;
    }

    return cert;

fail:

    nxt_cert_destroy(cert);

    return NULL;
}


static int
nxt_nxt_cert_pem_suffix(char *pem_str, const char *suffix)
{
    char        *p;
    nxt_uint_t  pem_len, suffix_len;

    pem_len = strlen(pem_str);
    suffix_len = strlen(suffix);

    if (suffix_len + 1 >= pem_len) {
        return 0;
    }

    p = pem_str + pem_len - suffix_len;

    if (nxt_strcmp(p, suffix) != 0) {
        return 0;
    }

    p--;

    if (*p != ' ') {
        return 0;
    }

    return p - pem_str;
}


void
nxt_cert_destroy(nxt_cert_t *cert)
{
    nxt_uint_t  i;

    EVP_PKEY_free(cert->key);

    for (i = 0; i != cert->count; i++) {
        X509_free(cert->chain[i]);
    }

    nxt_free(cert);
}



static nxt_int_t
nxt_cert_info_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_cert_info_t  *info;

    info = data;

    if (nxt_strcasestr_eq(&lhq->key, &info->name)) {
        return NXT_OK;
    }

    return NXT_DECLINED;
}


static const nxt_lvlhsh_proto_t  nxt_cert_info_hash_proto
    nxt_aligned(64) =
{
    NXT_LVLHSH_DEFAULT,
    nxt_cert_info_hash_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};


void
nxt_cert_info_init(nxt_task_t *task, nxt_array_t *certs)
{
    uint32_t         i;
    nxt_cert_t       *cert;
    nxt_cert_item_t  *items;

    for (items = certs->elts, i = 0; i < certs->nelts; i++) {
        cert = nxt_cert_fd(task, items[i].fd);

        if (nxt_slow_path(cert == NULL)) {
            continue;
        }

        (void) nxt_cert_info_save(&items[i].name, cert);

        nxt_cert_destroy(cert);
    }
}


nxt_int_t
nxt_cert_info_save(nxt_str_t *name, nxt_cert_t *cert)
{
    nxt_mp_t            *mp;
    nxt_int_t           ret;
    nxt_cert_info_t     *info;
    nxt_conf_value_t    *value;
    nxt_lvlhsh_query_t  lhq;

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (nxt_slow_path(mp == NULL)) {
        return NXT_ERROR;
    }

    info = nxt_mp_get(mp, sizeof(nxt_cert_info_t));
    if (nxt_slow_path(info == NULL)) {
        goto fail;
    }

    name = nxt_str_dup(mp, &info->name, name);
    if (nxt_slow_path(name == NULL)) {
        goto fail;
    }

    value = nxt_cert_details(mp, cert);
    if (nxt_slow_path(value == NULL)) {
        goto fail;
    }

    info->mp = mp;
    info->value = value;

    lhq.key_hash = nxt_djb_hash(name->start, name->length);
    lhq.replace = 1;
    lhq.key = *name;
    lhq.value = info;
    lhq.proto = &nxt_cert_info_hash_proto;

    ret = nxt_lvlhsh_insert(&nxt_cert_info, &lhq);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    if (lhq.value != info) {
        info = lhq.value;
        nxt_mp_destroy(info->mp);
    }

    return NXT_OK;

fail:

    nxt_mp_destroy(mp);
    return NXT_ERROR;
}


nxt_conf_value_t *
nxt_cert_info_get(nxt_str_t *name)
{
    nxt_int_t           ret;
    nxt_cert_info_t     *info;
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = nxt_djb_hash(name->start, name->length);
    lhq.key = *name;
    lhq.proto = &nxt_cert_info_hash_proto;

    ret = nxt_lvlhsh_find(&nxt_cert_info, &lhq);
    if (ret != NXT_OK) {
        return NULL;
    }

    info = lhq.value;

    return info->value;
}


nxt_conf_value_t *
nxt_cert_info_get_all(nxt_mp_t *mp)
{
    uint32_t           i;
    nxt_cert_info_t    *info;
    nxt_conf_value_t   *all;
    nxt_lvlhsh_each_t  lhe;

    nxt_lvlhsh_each_init(&lhe, &nxt_cert_info_hash_proto);

    i = 0;

    for ( ;; ) {
        info = nxt_lvlhsh_each(&nxt_cert_info, &lhe);

        if (info == NULL) {
            break;
        }

        i++;
    }

    all = nxt_conf_create_object(mp, i);
    if (nxt_slow_path(all == NULL)) {
        return NULL;
    }

    nxt_lvlhsh_each_init(&lhe, &nxt_cert_info_hash_proto);

    i = 0;

    for ( ;; ) {
        info = nxt_lvlhsh_each(&nxt_cert_info, &lhe);

        if (info == NULL) {
            break;
        }

        nxt_conf_set_member(all, &info->name, info->value, i);

        i++;
    }

    return all;
}


static nxt_conf_value_t *
nxt_cert_details(nxt_mp_t *mp, nxt_cert_t *cert)
{
    BIO               *bio;
    X509              *x509;
    u_char            *end;
    EVP_PKEY          *key;
    ASN1_TIME         *asn1_time;
    nxt_str_t         str;
    nxt_int_t         ret;
    nxt_uint_t        i;
    nxt_conf_value_t  *object, *chain, *element, *value;
    u_char            buf[256];

    static nxt_str_t key_str = nxt_string("key");
    static nxt_str_t chain_str = nxt_string("chain");
    static nxt_str_t since_str = nxt_string("since");
    static nxt_str_t until_str = nxt_string("until");
    static nxt_str_t issuer_str = nxt_string("issuer");
    static nxt_str_t subject_str = nxt_string("subject");
    static nxt_str_t validity_str = nxt_string("validity");

    object = nxt_conf_create_object(mp, 2);
    if (nxt_slow_path(object == NULL)) {
        return NULL;
    }

    if (cert->key != NULL) {
        key = cert->key;

        switch (EVP_PKEY_base_id(key)) {
        case EVP_PKEY_RSA:
            end = nxt_sprintf(buf, buf + sizeof(buf), "RSA (%d bits)",
                              EVP_PKEY_bits(key));

            str.length = end - buf;
            str.start = buf;
            break;

        case EVP_PKEY_DH:
            end = nxt_sprintf(buf, buf + sizeof(buf), "DH (%d bits)",
                              EVP_PKEY_bits(key));

            str.length = end - buf;
            str.start = buf;
            break;

        case EVP_PKEY_EC:
            nxt_str_set(&str, "ECDH");
            break;

        default:
            nxt_str_set(&str, "unknown");
        }

        ret = nxt_conf_set_member_string_dup(object, mp, &key_str, &str, 0);

        if (nxt_slow_path(ret != NXT_OK)) {
            return NULL;
        }

    } else {
        nxt_conf_set_member_null(object, &key_str, 0);
    }

    chain = nxt_conf_create_array(mp, cert->count);
    if (nxt_slow_path(chain == NULL)) {
        return NULL;
    }

    for (i = 0; i < cert->count; i++) {
        element = nxt_conf_create_object(mp, 3);
        if (nxt_slow_path(element == NULL)) {
            return NULL;
        }

        x509 = cert->chain[i];

        value = nxt_cert_name_details(mp, x509, 0);
        if (value == NULL) {
            return NULL;
        }

        nxt_conf_set_member(element, &subject_str, value, 0);

        value = nxt_cert_name_details(mp, x509, 1);
        if (value == NULL) {
            return NULL;
        }

        nxt_conf_set_member(element, &issuer_str, value, 1);

        value = nxt_conf_create_object(mp, 2);
        if (nxt_slow_path(value == NULL)) {
            return NULL;
        }

        bio = BIO_new(BIO_s_mem());
        if (nxt_slow_path(bio == NULL)) {
            return NULL;
        }

        asn1_time = X509_get_notBefore(x509);

        ret = ASN1_TIME_print(bio, asn1_time);

        if (nxt_fast_path(ret == 1)) {
            str.length = BIO_get_mem_data(bio, &str.start);
            ret = nxt_conf_set_member_string_dup(value, mp, &since_str, &str,
                                                 0);
        } else {
            ret = NXT_ERROR;
        }

        BIO_free(bio);

        if (nxt_slow_path(ret != NXT_OK)) {
            return NULL;
        }

        bio = BIO_new(BIO_s_mem());
        if (nxt_slow_path(bio == NULL)) {
            return NULL;
        }

        asn1_time = X509_get_notAfter(x509);

        ret = ASN1_TIME_print(bio, asn1_time);

        if (nxt_fast_path(ret == 1)) {
            str.length = BIO_get_mem_data(bio, &str.start);
            ret = nxt_conf_set_member_string_dup(value, mp, &until_str, &str,
                                                 1);
        } else {
            ret = NXT_ERROR;
        }

        BIO_free(bio);

        if (nxt_slow_path(ret != NXT_OK)) {
            return NULL;
        }

        nxt_conf_set_member(element, &validity_str, value, 2);

        nxt_conf_set_element(chain, i, element);
    }

    nxt_conf_set_member(object, &chain_str, chain, 1);

    return object;
}


typedef struct {
    int        nid;
    nxt_str_t  name;
} nxt_cert_nid_t;


static nxt_conf_value_t *
nxt_cert_name_details(nxt_mp_t *mp, X509 *x509, nxt_bool_t issuer)
{
    int                     len;
    X509_NAME               *x509_name;
    nxt_str_t               str;
    nxt_int_t               ret;
    nxt_uint_t              i, n, count;
    nxt_conf_value_t        *object, *names;
    STACK_OF(GENERAL_NAME)  *alt_names;
    u_char                  buf[256];

    static nxt_cert_nid_t  nids[] = {
        { NID_commonName, nxt_string("common_name") },
        { NID_countryName, nxt_string("country") },
        { NID_stateOrProvinceName, nxt_string("state_or_province") },
        { NID_localityName, nxt_string("locality") },
        { NID_organizationName, nxt_string("organization") },
        { NID_organizationalUnitName, nxt_string("department") },
    };

    static nxt_str_t alt_names_str = nxt_string("alt_names");

    count = 0;

    x509_name = issuer ? X509_get_issuer_name(x509)
                       : X509_get_subject_name(x509);

    for (n = 0; n != nxt_nitems(nids); n++) {

        if (X509_NAME_get_index_by_NID(x509_name, nids[n].nid, -1) < 0) {
            continue;
        }

        count++;
    }

    alt_names = X509_get_ext_d2i(x509, issuer ? NID_issuer_alt_name
                                              : NID_subject_alt_name,
                                 NULL, NULL);

    if (alt_names != NULL) {
        names = nxt_cert_alt_names_details(mp, alt_names);

        sk_GENERAL_NAME_pop_free(alt_names, GENERAL_NAME_free);

        if (nxt_slow_path(names == NULL)) {
            return NULL;
        }

        count++;

    } else {
        names = NULL;
    }

    object = nxt_conf_create_object(mp, count);
    if (nxt_slow_path(object == NULL)) {
        return NULL;
    }

    for (n = 0, i = 0; n != nxt_nitems(nids) && i != count; n++) {

        len = X509_NAME_get_text_by_NID(x509_name, nids[n].nid,
                                        (char *) buf, sizeof(buf));

        if (n == 1 && names != NULL) {
            nxt_conf_set_member(object, &alt_names_str, names, i++);
        }

        if (len < 0) {
            continue;
        }

        str.length = len;
        str.start = buf;

        ret = nxt_conf_set_member_string_dup(object, mp, &nids[n].name,
                                             &str, i++);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NULL;
        }
    }

    return object;
}


static nxt_conf_value_t *
nxt_cert_alt_names_details(nxt_mp_t *mp, STACK_OF(GENERAL_NAME) *alt_names)
{
    nxt_str_t         str;
    nxt_int_t         ret;
    nxt_uint_t        i, n, count;
    GENERAL_NAME      *name;
    nxt_conf_value_t  *array;

    count = sk_GENERAL_NAME_num(alt_names);
    n = 0;

    for (i = 0; i != count; i++) {
        name = sk_GENERAL_NAME_value(alt_names, i);

        if (name->type != GEN_DNS) {
            continue;
        }

        n++;
    }

    array = nxt_conf_create_array(mp, n);
    if (nxt_slow_path(array == NULL)) {
        return NULL;
    }

    for (n = 0, i = 0; n != count; n++) {
        name = sk_GENERAL_NAME_value(alt_names, n);

        if (name->type != GEN_DNS) {
            continue;
        }

        str.length = ASN1_STRING_length(name->d.dNSName);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        str.start = (u_char *) ASN1_STRING_get0_data(name->d.dNSName);
#else
        str.start = ASN1_STRING_data(name->d.dNSName);
#endif

        ret = nxt_conf_set_element_string_dup(array, mp, i++, &str);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NULL;
        }
    }

    return array;
}


nxt_int_t
nxt_cert_info_delete(nxt_str_t *name)
{
    nxt_int_t           ret;
    nxt_cert_info_t     *info;
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = nxt_djb_hash(name->start, name->length);
    lhq.key = *name;
    lhq.proto = &nxt_cert_info_hash_proto;

    ret = nxt_lvlhsh_delete(&nxt_cert_info, &lhq);

    if (ret == NXT_OK) {
        info = lhq.value;
        nxt_mp_destroy(info->mp);
    }

    return ret;
}



nxt_array_t *
nxt_cert_store_load(nxt_task_t *task, nxt_mp_t *mp)
{
    DIR              *dir;
    size_t           size, alloc;
    u_char           *buf, *p;
    nxt_str_t        name;
    nxt_int_t        ret;
    nxt_file_t       file;
    nxt_array_t      *certs;
    nxt_runtime_t    *rt;
    struct dirent    *de;
    nxt_cert_item_t  *item;

    rt = task->thread->runtime;

    if (nxt_slow_path(rt->certs.start == NULL)) {
        nxt_alert(task, "no certificates storage directory");
        return NULL;
    }

    certs = nxt_array_create(mp, 16, sizeof(nxt_cert_item_t));
    if (nxt_slow_path(certs == NULL)) {
        return NULL;
    }

    buf = NULL;
    alloc = 0;

    dir = opendir((char *) rt->certs.start);
    if (nxt_slow_path(dir == NULL)) {
        nxt_alert(task, "opendir(\"%s\") failed %E",
                  rt->certs.start, nxt_errno);
        goto fail;
    }

    for ( ;; ) {
        de = readdir(dir);
        if (de == NULL) {
            break;
        }

        nxt_debug(task, "readdir(\"%s\"): \"%s\"", rt->certs.start, de->d_name);

        name.length = nxt_strlen(de->d_name);
        name.start = (u_char *) de->d_name;

        if (nxt_str_eq(&name, ".", 1) || nxt_str_eq(&name, "..", 2)) {
            continue;
        }

        item = nxt_array_add(certs);
        if (nxt_slow_path(item == NULL)) {
            goto fail;
        }

        item->fd = -1;

        size = rt->certs.length + name.length + 1;

        if (size > alloc) {
            size += 32;

            p = nxt_realloc(buf, size);
            if (p == NULL) {
                goto fail;
            }

            alloc = size;
            buf = p;
        }

        p = nxt_cpymem(buf, rt->certs.start, rt->certs.length);
        p = nxt_cpymem(p, name.start, name.length + 1);

        nxt_memzero(&file, sizeof(nxt_file_t));

        file.name = buf;

        ret = nxt_file_open(task, &file, NXT_FILE_RDONLY, NXT_FILE_OPEN,
                            NXT_FILE_OWNER_ACCESS);


        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_array_remove_last(certs);
            continue;
        }

        item->fd = file.fd;

        if (nxt_slow_path(nxt_str_dup(mp, &item->name, &name) == NULL)) {
            goto fail;
        }
    }

    if (buf != NULL) {
        nxt_free(buf);
    }

    (void) closedir(dir);

    return certs;

fail:

    if (buf != NULL) {
        nxt_free(buf);
    }

    if (dir != NULL) {
        (void) closedir(dir);
    }

    nxt_cert_store_release(certs);

    return NULL;
}


void
nxt_cert_store_release(nxt_array_t *certs)
{
    uint32_t         i;
    nxt_cert_item_t  *items;

    for (items = certs->elts, i = 0;
         i < certs->nelts;
         i++)
    {
        nxt_fd_close(items[i].fd);
    }

    nxt_array_destroy(certs);
}


#if 0

void
nxt_cert_store_discovery_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    DIR            *dir;
    size_t         size;
    nxt_buf_t      *b;
    nxt_int_t      ret;
    nxt_port_t     *port;
    nxt_runtime_t  *rt;
    struct dirent  *de;

    port = nxt_runtime_port_find(task->thread->runtime, msg->port_msg.pid,
                                 msg->port_msg.reply_port);

    if (nxt_slow_path(port == NULL)) {
        return;
    }

    b = NULL;
    dir = NULL;

    rt = task->thread->runtime;

    if (nxt_slow_path(rt->certs.start == NULL)) {
        nxt_alert(task, "no certificates storage directory");
        goto fail;
    }

    dir = opendir((char *) rt->certs.start);
    if (nxt_slow_path(dir == NULL)) {
        nxt_alert(task, "opendir(\"%s\") failed %E",
                  rt->certs.start, nxt_errno);
        goto fail;
    }

    size = 0;

    for ( ;; ) {
        de = readdir(dir);
        if (de == NULL) {
            break;
        }

        if (de->d_type != DT_REG) {
            continue;
        }

        size += nxt_strlen(de->d_name) + 1;
    }

    b = nxt_port_mmap_get_buf(task, port, size);
    if (nxt_slow_path(b == NULL)) {
        goto fail;
    }

    rewinddir(dir);

    for ( ;; ) {
        de = readdir(dir);
        if (de == NULL) {
            break;
        }

        if (de->d_type != DT_REG) {
            continue;
        }

        size = nxt_strlen(de->d_name) + 1;

        if (nxt_slow_path(size > (size_t) nxt_buf_mem_free_size(&b->mem))) {
            b->mem.free = b->mem.start;
            break;
        }

        b->mem.free = nxt_cpymem(b->mem.free, de->d_name, size);
    }

    (void) closedir(dir);
    dir = NULL;

    if (nxt_slow_path(nxt_buf_mem_free_size(&b->mem) != 0)) {
        nxt_alert(task, "certificates storage directory "
                  "has changed while reading it");
        goto fail;
    }

    ret = nxt_port_socket_write(task, port, NXT_PORT_MSG_RPC_READY_LAST, -1,
                                msg->port_msg.stream, 0, b);

    if (nxt_fast_path(ret == NXT_OK)) {
        return;
    }

fail:

    if (dir != NULL) {
        (void) closedir(dir);
    }

    if (b != NULL) {
        b->completion_handler(task, b, b->parent);
    }

    (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_RPC_ERROR, -1,
                                 msg->port_msg.stream, 0, NULL);
}

#endif


void
nxt_cert_store_get(nxt_task_t *task, nxt_str_t *name, nxt_mp_t *mp,
    nxt_port_rpc_handler_t handler, void *ctx)
{
    uint32_t       stream;
    nxt_int_t      ret;
    nxt_buf_t      *b;
    nxt_port_t     *main_port, *recv_port;
    nxt_runtime_t  *rt;

    b = nxt_buf_mem_alloc(mp, name->length + 1, 0);
    if (nxt_slow_path(b == NULL)) {
        goto fail;
    }

    nxt_mp_retain(mp);
    b->completion_handler = nxt_cert_buf_completion;

    nxt_buf_cpystr(b, name);
    *b->mem.free++ = '\0';

    rt = task->thread->runtime;
    main_port = rt->port_by_type[NXT_PROCESS_MAIN];
    recv_port = rt->port_by_type[rt->type];

    stream = nxt_port_rpc_register_handler(task, recv_port, handler, handler,
                                           -1, ctx);
    if (nxt_slow_path(stream == 0)) {
        goto fail;
    }

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_CERT_GET, -1,
                                stream, recv_port->id, b);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_rpc_cancel(task, recv_port, stream);
        goto fail;
    }

    return;

fail:

    handler(task, NULL, ctx);
}


static void
nxt_cert_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_mp_t   *mp;
    nxt_buf_t  *b;

    b = obj;
    mp = b->data;
    nxt_assert(b->next == NULL);

    nxt_mp_free(mp, b);
    nxt_mp_release(mp);
}


void
nxt_cert_store_get_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    u_char               *p;
    nxt_int_t            ret;
    nxt_str_t            name;
    nxt_file_t           file;
    nxt_port_t           *port;
    nxt_runtime_t        *rt;
    nxt_port_msg_type_t  type;

    port = nxt_runtime_port_find(task->thread->runtime, msg->port_msg.pid,
                                 msg->port_msg.reply_port);

    if (nxt_slow_path(port == NULL)) {
        nxt_alert(task, "process port not found (pid %PI, reply_port %d)",
                  msg->port_msg.pid, msg->port_msg.reply_port);
        return;
    }

    if (nxt_slow_path(port->type != NXT_PROCESS_CONTROLLER
                      && port->type != NXT_PROCESS_ROUTER))
    {
        nxt_alert(task, "process %PI cannot store certificates",
                  msg->port_msg.pid);
        return;
    }

    nxt_memzero(&file, sizeof(nxt_file_t));

    file.fd = -1;
    type = NXT_PORT_MSG_RPC_ERROR;

    rt = task->thread->runtime;

    if (nxt_slow_path(rt->certs.start == NULL)) {
        nxt_alert(task, "no certificates storage directory");
        goto error;
    }

    name.start = msg->buf->mem.pos;
    name.length = nxt_strlen(name.start);

    file.name = nxt_malloc(rt->certs.length + name.length + 1);

    if (nxt_slow_path(file.name == NULL)) {
        goto error;
    }

    p = nxt_cpymem(file.name, rt->certs.start, rt->certs.length);
    p = nxt_cpymem(p, name.start, name.length + 1);

    ret = nxt_file_open(task, &file, NXT_FILE_RDWR, NXT_FILE_CREATE_OR_OPEN,
                        NXT_FILE_OWNER_ACCESS);

    nxt_free(file.name);

    if (nxt_fast_path(ret == NXT_OK)) {
        type = NXT_PORT_MSG_RPC_READY_LAST | NXT_PORT_MSG_CLOSE_FD;
    }

error:

    (void) nxt_port_socket_write(task, port, type, file.fd,
                                 msg->port_msg.stream, 0, NULL);
}


void
nxt_cert_store_delete(nxt_task_t *task, nxt_str_t *name, nxt_mp_t *mp)
{
    nxt_buf_t      *b;
    nxt_port_t     *main_port;
    nxt_runtime_t  *rt;

    b = nxt_buf_mem_alloc(mp, name->length + 1, 0);

    if (nxt_fast_path(b != NULL)) {
        nxt_buf_cpystr(b, name);
        *b->mem.free++ = '\0';

        rt = task->thread->runtime;
        main_port = rt->port_by_type[NXT_PROCESS_MAIN];

        (void) nxt_port_socket_write(task, main_port, NXT_PORT_MSG_CERT_DELETE,
                                     -1, 0, 0, b);
    }
}


void
nxt_cert_store_delete_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    u_char           *p;
    nxt_str_t        name;
    nxt_port_t       *ctl_port;
    nxt_runtime_t    *rt;
    nxt_file_name_t  *path;

    rt = task->thread->runtime;
    ctl_port = rt->port_by_type[NXT_PROCESS_CONTROLLER];

    if (nxt_slow_path(ctl_port == NULL)) {
        nxt_alert(task, "controller port not found");
        return;
    }

    if (nxt_slow_path(nxt_recv_msg_cmsg_pid(msg) != ctl_port->pid)) {
        nxt_alert(task, "process %PI cannot delete certificates",
                  nxt_recv_msg_cmsg_pid(msg));
        return;
    }

    if (nxt_slow_path(rt->certs.start == NULL)) {
        nxt_alert(task, "no certificates storage directory");
        return;
    }

    name.start = msg->buf->mem.pos;
    name.length = nxt_strlen(name.start);

    path = nxt_malloc(rt->certs.length + name.length + 1);

    if (nxt_fast_path(path != NULL)) {
        p = nxt_cpymem(path, rt->certs.start, rt->certs.length);
        p = nxt_cpymem(p, name.start, name.length + 1);

        (void) nxt_file_delete(path);

        nxt_free(path);
    }
}
