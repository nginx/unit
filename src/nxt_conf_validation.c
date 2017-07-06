
/*
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_conf.h>


typedef struct {
    nxt_str_t   name;
    nxt_uint_t  type;
    nxt_int_t   (*validator)(nxt_conf_value_t *value, void *data);
    void        *data;
} nxt_conf_vldt_object_t;


typedef nxt_int_t (*nxt_conf_vldt_member_t)(nxt_str_t *name,
                                            nxt_conf_value_t *value);

static nxt_int_t nxt_conf_vldt_listener(nxt_str_t *name,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_app(nxt_str_t *name, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_app_type(nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_object(nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_object_iterator(nxt_conf_value_t *value,
    void *data);


static const nxt_conf_vldt_object_t  nxt_conf_root_members[] = {
    { nxt_string("listeners"),
      NXT_CONF_OBJECT,
      &nxt_conf_vldt_object_iterator,
      &nxt_conf_vldt_listener },

    { nxt_string("applications"),
      NXT_CONF_OBJECT,
      &nxt_conf_vldt_object_iterator,
      &nxt_conf_vldt_app },

    { nxt_null_string, 0, NULL, NULL }
};


static const nxt_conf_vldt_object_t  nxt_conf_listener_members[] = {
    { nxt_string("application"),
      NXT_CONF_STRING,
      NULL,
      NULL },

    { nxt_null_string, 0, NULL, NULL }
};


static const nxt_conf_vldt_object_t  nxt_conf_application_members[] = {
    { nxt_string("type"),
      NXT_CONF_STRING,
      &nxt_conf_vldt_app_type,
      NULL },

    { nxt_string("workers"),
      NXT_CONF_INTEGER,
      NULL,
      NULL },

    { nxt_string("path"),
      NXT_CONF_STRING,
      NULL,
      NULL },

    { nxt_null_string, 0, NULL, NULL }
};


nxt_int_t
nxt_conf_validate(nxt_conf_value_t *value)
{
    if (nxt_conf_type(value) != NXT_CONF_OBJECT) {
        return NXT_ERROR;
    }

    return nxt_conf_vldt_object(value, (void *) nxt_conf_root_members);
}


static nxt_int_t
nxt_conf_vldt_listener(nxt_str_t *name, nxt_conf_value_t *value)
{
    return nxt_conf_vldt_object(value, (void *) nxt_conf_listener_members);
}


static nxt_int_t
nxt_conf_vldt_app(nxt_str_t *name, nxt_conf_value_t *value)
{
    return nxt_conf_vldt_object(value, (void *) nxt_conf_application_members);
}


static nxt_int_t
nxt_conf_vldt_app_type(nxt_conf_value_t *value, void *data)
{
    // TODO
    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_object(nxt_conf_value_t *value, void *data)
{
    uint32_t                index;
    nxt_str_t               name;
    nxt_conf_value_t        *member;
    nxt_conf_vldt_object_t  *vldt;

    index = 0;

    for ( ;; ) {
        member = nxt_conf_next_object_member(value, &name, &index);

        if (member == NULL) {
            return NXT_OK;
        }

        vldt = data;

        for ( ;; ) {
            if (vldt->name.length == 0) {
                return NXT_ERROR;
            }

            if (!nxt_strstr_eq(&vldt->name, &name)) {
                vldt++;
                continue;
            }

            if (nxt_conf_type(member) != vldt->type) {
                return NXT_ERROR;
            }

            if (vldt->validator != NULL
                && vldt->validator(member, vldt->data) != NXT_OK)
            {
                return NXT_ERROR;
            }

            break;
        }
    }
}


static nxt_int_t
nxt_conf_vldt_object_iterator(nxt_conf_value_t *value, void *data)
{
    uint32_t                index;
    nxt_str_t               name;
    nxt_conf_value_t        *member;
    nxt_conf_vldt_member_t  validator;

    validator = data;
    index = 0;

    for ( ;; ) {
        member = nxt_conf_next_object_member(value, &name, &index);

        if (member == NULL) {
            return NXT_OK;
        }

        if (validator(&name, member) != NXT_OK) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}
