
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


typedef struct {
    nxt_http_status_t       status;
    nxt_str_t               location;
} nxt_http_return_conf_t;


static nxt_http_action_t *nxt_http_return(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_action_t *action);


static const nxt_http_request_state_t  nxt_http_return_send_state;


nxt_int_t
nxt_http_return_init(nxt_mp_t *mp, nxt_http_action_t *action,
    nxt_http_action_conf_t *acf)
{
    nxt_str_t               *loc;
    nxt_uint_t              encode;
    nxt_http_return_conf_t  *conf;

    conf = nxt_mp_zget(mp, sizeof(nxt_http_return_conf_t));
    if (nxt_slow_path(conf == NULL)) {
        return NXT_ERROR;
    }

    action->handler = nxt_http_return;
    action->u.conf = conf;

    conf->status = nxt_conf_get_number(acf->ret);

    if (acf->location.length > 0) {
        if (nxt_is_complex_uri_encoded(acf->location.start,
                                       acf->location.length))
        {
            loc = nxt_str_dup(mp, &conf->location, &acf->location);
            if (nxt_slow_path(loc == NULL)) {
                return NXT_ERROR;
            }

        } else {
            loc = &conf->location;

            encode = nxt_encode_complex_uri(NULL, acf->location.start,
                                            acf->location.length);
            loc->length = acf->location.length + encode * 2;

            loc->start = nxt_mp_nget(mp, loc->length);
            if (nxt_slow_path(loc->start == NULL)) {
                return NXT_ERROR;
            }

            nxt_encode_complex_uri(loc->start, acf->location.start,
                                   acf->location.length);
        }
    }

    return NXT_OK;
}


nxt_http_action_t *
nxt_http_return(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *action)
{
    nxt_http_field_t        *field;
    nxt_http_return_conf_t  *conf;

    conf = action->u.conf;

    nxt_debug(task, "http return: %d (loc: \"%V\")",
              conf->status, &conf->location);

    if (conf->status >= NXT_HTTP_BAD_REQUEST
        && conf->status <= NXT_HTTP_SERVER_ERROR_MAX)
    {
        nxt_http_request_error(task, r, conf->status);
        return NULL;
    }

    r->status = conf->status;
    r->resp.content_length_n = 0;

    if (conf->location.length > 0) {
        field = nxt_list_zero_add(r->resp.fields);
        if (nxt_slow_path(field == NULL)) {
            nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
            return NULL;
        }

        nxt_http_field_name_set(field, "Location");

        field->value = conf->location.start;
        field->value_length = conf->location.length;
    }

    r->state = &nxt_http_return_send_state;

    nxt_http_request_header_send(task, r, NULL, NULL);

    return NULL;
}


static const nxt_http_request_state_t  nxt_http_return_send_state
    nxt_aligned(64) =
{
    .error_handler = nxt_http_request_error_handler,
};
