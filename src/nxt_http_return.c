
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


static const nxt_http_request_state_t  nxt_http_return_send_state;


nxt_http_action_t *
nxt_http_return_handler(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *action)
{
    nxt_http_field_t   *field;
    nxt_http_status_t  status;

    status = action->u.return_code;

    if (status >= NXT_HTTP_BAD_REQUEST
        && status <= NXT_HTTP_SERVER_ERROR_MAX)
    {
        nxt_http_request_error(task, r, status);
        return NULL;
    }

    r->status = status;
    r->resp.content_length_n = 0;

    if (action->name.length > 0) {
        field = nxt_list_zero_add(r->resp.fields);
        if (nxt_slow_path(field == NULL)) {
            nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
            return NULL;
        }

        nxt_http_field_name_set(field, "Location");

        field->value = action->name.start;
        field->value_length = action->name.length;
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
