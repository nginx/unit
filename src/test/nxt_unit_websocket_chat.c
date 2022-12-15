
/*
 * Copyright (C) NGINX, Inc.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include <nxt_unit.h>
#include <nxt_unit_request.h>
#include <nxt_clang.h>
#include <nxt_websocket.h>
#include <nxt_unit_websocket.h>
#include <nxt_main.h>


#define CONTENT_TYPE    "Content-Type"
#define CONTENT_LENGTH  "Content-Length"
#define TEXT_HTML       "text/html"

typedef struct {
    nxt_queue_link_t  link;
    int               id;
} ws_chat_request_data_t;


static int ws_chat_root(nxt_unit_request_info_t *req);
static void ws_chat_broadcast(const char *buf, size_t size);


static const char     ws_chat_index_html[];
static const int      ws_chat_index_html_size;

static char           ws_chat_index_content_length[34];
static int            ws_chat_index_content_length_size;

static nxt_queue_t    ws_chat_sessions;
static int            ws_chat_next_id = 0;


static void
ws_chat_request_handler(nxt_unit_request_info_t *req)
{
    static char             buf[1024];
    int                     buf_size;
    int                     rc = NXT_UNIT_OK;
    nxt_unit_request_t      *r;
    ws_chat_request_data_t  *data;

    r = req->request;

    const char* target = nxt_unit_sptr_get(&r->target);

    if (strcmp(target, "/") == 0) {
        rc = ws_chat_root(req);
        goto fail;
    }

    if (strcmp(target, "/chat") == 0) {
        if (!nxt_unit_request_is_websocket_handshake(req)) {
            goto notfound;
        }

        rc = nxt_unit_response_init(req, 101, 0, 0);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            goto fail;
        }

        data = req->data;
        nxt_queue_insert_tail(&ws_chat_sessions, &data->link);

        data->id = ws_chat_next_id++;

        nxt_unit_response_upgrade(req);
        nxt_unit_response_send(req);


        buf_size = snprintf(buf, sizeof(buf), "Guest #%d has joined.", data->id);

        ws_chat_broadcast(buf, buf_size);

        return;
    }

notfound:

    rc = nxt_unit_response_init(req, 404, 0, 0);

fail:

    nxt_unit_request_done(req, rc);
}


static int
ws_chat_root(nxt_unit_request_info_t *req)
{
    int rc;

    rc = nxt_unit_response_init(req, 200 /* Status code. */,
                                2 /* Number of response headers. */,
                                nxt_length(CONTENT_TYPE)
                                + nxt_length(TEXT_HTML)
                                + nxt_length(CONTENT_LENGTH)
                                + ws_chat_index_content_length_size
                                + ws_chat_index_html_size);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return rc;
    }

    rc = nxt_unit_response_add_field(req,
                                     CONTENT_TYPE, nxt_length(CONTENT_TYPE),
                                     TEXT_HTML, nxt_length(TEXT_HTML));
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return rc;
    }

    rc = nxt_unit_response_add_field(req,
                                     CONTENT_LENGTH, nxt_length(CONTENT_LENGTH),
                                     ws_chat_index_content_length,
                                     ws_chat_index_content_length_size);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return rc;
    }

    rc = nxt_unit_response_add_content(req, ws_chat_index_html,
                                       ws_chat_index_html_size);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return rc;
    }

    return nxt_unit_response_send(req);
}


static void
ws_chat_broadcast(const char *buf, size_t size)
{
    ws_chat_request_data_t   *data;
    nxt_unit_request_info_t  *req;

    nxt_unit_debug(NULL, "broadcast: %*.s", (int) size, buf);

    nxt_queue_each(data, &ws_chat_sessions, ws_chat_request_data_t, link) {

        req = nxt_unit_get_request_info_from_data(data);

        nxt_unit_req_debug(req, "send: %*.s", (int) size, buf);

        nxt_unit_websocket_send(req, NXT_WEBSOCKET_OP_TEXT, 1, buf, size);
    } nxt_queue_loop;
}


static void
ws_chat_websocket_handler(nxt_unit_websocket_frame_t *ws)
{
    int                     buf_size;
    static char             buf[1024];
    ws_chat_request_data_t  *data;

    if (ws->header->opcode != NXT_WEBSOCKET_OP_TEXT) {
        return;
    }

    data = ws->req->data;

    buf_size = snprintf(buf, sizeof(buf), "Guest #%d: ", data->id);

    buf_size += nxt_unit_websocket_read(ws, buf + buf_size,
                                        nxt_min(sizeof(buf),
                                                ws->content_length));

    ws_chat_broadcast(buf, buf_size);

    nxt_unit_websocket_done(ws);
}


static void
ws_chat_close_handler(nxt_unit_request_info_t *req)
{
    int                     buf_size;
    static char             buf[1024];
    ws_chat_request_data_t  *data;

    data = req->data;
    buf_size = snprintf(buf, sizeof(buf), "Guest #%d has disconnected.",
                        data->id);

    nxt_queue_remove(&data->link);
    nxt_unit_request_done(req, NXT_UNIT_OK);

    ws_chat_broadcast(buf, buf_size);
}


int
main(void)
{
    nxt_unit_ctx_t   *ctx;
    nxt_unit_init_t  init;

    ws_chat_index_content_length_size =
        snprintf(ws_chat_index_content_length,
                 sizeof(ws_chat_index_content_length), "%d",
                 ws_chat_index_html_size);

    nxt_queue_init(&ws_chat_sessions);

    memset(&init, 0, sizeof(nxt_unit_init_t));

    init.callbacks.request_handler = ws_chat_request_handler;
    init.callbacks.websocket_handler = ws_chat_websocket_handler;
    init.callbacks.close_handler = ws_chat_close_handler;

    init.request_data_size = sizeof(ws_chat_request_data_t);

    ctx = nxt_unit_init(&init);
    if (ctx == NULL) {
        return 1;
    }

    nxt_unit_run(ctx);

    nxt_unit_done(ctx);

    return 0;
}


static const char ws_chat_index_html[] =
"<html>\n"
"<head>\n"
"    <title>WebSocket Chat Examples</title>\n"
"    <style type=\"text/css\">\n"
"        input#chat {\n"
"            width: 410px\n"
"        }\n"
"\n"
"        #container {\n"
"            width: 400px;\n"
"        }\n"
"\n"
"        #console {\n"
"            border: 1px solid #CCCCCC;\n"
"            border-right-color: #999999;\n"
"            border-bottom-color: #999999;\n"
"            height: 170px;\n"
"            overflow-y: scroll;\n"
"            padding: 5px;\n"
"            width: 100%;\n"
"        }\n"
"\n"
"        #console p {\n"
"            padding: 0;\n"
"            margin: 0;\n"
"        }\n"
"    </style>\n"
"    <script>\n"
"        \"use strict\";\n"
"\n"
"        var Chat = {};\n"
"\n"
"        Chat.socket = null;\n"
"\n"
"        Chat.connect = (function(host) {\n"
"            if ('WebSocket' in window) {\n"
"                Chat.socket = new WebSocket(host);\n"
"            } else if ('MozWebSocket' in window) {\n"
"                Chat.socket = new MozWebSocket(host);\n"
"            } else {\n"
"                Console.log('Error: WebSocket is not supported by this browser.');\n"
"                return;\n"
"            }\n"
"\n"
"            Chat.socket.onopen = function () {\n"
"                Console.log('Info: WebSocket connection opened.');\n"
"                document.getElementById('chat').onkeydown = function(event) {\n"
"                    if (event.keyCode == 13) {\n"
"                        Chat.sendMessage();\n"
"                    }\n"
"                };\n"
"            };\n"
"\n"
"            Chat.socket.onclose = function () {\n"
"                document.getElementById('chat').onkeydown = null;\n"
"                Console.log('Info: WebSocket closed.');\n"
"            };\n"
"\n"
"            Chat.socket.onmessage = function (message) {\n"
"                Console.log(message.data);\n"
"            };\n"
"        });\n"
"\n"
"        Chat.initialize = function() {\n"
"            var proto = 'ws://';\n"
"            if (window.location.protocol == 'https:') {\n"
"                proto = 'wss://'\n"
"            }\n"
"            Chat.connect(proto + window.location.host + '/chat');\n"
"        };\n"
"\n"
"        Chat.sendMessage = (function() {\n"
"            var message = document.getElementById('chat').value;\n"
"            if (message != '') {\n"
"                Chat.socket.send(message);\n"
"                document.getElementById('chat').value = '';\n"
"            }\n"
"        });\n"
"\n"
"        var Console = {};\n"
"\n"
"        Console.log = (function(message) {\n"
"            var console = document.getElementById('console');\n"
"            var p = document.createElement('p');\n"
"            p.style.wordWrap = 'break-word';\n"
"            p.innerHTML = message;\n"
"            console.appendChild(p);\n"
"            while (console.childNodes.length > 25) {\n"
"                console.removeChild(console.firstChild);\n"
"            }\n"
"            console.scrollTop = console.scrollHeight;\n"
"        });\n"
"\n"
"        Chat.initialize();\n"
"\n"
"      </script>\n"
"</head>\n"
"<body>\n"
"<noscript><h2 style=\"color: #ff0000\">Seems your browser doesn't support Javascript! Websockets rely on Javascript being enabled. Please enable\n"
"    Javascript and reload this page!</h2></noscript>\n"
"<div>\n"
"    <p><input type=\"text\" placeholder=\"type and press enter to chat\" id=\"chat\" /></p>\n"
"    <div id=\"container\">\n"
"        <div id=\"console\"/>\n"
"    </div>\n"
"</div>\n"
"</body>\n"
"</html>\n"
;

static const int  ws_chat_index_html_size = nxt_length(ws_chat_index_html);
