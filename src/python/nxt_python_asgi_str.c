
/*
 * Copyright (C) NGINX, Inc.
 */


#include <python/nxt_python.h>

#if (NXT_HAVE_ASGI)

#include <nxt_main.h>
#include <python/nxt_python_asgi_str.h>


PyObject  *nxt_py_1_0_str;
PyObject  *nxt_py_1_1_str;
PyObject  *nxt_py_2_0_str;
PyObject  *nxt_py_2_1_str;
PyObject  *nxt_py_3_0_str;
PyObject  *nxt_py_add_done_callback_str;
PyObject  *nxt_py_asgi_str;
PyObject  *nxt_py_bad_state_str;
PyObject  *nxt_py_body_str;
PyObject  *nxt_py_bytes_str;
PyObject  *nxt_py_client_str;
PyObject  *nxt_py_code_str;
PyObject  *nxt_py_done_str;
PyObject  *nxt_py_exception_str;
PyObject  *nxt_py_failed_to_send_body_str;
PyObject  *nxt_py_headers_str;
PyObject  *nxt_py_http_str;
PyObject  *nxt_py_http_disconnect_str;
PyObject  *nxt_py_http_request_str;
PyObject  *nxt_py_http_version_str;
PyObject  *nxt_py_https_str;
PyObject  *nxt_py_lifespan_str;
PyObject  *nxt_py_lifespan_shutdown_str;
PyObject  *nxt_py_lifespan_startup_str;
PyObject  *nxt_py_method_str;
PyObject  *nxt_py_message_str;
PyObject  *nxt_py_message_too_big_str;
PyObject  *nxt_py_more_body_str;
PyObject  *nxt_py_path_str;
PyObject  *nxt_py_query_string_str;
PyObject  *nxt_py_raw_path_str;
PyObject  *nxt_py_result_str;
PyObject  *nxt_py_root_path_str;
PyObject  *nxt_py_scheme_str;
PyObject  *nxt_py_server_str;
PyObject  *nxt_py_set_exception_str;
PyObject  *nxt_py_set_result_str;
PyObject  *nxt_py_spec_version_str;
PyObject  *nxt_py_status_str;
PyObject  *nxt_py_subprotocol_str;
PyObject  *nxt_py_subprotocols_str;
PyObject  *nxt_py_text_str;
PyObject  *nxt_py_type_str;
PyObject  *nxt_py_state_str;
PyObject  *nxt_py_version_str;
PyObject  *nxt_py_websocket_str;
PyObject  *nxt_py_websocket_accept_str;
PyObject  *nxt_py_websocket_close_str;
PyObject  *nxt_py_websocket_connect_str;
PyObject  *nxt_py_websocket_disconnect_str;
PyObject  *nxt_py_websocket_receive_str;
PyObject  *nxt_py_websocket_send_str;
PyObject  *nxt_py_ws_str;
PyObject  *nxt_py_wss_str;

static nxt_python_string_t nxt_py_asgi_strings[] = {
    { nxt_string("1.0"), &nxt_py_1_0_str },
    { nxt_string("1.1"), &nxt_py_1_1_str },
    { nxt_string("2.0"), &nxt_py_2_0_str },
    { nxt_string("2.1"), &nxt_py_2_1_str },
    { nxt_string("3.0"), &nxt_py_3_0_str },
    { nxt_string("add_done_callback"), &nxt_py_add_done_callback_str },
    { nxt_string("asgi"), &nxt_py_asgi_str },
    { nxt_string("bad state"), &nxt_py_bad_state_str },
    { nxt_string("body"), &nxt_py_body_str },
    { nxt_string("bytes"), &nxt_py_bytes_str },
    { nxt_string("client"), &nxt_py_client_str },
    { nxt_string("code"), &nxt_py_code_str },
    { nxt_string("done"), &nxt_py_done_str },
    { nxt_string("exception"), &nxt_py_exception_str },
    { nxt_string("failed to send body"), &nxt_py_failed_to_send_body_str },
    { nxt_string("headers"), &nxt_py_headers_str },
    { nxt_string("http"), &nxt_py_http_str },
    { nxt_string("http.disconnect"), &nxt_py_http_disconnect_str },
    { nxt_string("http.request"), &nxt_py_http_request_str },
    { nxt_string("http_version"), &nxt_py_http_version_str },
    { nxt_string("https"), &nxt_py_https_str },
    { nxt_string("lifespan"), &nxt_py_lifespan_str },
    { nxt_string("lifespan.shutdown"), &nxt_py_lifespan_shutdown_str },
    { nxt_string("lifespan.startup"), &nxt_py_lifespan_startup_str },
    { nxt_string("message"), &nxt_py_message_str },
    { nxt_string("message too big"), &nxt_py_message_too_big_str },
    { nxt_string("method"), &nxt_py_method_str },
    { nxt_string("more_body"), &nxt_py_more_body_str },
    { nxt_string("path"), &nxt_py_path_str },
    { nxt_string("query_string"), &nxt_py_query_string_str },
    { nxt_string("raw_path"), &nxt_py_raw_path_str },
    { nxt_string("result"), &nxt_py_result_str },
    { nxt_string("root_path"), &nxt_py_root_path_str },
    { nxt_string("scheme"), &nxt_py_scheme_str },
    { nxt_string("server"), &nxt_py_server_str },
    { nxt_string("set_exception"), &nxt_py_set_exception_str },
    { nxt_string("set_result"), &nxt_py_set_result_str },
    { nxt_string("spec_version"), &nxt_py_spec_version_str },
    { nxt_string("status"), &nxt_py_status_str },
    { nxt_string("subprotocol"), &nxt_py_subprotocol_str },
    { nxt_string("subprotocols"), &nxt_py_subprotocols_str },
    { nxt_string("text"), &nxt_py_text_str },
    { nxt_string("type"), &nxt_py_type_str },
    { nxt_string("state"), &nxt_py_state_str },
    { nxt_string("version"), &nxt_py_version_str },
    { nxt_string("websocket"), &nxt_py_websocket_str },
    { nxt_string("websocket.accept"), &nxt_py_websocket_accept_str },
    { nxt_string("websocket.close"), &nxt_py_websocket_close_str },
    { nxt_string("websocket.connect"), &nxt_py_websocket_connect_str },
    { nxt_string("websocket.disconnect"), &nxt_py_websocket_disconnect_str },
    { nxt_string("websocket.receive"), &nxt_py_websocket_receive_str },
    { nxt_string("websocket.send"), &nxt_py_websocket_send_str },
    { nxt_string("ws"), &nxt_py_ws_str },
    { nxt_string("wss"), &nxt_py_wss_str },
    { nxt_null_string, NULL },
};


int
nxt_py_asgi_str_init(void)
{
    return nxt_python_init_strings(nxt_py_asgi_strings);
}


void
nxt_py_asgi_str_done(void)
{
    nxt_python_done_strings(nxt_py_asgi_strings);
}


#endif /* NXT_HAVE_ASGI */
