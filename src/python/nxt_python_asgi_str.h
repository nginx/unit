
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PYTHON_ASGI_STR_H_INCLUDED_
#define _NXT_PYTHON_ASGI_STR_H_INCLUDED_


extern PyObject  *nxt_py_1_0_str;
extern PyObject  *nxt_py_1_1_str;
extern PyObject  *nxt_py_2_0_str;
extern PyObject  *nxt_py_2_1_str;
extern PyObject  *nxt_py_3_0_str;
extern PyObject  *nxt_py_add_done_callback_str;
extern PyObject  *nxt_py_asgi_str;
extern PyObject  *nxt_py_bad_state_str;
extern PyObject  *nxt_py_body_str;
extern PyObject  *nxt_py_bytes_str;
extern PyObject  *nxt_py_client_str;
extern PyObject  *nxt_py_code_str;
extern PyObject  *nxt_py_done_str;
extern PyObject  *nxt_py_exception_str;
extern PyObject  *nxt_py_failed_to_send_body_str;
extern PyObject  *nxt_py_headers_str;
extern PyObject  *nxt_py_http_str;
extern PyObject  *nxt_py_http_disconnect_str;
extern PyObject  *nxt_py_http_request_str;
extern PyObject  *nxt_py_http_version_str;
extern PyObject  *nxt_py_https_str;
extern PyObject  *nxt_py_lifespan_str;
extern PyObject  *nxt_py_lifespan_shutdown_str;
extern PyObject  *nxt_py_lifespan_startup_str;
extern PyObject  *nxt_py_method_str;
extern PyObject  *nxt_py_message_str;
extern PyObject  *nxt_py_message_too_big_str;
extern PyObject  *nxt_py_more_body_str;
extern PyObject  *nxt_py_path_str;
extern PyObject  *nxt_py_query_string_str;
extern PyObject  *nxt_py_result_str;
extern PyObject  *nxt_py_raw_path_str;
extern PyObject  *nxt_py_root_path_str;
extern PyObject  *nxt_py_scheme_str;
extern PyObject  *nxt_py_server_str;
extern PyObject  *nxt_py_set_exception_str;
extern PyObject  *nxt_py_set_result_str;
extern PyObject  *nxt_py_spec_version_str;
extern PyObject  *nxt_py_status_str;
extern PyObject  *nxt_py_subprotocol_str;
extern PyObject  *nxt_py_subprotocols_str;
extern PyObject  *nxt_py_text_str;
extern PyObject  *nxt_py_type_str;
extern PyObject  *nxt_py_state_str;
extern PyObject  *nxt_py_version_str;
extern PyObject  *nxt_py_websocket_str;
extern PyObject  *nxt_py_websocket_accept_str;
extern PyObject  *nxt_py_websocket_close_str;
extern PyObject  *nxt_py_websocket_connect_str;
extern PyObject  *nxt_py_websocket_disconnect_str;
extern PyObject  *nxt_py_websocket_receive_str;
extern PyObject  *nxt_py_websocket_send_str;
extern PyObject  *nxt_py_ws_str;
extern PyObject  *nxt_py_wss_str;


int nxt_py_asgi_str_init(void);
void nxt_py_asgi_str_done(void);


#endif  /* _NXT_PYTHON_ASGI_STR_H_INCLUDED_ */
