use rust_unit_wasm::*;

// Buffer of some size to store the copy of the request
const REQUEST_BUF: *mut *mut u8 = std::ptr::null_mut();

#[no_mangle]
pub extern "C" fn luw_module_end_handler() {
    //free(REQUEST_BUF);
}

#[no_mangle]
pub extern "C" fn luw_module_init_handler() {
    //REQUEST_BUF = malloc(luw_mem_get_init_size());
}

#[no_mangle]
pub extern "C" fn luw_request_handler(addr: *mut u8) -> i32 {
    // Need a initalization
    //
    // It sucks that rust needs this, this is supposed to be
    // an opaque structure and the structure is 0-initialised
    // in luw_init_ctx();
    let mut ctx_: luw_ctx_t = luw_ctx_t {
        addr: std::ptr::null_mut(),
        mem: std::ptr::null_mut(),
        req: std::ptr::null_mut(),
        resp: std::ptr::null_mut(),
        resp_hdr: std::ptr::null_mut(),
        resp_offset: 0,
        req_buf: std::ptr::null_mut(),
        hdrp: std::ptr::null_mut(),
        reqp: std::ptr::null_mut(),
    };
    let ctx: *mut luw_ctx_t = &mut ctx_;

    unsafe {
        // Initialise the context structure.
        //
        // addr is the address of the previously allocated memory shared
        // between the module and unit.
        //
        // The response data will be stored @ addr + offset (of 4096 bytes).
        // This will leave some space for the response  headers.
        luw_init_ctx(ctx, addr, 4096);

        // Allocate memory to store the request and copy the request data.
        luw_set_req_buf(
            ctx,
            REQUEST_BUF,
            luw_srb_flags_t_LUW_SRB_ALLOC | luw_srb_flags_t_LUW_SRB_FULL_SIZE,
        );

        // Define the Response Body Text.
        let response = "Hello World - From WebAssembly in Rust on Unit :) \n";
        luw_mem_writep(ctx, response.as_ptr() as *const i8);

        // Debgging: Print the response.len()
        let content_len = format!("{}\0", response.len());

        // Init Response Headers
        //
        // Needs the context, number of headers about to add as well as
        // the offset where to store the headers. In this case we are
        // storing the response headers at the beginning of our shared
        // memory at offset 0.

        luw_http_init_headers(ctx, 2, 0);
        luw_http_add_header(
            ctx,
            0,
            "Content-Type\0".as_ptr() as *const i8,
            "text/plain\0".as_ptr() as *const i8,
        );
        luw_http_add_header(
            ctx,
            1,
            "Content-Length\0".as_ptr() as *const i8,
            content_len.as_ptr() as *const i8,
        );

        // This calls nxt_wasm_send_headers() in Unit
        luw_http_send_headers(ctx);

        // This calls nxt_wasm_send_response() in Unit
        luw_http_send_response(ctx);

        // This calls nxt_wasm_response_end() in Unit
        luw_http_response_end();
    }

    return 0;
}
