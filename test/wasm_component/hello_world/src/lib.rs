use wasi::http::types::{
   Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam,
};

wasi::http::proxy::export!(Component);

struct Component;

impl wasi::exports::http::incoming_handler::Guest for Component {
   fn handle(_request: IncomingRequest, response_out: ResponseOutparam) {

      let hdrs = Fields::new();
      let mesg = String::from("Hello");
      let _try = hdrs.set(&"Content-Type".to_string(), &[b"plain/text".to_vec()]);
      let _try = hdrs.set(&"Content-Length".to_string(), &[mesg.len().to_string().as_bytes().to_vec()]);

      let resp = OutgoingResponse::new(hdrs);

      // Add the HTTP Response Status Code
      resp.set_status_code(200).unwrap();

      let body = resp.body().unwrap();
      ResponseOutparam::set(response_out, Ok(resp));

      let out = body.write().unwrap();
      out.blocking_write_and_flush(mesg.as_bytes()).unwrap();
      drop(out);

      OutgoingBody::finish(body, None).unwrap();
   }
}
