#![allow(non_camel_case_types)]

use opentelemetry::global::BoxedSpan;
use opentelemetry::trace::{
    Span, SpanBuilder, SpanKind, TraceId, Tracer, TracerProvider,
};
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::Protocol;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::{Config, BatchConfigBuilder, Sampler};
use opentelemetry_sdk::{runtime, Resource};
use std::ffi::{c_char, CStr, CString};
use std::{ptr, time};
use std::ptr::addr_of;
use std::slice;
use std::sync::{Arc, OnceLock};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

const TRACEPARENT_HEADER_LEN: u8 = 55;
const TIMEOUT: time::Duration = std::time::Duration::from_secs(10);

const NXT_LOG_ERR:    nxt_uint_t = 1;

#[repr(C)]
pub struct nxt_str_t {
    pub length: usize,
    pub start: *const u8,
}

#[cfg(target_arch = "x86_64")]
pub type nxt_uint_t = ::std::os::raw::c_uint;

#[cfg(not(target_arch = "x86_64"))]
pub type nxt_uint_t = usize;

// Stored sender channel to send spans or a shutdown message to within the
// Tokio runtime.
#[allow(static_mut_refs)]
unsafe fn nxt_otel_rs_span_tx(destruct: bool) -> *const OnceLock<Sender<SpanMessage>> {
    static mut SPAN_TX: OnceLock<Sender<SpanMessage>> = OnceLock::new();
    if destruct {
        SPAN_TX.take();
    }

    addr_of!(SPAN_TX)
}

// Message type to send on the channel. Either a span or a shutdown message for
// graceful termination of the tokio runtime.
enum SpanMessage {
    Span {
        s: Arc<BoxedSpan>
    },
    Shutdown,
}

#[no_mangle]
unsafe fn nxt_otel_rs_is_init() -> u8 {
    (*nxt_otel_rs_span_tx(false)).get().map_or(0, |_| 1)
}

#[no_mangle]
unsafe fn nxt_otel_rs_uninit() {
    if nxt_otel_rs_is_init() == 1 {
        nxt_otel_rs_shutdown_tracer();
        nxt_otel_rs_span_tx(true);
    }
}

// potentially returns an error message
#[no_mangle]
unsafe fn nxt_otel_rs_init(
    log_callback: unsafe extern "C" fn(log_level: nxt_uint_t, msg: *const c_char),
    endpoint: *const nxt_str_t,
    protocol: *const nxt_str_t,
    sample_fraction: f64,
    batch_size: f64
) {
    if endpoint.is_null() || protocol.is_null() {
        return
    }

    let ep = String::from_utf8_unchecked(
        slice::from_raw_parts((*endpoint).start, (*endpoint).length).to_vec()
    ).clone(); // we want our own memory

    let proto: Protocol;
    match String::from_utf8_unchecked(
        slice::from_raw_parts((*protocol).start, (*protocol).length).to_vec()
    ).to_lowercase()
        .as_str() {
            "http" => proto = Protocol::HttpBinary,
            "grpc" => proto = Protocol::Grpc,
            e => {
                let msg_string = format!("unknown tracer type: {:#?}", e);
                let msg = CString::from_vec_unchecked(msg_string.as_bytes().to_vec());
                log_callback(NXT_LOG_ERR, msg.into_raw() as _);
                return;
            }
        }

    // make sure we are starting with a clean state
    nxt_otel_rs_uninit();

    // Create a new mpsc channel. Tokio runtime gets receiver, the send
    // trace function gets sender.
    let (tx, rx): (Sender<SpanMessage>, Receiver<SpanMessage>) = mpsc::channel(32);

    // Store the sender so the other function can also reach it.
    match (*nxt_otel_rs_span_tx(false)).set(tx) {
        /* spawn a new thread with the tokio runtime and forget about it.
         * This function will return that allows the C code to carry on
         * doing its thing, whereas the runtime function is a long lived
         * process that only exits when a shutdown message is sent.
         */
        Ok(_) => {
            std::thread::spawn(move || nxt_otel_rs_runtime(
                ep,
                proto,
                batch_size,
                sample_fraction,
                rx
            ));
        },
        Err(e) => {
            let msg_string = format!("couldn't initialize tracer: {:#?}", e);
            let msg = CString::from_vec_unchecked(msg_string.as_bytes().to_vec());
            log_callback(NXT_LOG_ERR, msg.into_raw() as _);
        }
    }
}


/* function that we wrap around Tokio's runtime code. This is long lived,
 * which means it stops only when a shutdown signal is sent to the rx
 * channel, or we terminate the process and leave memory all over.
 */
#[tokio::main]
async unsafe fn nxt_otel_rs_runtime(
    endpoint: String,
    proto: Protocol,
    batch_size: f64,
    sample_fraction: f64,
    mut rx: Receiver<SpanMessage>
) {
    let pipeline = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_trace_config(
            Config::default()
                .with_resource(
                    Resource::new(vec![KeyValue::new(
                        opentelemetry_semantic_conventions::resource::SERVICE_NAME,
                        "NGINX Unit",
                    )])
                )
                .with_sampler(Sampler::TraceIdRatioBased(sample_fraction))
        )
        .with_batch_config(
            BatchConfigBuilder::default()
                .with_max_export_batch_size(batch_size as _)
                .with_max_queue_size(4096)
                .build()
        );

    let res = match proto {
        Protocol::HttpBinary | Protocol::HttpJson => pipeline
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .http()
                    .with_http_client(reqwest::Client::new()) // needed because rustls feature
                    .with_endpoint(endpoint)
                    .with_protocol(proto)
                    .with_timeout(TIMEOUT)
            ).install_batch(runtime::Tokio),
        Protocol::Grpc => pipeline
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(endpoint)
                    .with_protocol(proto)
                    .with_timeout(TIMEOUT)
            ).install_batch(runtime::Tokio),
    };

    match res {
        Err(e) => {
            eprintln!("otel tracing error: {}", e);
            return;
        }
        Ok(t) => {
            global::set_tracer_provider(t);
        }
    }

    // this is the block that keeps this function running until it gets shut down.
    // @see https://tokio.rs/tokio/tutorial/channels for the inspiration.
    while let Some(message) = rx.recv().await {
        match message {
            SpanMessage::Shutdown => {
                eprintln!("it was a shutdown");
                break;
            }
            SpanMessage::Span { s: _s } => {
                // do nothing, because the point is for this _s var to be dropped
                // here rather than where it was sent from.
            }
        }
    }
}

// it's on the caller to pass in a buf of proper length
#[no_mangle]
pub unsafe fn nxt_otel_rs_copy_traceparent(buf: *mut i8, span: *const BoxedSpan) {
    if buf.is_null() || span.is_null() {
        return;
    }

    let traceparent = format!(
        "00-{:032x}-{:016x}-{:02x}",
        (*span).span_context().trace_id(), // 16 chars, 32 hex
        (*span).span_context().span_id(),  // 8 byte, 16 hex
        (*span).span_context().trace_flags()  // 1 char, 2 hex
    );

    assert_eq!(traceparent.len(), TRACEPARENT_HEADER_LEN as usize);

    ptr::copy_nonoverlapping(
        traceparent.as_bytes().as_ptr(),
        buf as _,
        TRACEPARENT_HEADER_LEN as _,
    );
    // set null terminator
    *buf.add(TRACEPARENT_HEADER_LEN as _) = b'\0' as _;
}

#[no_mangle]
pub unsafe fn nxt_otel_rs_add_event_to_trace(
    trace: *mut BoxedSpan,
    key: *const nxt_str_t,
    val: *const nxt_str_t,
) {
    if !key.is_null() && !val.is_null() && !trace.is_null() {
        /* We need .clone() here because when using the batch exporter, when the
         * trace gets exported, the request object that these pointers pointed to
         * no longer exists.
         */
        let key = String::from_utf8_unchecked(
            slice::from_raw_parts((*key).start, (*key).length).to_vec()
        ).clone();
        let val = String::from_utf8_unchecked(
            slice::from_raw_parts((*val).start, (*val).length).to_vec()
        ).clone();

        (*trace).add_event(
            String::from("Unit Attribute"),
            vec![KeyValue::new(key, val)]
        );
    }
}

#[no_mangle]
pub unsafe fn nxt_otel_rs_get_or_create_trace(trace_id: *mut i8) -> *mut BoxedSpan {
    let mut trace_key = None;
    let trace_cstr: &CStr;
    if !trace_id.is_null() {
        trace_cstr = CStr::from_ptr(trace_id as _);
        // We need .into_owned() here as well to avoid referencing a deallocated piece of memory.
        if let Ok(id) = TraceId::from_hex(&trace_cstr.to_string_lossy().into_owned()) {
            trace_key = Some(id);
        }
    }

    let tracer = global::tracer_provider().tracer("NGINX Unit");
    let span = tracer.build(SpanBuilder {
            trace_id: trace_key,
            span_kind: Some(SpanKind::Server),
            ..Default::default()
        });

    Arc::<BoxedSpan>::into_raw(Arc::new(span)) as *mut BoxedSpan
}

#[no_mangle]
pub unsafe fn nxt_otel_rs_send_trace(trace: *mut BoxedSpan) {
    // damage nothing on an improper call
    if trace.is_null() {
        eprintln!("trace was null, returning");
        return;
    }

    /* memory needs to be accounted for via arc here
     * see the final return statement from
     * nxt_otel_get_or_create_trace
     */
    let arc_span = Arc::from_raw(trace);

    /* Instead of dropping the reference at the end of this function
     * we'll send the entire Arc through the channel to the long
     * running process that will drop it there. The reason we need to
     * drop it there, rather than here is because that code block is
     * within the tokio runtime context with the mpsc channels still
     * open, whereas if we tried to do it here, it would fail for
     * a number of different reasons:
     * - channel closed
     * - not a tokio runtime
     * - different tokio runtime
     */
    (*nxt_otel_rs_span_tx(false))
        .get()
        .and_then(|x| Some(x.try_send(SpanMessage::Span{ s: arc_span })));
}

/* Function to send a shutdown signal to the tokio runtime.
 * The receive loop will break and exit.
 * It might be better to close the channels here instead.
 */
#[no_mangle]
pub unsafe fn nxt_otel_rs_shutdown_tracer() {
    (*nxt_otel_rs_span_tx(false))
        .get()
        .and_then(|x| Some(x.try_send(SpanMessage::Shutdown)));
}
