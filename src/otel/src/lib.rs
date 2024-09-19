use opentelemetry::global::BoxedSpan;
use opentelemetry::trace::{
    Span, SpanBuilder, SpanKind, TraceId, Tracer, TracerProvider,
};
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::Protocol;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::{Config, BatchConfigBuilder};
use opentelemetry_sdk::{runtime, Resource};
use std::ffi::{CStr, CString};
use std::ptr;
use std::ptr::addr_of;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};


const TRACEPARENT_HEADER_LEN: u8 = 55;


// Stored sender channel to send spans or a shutdown message to within the
// Tokio runtime.
unsafe fn span_tx(destruct: bool) -> *const OnceLock<Sender<SpanMessage>> {
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
unsafe fn nxt_otel_is_init() -> u8 {
    (*span_tx(false)).get().map_or(0, |_| 1)
}

#[no_mangle]
unsafe fn nxt_otel_uninit() {
    if nxt_otel_is_init() == 1 {
        nxt_otel_shutdown_tracer();
        span_tx(true);
    }
}

// potentially returns an error message
#[no_mangle]
unsafe fn nxt_otel_init(
    log_callback: unsafe extern "C" fn(*mut i8),
    endpoint: *const i8,
    protocol: *const i8,
    batch_size: f64
) {
    if endpoint.is_null() ||
       protocol.is_null() {
        return
    }

    let ep = CStr::from_ptr(endpoint as _)
        .to_string_lossy()
        .into_owned();

    let proto: Protocol;
    match CStr::from_ptr(protocol as _)
        .to_str()
        .or::<Result<String, ()>>(Ok("<invalid unicode>"))
        .unwrap()
        .to_lowercase()
        .as_str() {
            "http" => proto = Protocol::HttpBinary,
            "grpc" => proto = Protocol::Grpc,
            e => {
                let msg_string = format!("unknown tracer type: {:#?}", e);
                let msg = CString::from_vec_unchecked(msg_string.as_bytes().to_vec());
                log_callback(msg.into_raw() as _);
                return;
            }
        }

    // make sure we are starting with a clean state
    nxt_otel_uninit();

    // Create a new mpsc channel. Tokio runtime gets receiver, the send
    // trace function gets sender.
    let (tx, rx): (Sender<SpanMessage>, Receiver<SpanMessage>) = mpsc::channel(32);

    // Store the sender so the other function can also reach it.
    match (*span_tx(false)).set(tx) {
        /* spawn a new thread with the tokio runtime and forget about it.
         * This function will return that allows the C code to carry on
         * doing its thing, whereas the runtime function is a long lived
         * process that only exits when a shutdown message is sent.
         */
        Ok(_) => {
            std::thread::spawn(move || runtime(
                log_callback,
                ep,
                proto,
                batch_size,
                rx
            ));
        },
        Err(e) => {
            let msg_string = format!("couldn't initialize tracer: {:#?}", e);
            let msg = CString::from_vec_unchecked(msg_string.as_bytes().to_vec());
            log_callback(msg.into_raw() as _);
        }
    }
}


/* function that we wrap around Tokio's runtime code. This is long lived,
 * which means it stops only when a shutdown signal is sent to the rx
 * channel, or we terminate the process and leave memory all over.
 */
#[tokio::main]
async unsafe fn runtime(
    log_callback: unsafe extern "C" fn(*mut i8),
    endpoint: String,
    proto: Protocol,
    batch_size: f64,
    mut rx: Receiver<SpanMessage>
) {
    let otlp_exporter = opentelemetry_otlp::new_exporter()
        .http()
        .with_endpoint(endpoint)
        .with_protocol(proto)
        .with_timeout(Duration::new(10, 0));

    // Then pass it into pipeline builder
    let res = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_trace_config(Config::default().with_resource(
            Resource::new(vec![KeyValue::new(
                opentelemetry_semantic_conventions::resource::SERVICE_NAME,
                "NGINX Unit",
            )]),
        ))
        .with_batch_config(
            BatchConfigBuilder::default()
                .with_max_export_batch_size(batch_size as _)
                .build()
        )
        .with_exporter(otlp_exporter)
        .install_batch(runtime::Tokio);


    match res {
        Err(e) => {
            let msg = CString::from_vec_unchecked(e.to_string().as_bytes().to_vec());
            log_callback(msg.into_raw() as _)
        }
        Ok(t) => {
            global::set_tracer_provider(t);
            let msg = CString::from_vec_unchecked("otel exporter has been initialised".as_bytes().to_vec());
            log_callback(msg.into_raw() as _);
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
                // do nothing, because the point is for this _s var to be dropped here
                // rather than where it was sent from.
            }
        }
    }
}

// it's on the caller to pass in a buf of proper length
#[no_mangle]
pub unsafe fn nxt_otel_copy_traceparent(buf: *mut i8, span: *const BoxedSpan) {
    if buf.is_null() || span.is_null() {
        return;
    }

    let traceparent = format!(
        "00-{:032x}-{:016x}-{:02x}",
        (*span).span_context().trace_id(), // 16 chars, 32 hex
        (*span).span_context().span_id(),  // 8 byte, 16 hex
        (*span).span_context().trace_flags()  // 1 char, 2 hex
    );

    assert_eq!(traceparent.len(), TRACEPARENT_HEADER_LEN);

    ptr::copy_nonoverlapping(
        traceparent.as_bytes().as_ptr(),
        buf as _,
        TRACEPARENT_HEADER_LEN,
    );
    // set null terminator
    *buf.add(TRACEPARENT_HEADER_LEN) = b'\0' as _;
}

#[no_mangle]
pub unsafe fn nxt_otel_add_event_to_trace(
    trace: *mut BoxedSpan,
    key: *mut i8,
    val: *mut i8,
) {
    if !key.is_null() && !val.is_null() && !trace.is_null() {
        /* We need .into_owned() here because when using the batch exporter, when the
         * trace gets exported, the request object that these pointers pointed to
         * no longer exists.
         */
        let key = CStr::from_ptr(key as _).to_string_lossy().into_owned();
        let val = CStr::from_ptr(val as _).to_string_lossy().into_owned();

        (*trace)
            .add_event(String::from("Unit Attribute"), vec![KeyValue::new(key, val)]);
    }
}

#[no_mangle]
pub unsafe fn nxt_otel_get_or_create_trace(trace_id: *mut i8) -> *mut BoxedSpan {
    let mut trace_key = None;
    let trace_cstr: &CStr;
    if !trace_id.is_null() {
        trace_cstr = CStr::from_ptr(trace_id as _);
        // We need .into_owned() here as well to avoid referencing a deallocated piece of memory.
        if let Ok(id) = TraceId::from_hex(&trace_cstr.to_string_lossy().into_owned()) {
            trace_key = Some(id);
        }
    }

    let span = global::tracer_provider().tracer("NGINX Unit").build(SpanBuilder {
            trace_id: trace_key,
            span_kind: Some(SpanKind::Server),
            ..Default::default()
        });

    Arc::<BoxedSpan>::into_raw(Arc::new(span)) as *mut BoxedSpan
}

#[no_mangle]
#[tokio::main]
pub async unsafe fn nxt_otel_send_trace(trace: *mut BoxedSpan) {
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
    (*span_tx(false))
        .get()
        .unwrap()
        .try_send(SpanMessage::Span { s: arc_span })
        .unwrap();
}

/* Function to send a shutdown signal to the tokio runtime.
 * The receive loop will break and exit.
 * It might be better to close the channels here instead.
 */
#[no_mangle]
pub unsafe fn nxt_otel_shutdown_tracer() {
    (*span_tx(false))
        .get()
        .unwrap()
        .try_send(SpanMessage::Shutdown)
        .unwrap();
}
