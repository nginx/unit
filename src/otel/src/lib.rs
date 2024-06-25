use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use opentelemetry::trace::{
    Span, SpanBuilder, SpanKind, TraceId, Tracer, TracerProvider,
};
use opentelemetry::KeyValue;
use opentelemetry_otlp::{Protocol::HttpBinary, WithExportConfig};
use opentelemetry_sdk::trace::{Config, Span as SpanImpl, TracerProvider as TracerProviderImpl};
use opentelemetry_sdk::Resource;

// otel_endpoint is hardcoded for phase 1 purposes.
const OTEL_TRACES_ENDPOINT: &str = "http://lgtm:4318/v1/traces";

static GLOBAL_TRACER_PROVIDER: OnceLock<TracerProviderImpl> = OnceLock::new();

// potentially returns an error message
#[no_mangle]
unsafe fn nxt_otel_init(log_callback: unsafe extern "C" fn(*mut i8)) {
    let otlp_exporter = opentelemetry_otlp::new_exporter()
        .http()
        .with_endpoint(OTEL_TRACES_ENDPOINT)
        .with_protocol(HttpBinary)
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
        .with_exporter(otlp_exporter)
        .install_simple();

    // unwrap
    match res {
        Err(e) => {
            let msg = CString::from_vec_unchecked(e.to_string().as_bytes().to_vec());
            log_callback(msg.into_raw() as _)
        },
        Ok(t) => {
            GLOBAL_TRACER_PROVIDER.get_or_init(move || t);
            let msg = CString::from_vec_unchecked("otel exporter has been initialised".as_bytes().to_vec());
            log_callback(msg.into_raw() as _);
        }
    }
}

// it's on the caller to pass in a buf of proper length
#[no_mangle]
pub unsafe fn nxt_otel_copy_traceparent(buf: *mut i8, span: *const SpanImpl) {
    if buf.is_null() || span.is_null() {
        return;
    }

    let traceparent = format!(
        "00-{:032x}-{:016x}-{:02x}",
        (*span).span_context().trace_id(), // 16 chars, 32 hex
        (*span).span_context().span_id(),  // 8 byte, 16 hex
        (*span).span_context().trace_flags()  // 1 char, 2 hex
    );

    assert_eq!(traceparent.len(), 55);

    ptr::copy_nonoverlapping(
        traceparent.as_bytes().as_ptr(),
        buf as _,
        55,
    );
    // set null terminator
    *buf.add(55) = b'\0' as _;
}

#[no_mangle]
pub unsafe fn nxt_otel_add_event_to_trace(
    trace: *mut SpanImpl,
    key: *mut i8,
    val: *mut i8,
) {
    if !key.is_null() && !val.is_null() && !trace.is_null() {
        let key = CStr::from_ptr(key as _).to_string_lossy();
        let val = CStr::from_ptr(val as _).to_string_lossy();

        (*trace)
            .add_event(String::from("Unit Attribute"), vec![KeyValue::new(key, val)]);
    }
}

#[no_mangle]
pub unsafe fn nxt_otel_get_or_create_trace(trace_id: *mut i8) -> *mut SpanImpl {
    let mut trace_key = None;
    let trace_cstr: &CStr;
    if !trace_id.is_null() {
        trace_cstr = CStr::from_ptr(trace_id as _);
        if let Ok(id) = TraceId::from_hex(&trace_cstr.to_string_lossy()) {
            trace_key = Some(id);
        }
    }

    let span: SpanImpl;
    if let Some(provider) = GLOBAL_TRACER_PROVIDER.get() {
        span = provider.tracer("NGINX Unit").build(SpanBuilder {
            trace_id: trace_key,
            span_kind: Some(SpanKind::Server),
            ..Default::default()
        });
    } else {
        return ptr::null::<SpanImpl>() as *mut SpanImpl;
    }

    Arc::<SpanImpl>::into_raw(Arc::new(span)) as *mut SpanImpl
}

#[no_mangle]
#[tokio::main]
pub async unsafe fn nxt_otel_send_trace(trace: *mut SpanImpl) {
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

    /* simple exporter will export spans when dropped
     * aka at end of this function
     * One final thing we can do here is check
     * the strong count of the Arc. If it is not
     * now one, we can decrement manually to ensure
     * that is goes out of scope here.
     */
}
