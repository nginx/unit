use super::inputfile::InputFile;
use super::UnitClient;
use super::UnitSerializableMap;
use super::UnitctlError;
use crate::known_size::KnownSize;
use hyper::{Body, Request};
use rustls_pemfile::Item;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::atomic::AtomicUsize;
use unit_client_rs::unit_client::UnitClientError;

/// Send the contents of a file to the unit server
/// We assume that the file is valid and can be sent to the server
pub async fn send_and_validate_config_deserialize_response(
    client: &UnitClient,
    method: &str,
    path: &str,
    input_file: Option<&InputFile>,
) -> Result<UnitSerializableMap, UnitctlError> {
    let body_data = match input_file {
        Some(input) => Some(input.to_unit_serializable_map()?),
        None => None,
    };

    /* Unfortunately, we have load the json text into memory before sending it to the server.
     * This allows for validation of the json content before sending to the server. There may be
     * a better way of doing this and it is worth investigating. */
    let json = serde_json::to_value(&body_data).map_err(|error| UnitClientError::JsonError {
        source: error,
        path: path.into(),
    })?;

    let mime_type = input_file.map(|f| f.mime_type());
    let reader = KnownSize::String(json.to_string());

    streaming_upload_deserialize_response(client, method, path, mime_type, reader)
        .await
        .map_err(|e| UnitctlError::UnitClientError { source: e })
}

/// Send an empty body to the unit server
pub async fn send_empty_body_deserialize_response(
    client: &UnitClient,
    method: &str,
    path: &str,
) -> Result<UnitSerializableMap, UnitctlError> {
    send_body_deserialize_response(client, method, path, None).await
}

/// Send the contents of a PEM file to the unit server
pub async fn send_and_validate_pem_data_deserialize_response(
    client: &UnitClient,
    method: &str,
    path: &str,
    input_file: &InputFile,
) -> Result<UnitSerializableMap, UnitctlError> {
    let bytes: Vec<u8> = input_file.try_into()?;
    {
        let mut cursor = Cursor::new(&bytes);
        let items = rustls_pemfile::read_all(&mut cursor)
            .map(|item| item.map_err(|e| UnitctlError::IoError { source: e }))
            .collect();
        validate_pem_items(items)?;
    }
    let known_size = KnownSize::Vec((*bytes).to_owned());

    streaming_upload_deserialize_response(client, method, path, Some(input_file.mime_type()), known_size)
        .await
        .map_err(|e| UnitctlError::UnitClientError { source: e })
}

/// Validate the contents of a PEM file
fn validate_pem_items(pem_items: Vec<Result<Item, UnitctlError>>) -> Result<(), UnitctlError> {
    fn item_name(item: Item) -> String {
        match item {
            Item::X509Certificate(_) => "X509Certificate",
            Item::Sec1Key(_) => "Sec1Key",
            Item::Crl(_) => "Crl",
            Item::Pkcs1Key(_) => "Pkcs1Key",
            Item::Pkcs8Key(_) => "Pkcs8Key",
            // Note: this is not a valid PEM item, but rustls_pemfile library defines the enum as non-exhaustive
            _ => "Unknown",
        }
        .to_string()
    }

    if pem_items.is_empty() {
        let error = UnitctlError::CertificateError {
            message: "No certificates found in file".to_string(),
        };
        return Err(error);
    }

    let mut items_tally: HashMap<String, AtomicUsize> = HashMap::new();

    for pem_item_result in pem_items {
        let pem_item = pem_item_result?;
        let key = item_name(pem_item);
        if let Some(count) = items_tally.get_mut(key.clone().as_str()) {
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            items_tally.insert(key, AtomicUsize::new(1));
        }
    }

    let key_count = items_tally
        .iter()
        .filter(|(key, _)| key.ends_with("Key"))
        .fold(0, |acc, (_, count)| {
            acc + count.load(std::sync::atomic::Ordering::Relaxed)
        });
    let cert_count = items_tally
        .iter()
        .filter(|(key, _)| key.ends_with("Certificate"))
        .fold(0, |acc, (_, count)| {
            acc + count.load(std::sync::atomic::Ordering::Relaxed)
        });

    if key_count == 0 {
        let error = UnitctlError::CertificateError {
            message: "No private keys found in file".to_string(),
        };
        return Err(error);
    }
    if cert_count == 0 {
        let error = UnitctlError::CertificateError {
            message: "No certificates found in file".to_string(),
        };
        return Err(error);
    }

    Ok(())
}

pub async fn send_body_deserialize_response<RESPONSE: for<'de> serde::Deserialize<'de>>(
    client: &UnitClient,
    method: &str,
    path: &str,
    input_file: Option<&InputFile>,
) -> Result<RESPONSE, UnitctlError> {
    match input_file {
        Some(input) => {
            streaming_upload_deserialize_response(client, method, path, Some(input.mime_type()), input.try_into()?)
        }
        None => streaming_upload_deserialize_response(client, method, path, None, KnownSize::Empty),
    }
    .await
    .map_err(|e| UnitctlError::UnitClientError { source: e })
}

async fn streaming_upload_deserialize_response<RESPONSE: for<'de> serde::Deserialize<'de>>(
    client: &UnitClient,
    method: &str,
    path: &str,
    mime_type: Option<String>,
    read: KnownSize,
) -> Result<RESPONSE, UnitClientError> {
    let uri = client.control_socket.create_uri_with_path(path);

    let content_length = read.len();
    let body = Body::from(read);

    let mut request = Request::builder()
        .method(method)
        .header("Content-Length", content_length)
        .uri(uri)
        .body(body)
        .expect("Unable to build request");

    if let Some(content_type) = mime_type {
        request
            .headers_mut()
            .insert("Content-Type", content_type.parse().unwrap());
    }

    client.send_request_and_deserialize_response(request).await
}
