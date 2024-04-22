use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt::Debug;
use std::future::Future;
use std::rc::Rc;
use std::{fmt, io};

use custom_error::custom_error;
use hyper::body::{Buf, HttpBody};
use hyper::client::{HttpConnector, ResponseFuture};
use hyper::Error as HyperError;
use hyper::{http, Body, Client, Request};
use hyper_tls::HttpsConnector;
use hyperlocal::{UnixClientExt, UnixConnector};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

use crate::control_socket_address::ControlSocket;
use unit_openapi::apis::configuration::Configuration;
use unit_openapi::apis::{Error as OpenAPIError, StatusApi};
use unit_openapi::apis::{ListenersApi, ListenersApiClient, StatusApiClient};
use unit_openapi::models::{ConfigListener, Status};

const USER_AGENT: &str = concat!("UNIT CLI/", env!("CARGO_PKG_VERSION"), "/rust");

custom_error! {pub UnitClientError
    OpenAPIError { source: OpenAPIError } = "OpenAPI error",
    JsonError { source: serde_json::Error,
                path: String} = "JSON error [path={path}]",
    HyperError { source: hyper::Error,
                 control_socket_address: String,
                 path: String} = "Communications error [control_socket_address={control_socket_address}, path={path}]: {source}",
    HttpRequestError { source: http::Error,
                       path: String} = "HTTP error [path={path}]",
    HttpResponseError { status: http::StatusCode,
                        path: String,
                        body: String} = "HTTP response error [path={path}, status={status}]:\n{body}",
    HttpResponseJsonBodyError { status: http::StatusCode,
                                path: String,
                                error: String,
                                detail: String} = "HTTP response error [path={path}, status={status}]:\n  Error: {error}\n  Detail: {detail}",
    IoError { source: io::Error, socket: String } = "IO error [socket={socket}]",
    UnixSocketAddressError {
        source: io::Error,
        control_socket_address: String
    } = "Invalid unix domain socket address [control_socket_address={control_socket_address}]",
    SocketPermissionsError { control_socket_address: String } =
    "Insufficient permissions to connect to control socket [control_socket_address={control_socket_address}]",
    UnixSocketNotFound { control_socket_address: String } = "Unix socket not found [control_socket_address={control_socket_address}]",
    TcpSocketAddressUriError {
        source: http::uri::InvalidUri,
        control_socket_address: String
    } = "Invalid TCP socket address [control_socket_address={control_socket_address}]",
    TcpSocketAddressParseError {
        message: String,
        control_socket_address: String
    } = "Invalid TCP socket address [control_socket_address={control_socket_address}]: {message}",
    TcpSocketAddressNoPortError {
        control_socket_address: String
    } = "TCP socket address does not have a port specified [control_socket_address={control_socket_address}]",
    UnitdProcessParseError {
        message: String,
        pid: u64
    } = "{message} for [pid={pid}]",
    UnitdProcessExecError {
        source: Box<dyn StdError>,
        message: String,
        executable_path: String,
        pid: u64
    } = "{message} for [pid={pid}, executable_path={executable_path}]: {source}",
}

impl UnitClientError {
    fn new(error: HyperError, control_socket_address: String, path: String) -> Self {
        if error.is_connect() {
            if let Some(source) = error.source() {
                if let Some(io_error) = source.downcast_ref::<io::Error>() {
                    if io_error.kind().eq(&io::ErrorKind::PermissionDenied) {
                        return UnitClientError::SocketPermissionsError { control_socket_address };
                    }
                }
            }
        }

        UnitClientError::HyperError {
            source: error,
            control_socket_address,
            path,
        }
    }
}

macro_rules! new_openapi_client_from_hyper_client {
    ($unit_client:expr, $hyper_client: ident, $api_client:ident, $api_trait:ident) => {{
        let config = Configuration {
            base_path: $unit_client.control_socket.create_uri_with_path("/").to_string(),
            user_agent: Some(format!("{}/OpenAPI-Generator", USER_AGENT).to_owned()),
            client: $hyper_client.clone(),
            basic_auth: None,
            oauth_access_token: None,
            api_key: None,
        };
        let rc_config = Rc::new(config);
        Box::new($api_client::new(rc_config)) as Box<dyn $api_trait>
    }};
}

macro_rules! new_openapi_client {
    ($unit_client:expr, $api_client:ident, $api_trait:ident) => {
        match &*$unit_client.client {
            RemoteClient::Tcp { client } => {
                new_openapi_client_from_hyper_client!($unit_client, client, $api_client, $api_trait)
            }
            RemoteClient::Unix { client } => {
                new_openapi_client_from_hyper_client!($unit_client, client, $api_client, $api_trait)
            }
        }
    };
}

#[derive(Clone)]
pub enum RemoteClient<B>
where
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    Unix {
        client: Client<UnixConnector, B>,
    },
    Tcp {
        client: Client<HttpsConnector<HttpConnector>, B>,
    },
}

impl<B> RemoteClient<B>
where
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    fn client_name(&self) -> &str {
        match self {
            RemoteClient::Unix { .. } => "Client<UnixConnector, Body>",
            RemoteClient::Tcp { .. } => "Client<HttpsConnector<HttpConnector>, Body>",
        }
    }

    pub fn request(&self, req: Request<B>) -> ResponseFuture {
        match self {
            RemoteClient::Unix { client } => client.request(req),
            RemoteClient::Tcp { client } => client.request(req),
        }
    }
}

impl<B> Debug for RemoteClient<B>
where
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.client_name())
    }
}

#[derive(Debug)]
pub struct UnitClient {
    pub control_socket: ControlSocket,
    /// A `current_thread` runtime for executing operations on the
    /// asynchronous client in a blocking manner.
    rt: Runtime,
    /// Client for communicating with the control API over the UNIX domain socket
    client: Box<RemoteClient<Body>>,
}

impl UnitClient {
    pub fn new_with_runtime(control_socket: ControlSocket, runtime: Runtime) -> Self {
        if control_socket.is_local_socket() {
            Self::new_unix(control_socket, runtime)
        } else {
            Self::new_http(control_socket, runtime)
        }
    }

    pub fn new(control_socket: ControlSocket) -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Unable to create a current_thread runtime");
        Self::new_with_runtime(control_socket, runtime)
    }

    pub fn new_http(control_socket: ControlSocket, runtime: Runtime) -> Self {
        let remote_client = Client::builder().build(HttpsConnector::new());
        Self {
            control_socket,
            rt: runtime,
            client: Box::from(RemoteClient::Tcp { client: remote_client }),
        }
    }

    pub fn new_unix(control_socket: ControlSocket, runtime: Runtime) -> UnitClient {
        let remote_client = Client::unix();

        Self {
            control_socket,
            rt: runtime,
            client: Box::from(RemoteClient::Unix { client: remote_client }),
        }
    }

    /// Sends a request to UNIT and deserializes the JSON response body into the value of type `RESPONSE`.
    pub fn send_request_and_deserialize_response<RESPONSE: for<'de> serde::Deserialize<'de>>(
        &self,
        mut request: Request<Body>,
    ) -> Result<RESPONSE, UnitClientError> {
        let uri = request.uri().clone();
        let path: &str = uri.path();

        request.headers_mut().insert("User-Agent", USER_AGENT.parse().unwrap());

        let response_future = self.client.request(request);

        self.rt.block_on(async {
            let response = response_future
                .await
                .map_err(|error| UnitClientError::new(error, self.control_socket.to_string(), path.to_string()))?;

            let status = response.status();
            let body = hyper::body::aggregate(response)
                .await
                .map_err(|error| UnitClientError::new(error, self.control_socket.to_string(), path.to_string()))?;
            let reader = &mut body.reader();
            if !status.is_success() {
                let error: HashMap<String, String> =
                    serde_json::from_reader(reader).map_err(|error| UnitClientError::JsonError {
                        source: error,
                        path: path.to_string(),
                    })?;

                return Err(UnitClientError::HttpResponseJsonBodyError {
                    status,
                    path: path.to_string(),
                    error: error.get("error").unwrap_or(&"Unknown error".into()).to_string(),
                    detail: error.get("detail").unwrap_or(&"".into()).to_string(),
                });
            }
            serde_json::from_reader(reader).map_err(|error| UnitClientError::JsonError {
                source: error,
                path: path.to_string(),
            })
        })
    }

    pub fn listeners_api(&self) -> Box<dyn ListenersApi + 'static> {
        new_openapi_client!(self, ListenersApiClient, ListenersApi)
    }

    pub fn listeners(&self) -> Result<HashMap<String, ConfigListener>, Box<UnitClientError>> {
        let list_listeners = self.listeners_api().get_listeners();
        self.execute_openapi_future(list_listeners)
    }

    pub fn execute_openapi_future<F: Future<Output = Result<R, OpenAPIError>>, R: for<'de> serde::Deserialize<'de>>(
        &self,
        future: F,
    ) -> Result<R, Box<UnitClientError>> {
        self.rt.block_on(future).map_err(|error| {
            let remapped_error = if let OpenAPIError::Hyper(hyper_error) = error {
                UnitClientError::new(hyper_error, self.control_socket.to_string(), "".to_string())
            } else {
                UnitClientError::OpenAPIError { source: error }
            };

            Box::new(remapped_error)
        })
    }

    pub fn status_api(&self) -> Box<dyn StatusApi + 'static> {
        new_openapi_client!(self, StatusApiClient, StatusApi)
    }

    pub fn status(&self) -> Result<Status, Box<UnitClientError>> {
        let status = self.status_api().get_status();
        self.execute_openapi_future(status)
    }

    pub fn is_running(&self) -> bool {
        self.status().is_ok()
    }
}

pub type UnitSerializableMap = HashMap<String, serde_json::Value>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnitStatus {
    pub connections: UnitStatusConnections,
    pub requests: UnitStatusRequests,
    pub applications: HashMap<String, UnitStatusApplication>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnitStatusConnections {
    #[serde(default)]
    pub closed: usize,
    #[serde(default)]
    pub idle: usize,
    #[serde(default)]
    pub active: usize,
    #[serde(default)]
    pub accepted: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnitStatusRequests {
    #[serde(default)]
    pub active: usize,
    #[serde(default)]
    pub total: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnitStatusApplication {
    #[serde(default)]
    pub processes: HashMap<String, usize>,
    #[serde(default)]
    pub requests: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use crate::unitd_instance::UnitdInstance;

    use super::*;
    // Integration tests

    #[test]
    fn can_connect_to_unit_api() {
        match UnitdInstance::running_unitd_instances().first() {
            Some(unit_instance) => {
                let control_api_socket_address = unit_instance
                    .control_api_socket_address()
                    .expect("No control API socket path found");
                let control_socket = ControlSocket::try_from(control_api_socket_address)
                    .expect("Unable to parse control socket address");
                let unit_client = UnitClient::new(control_socket);
                assert!(unit_client.is_running());
            }
            None => {
                eprintln!("No running unitd instances found - skipping test");
            }
        }
    }

    #[test]
    fn can_get_unit_status() {
        match UnitdInstance::running_unitd_instances().first() {
            Some(unit_instance) => {
                let control_api_socket_address = unit_instance
                    .control_api_socket_address()
                    .expect("No control API socket path found");
                let control_socket = ControlSocket::try_from(control_api_socket_address)
                    .expect("Unable to parse control socket address");
                let unit_client = UnitClient::new(control_socket);
                let status = unit_client.status().expect("Unable to get unit status");
                println!("Unit status: {:?}", status);
            }
            None => {
                eprintln!("No running unitd instances found - skipping test");
            }
        }
    }

    #[test]
    fn can_get_unit_listeners() {
        match UnitdInstance::running_unitd_instances().first() {
            Some(unit_instance) => {
                let control_api_socket_address = unit_instance
                    .control_api_socket_address()
                    .expect("No control API socket path found");
                let control_socket = ControlSocket::try_from(control_api_socket_address)
                    .expect("Unable to parse control socket address");
                let unit_client = UnitClient::new(control_socket);
                unit_client.listeners().expect("Unable to get Unit listeners");
            }
            None => {
                eprintln!("No running unitd instances found - skipping test");
            }
        }
    }
}
