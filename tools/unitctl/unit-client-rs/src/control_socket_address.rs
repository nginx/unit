use crate::control_socket_address::ControlSocket::{TcpSocket, UnixLocalAbstractSocket, UnixLocalSocket};
use crate::control_socket_address::ControlSocketScheme::{HTTP, HTTPS};
use crate::unit_client::UnitClientError;
use hyper::http::uri::{Authority, PathAndQuery};
use hyper::Uri;
use std::fmt::{Display, Formatter};
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{PathBuf, MAIN_SEPARATOR};

type AbstractSocketName = String;
type UnixSocketPath = PathBuf;
type Port = u16;

#[derive(Debug, Clone)]
pub enum ControlSocket {
    UnixLocalAbstractSocket(AbstractSocketName),
    UnixLocalSocket(UnixSocketPath),
    TcpSocket(Uri),
}

#[derive(Debug)]
pub enum ControlSocketScheme {
    HTTP,
    HTTPS,
}

impl ControlSocketScheme {
    fn port(&self) -> Port {
        match self {
            HTTP => 80,
            HTTPS => 443,
        }
    }
}


impl Display for ControlSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            UnixLocalAbstractSocket(name) => f.write_fmt(format_args!("unix:@{}", name)),
            UnixLocalSocket(path) => f.write_fmt(format_args!("unix:{}", path.to_string_lossy())),
            TcpSocket(uri) => uri.fmt(f),
        }
    }
}

impl From<ControlSocket> for String {
    fn from(val: ControlSocket) -> Self {
        val.to_string()
    }
}

impl From<ControlSocket> for PathBuf {
    fn from(val: ControlSocket) -> Self {
        match val {
            UnixLocalAbstractSocket(socket_name) => PathBuf::from(format!("@{}", socket_name)),
            UnixLocalSocket(socket_path) => socket_path,
            TcpSocket(_) => PathBuf::default(),
        }
    }
}

impl From<ControlSocket> for Uri {
    fn from(val: ControlSocket) -> Self {
        val.create_uri_with_path("")
    }
}

impl TryFrom<String> for ControlSocket {
    type Error = UnitClientError;

    fn try_from(socket_address: String) -> Result<Self, Self::Error> {
        ControlSocket::parse_address(socket_address.as_str())
    }
}

impl TryFrom<&str> for ControlSocket {
    type Error = UnitClientError;

    fn try_from(socket_address: &str) -> Result<Self, Self::Error> {
        ControlSocket::parse_address(socket_address)
    }
}

impl TryFrom<Uri> for ControlSocket {
    type Error = UnitClientError;

    fn try_from(socket_uri: Uri) -> Result<Self, Self::Error> {
        match socket_uri.scheme_str() {
            // URIs with the unix scheme will have a hostname that is a hex encoded string
            // representing the path to the socket
            Some("unix") => {
                let host = match socket_uri.host() {
                    Some(host) => host,
                    None => {
                        return Err(UnitClientError::TcpSocketAddressParseError {
                            message: "No host found in socket address".to_string(),
                            control_socket_address: socket_uri.to_string(),
                        })
                    }
                };
                let bytes = hex::decode(host).map_err(|error| UnitClientError::TcpSocketAddressParseError {
                    message: error.to_string(),
                    control_socket_address: socket_uri.to_string(),
                })?;
                let path = String::from_utf8_lossy(&bytes);
                ControlSocket::parse_address(path)
            }
            Some("http") | Some("https") => Ok(TcpSocket(socket_uri)),
            Some(unknown) => Err(UnitClientError::TcpSocketAddressParseError {
                message: format!("Unsupported scheme found in socket address: {}", unknown).to_string(),
                control_socket_address: socket_uri.to_string(),
            }),
            None => Err(UnitClientError::TcpSocketAddressParseError {
                message: "No scheme found in socket address".to_string(),
                control_socket_address: socket_uri.to_string(),
            }),
        }
    }
}

impl ControlSocket {
    pub fn socket_scheme(&self) -> ControlSocketScheme {
        match self {
            UnixLocalAbstractSocket(_) => ControlSocketScheme::HTTP,
            UnixLocalSocket(_) => ControlSocketScheme::HTTP,
            TcpSocket(uri) => match uri.scheme_str().expect("Scheme should not be None") {
                "http" => ControlSocketScheme::HTTP,
                "https" => ControlSocketScheme::HTTPS,
                _ => unreachable!("Scheme should be http or https"),
            },
        }
    }

    pub fn create_uri_with_path(&self, str_path: &str) -> Uri {
        match self {
            UnixLocalAbstractSocket(name) => {
                let socket_path = PathBuf::from(format!("@{}", name));
                hyperlocal::Uri::new(socket_path, str_path).into()
            }
            UnixLocalSocket(socket_path) => hyperlocal::Uri::new(socket_path, str_path).into(),
            TcpSocket(uri) => {
                if str_path.is_empty() {
                    uri.clone()
                } else {
                    let authority = uri.authority().expect("Authority should not be None");
                    Uri::builder()
                        .scheme(uri.scheme_str().expect("Scheme should not be None"))
                        .authority(authority.clone())
                        .path_and_query(str_path)
                        .build()
                        .expect("URI should be valid")
                }
            }
        }
    }

    pub fn validate_http_address(uri: Uri) -> Result<(), UnitClientError> {
        let http_address = uri.to_string();
        if uri.authority().is_none() {
            return Err(UnitClientError::TcpSocketAddressParseError {
                message: "No authority found in socket address".to_string(),
                control_socket_address: http_address,
            });
        }
        if uri.port_u16().is_none() {
            return Err(UnitClientError::TcpSocketAddressNoPortError {
                control_socket_address: http_address,
            });
        }
        if !(uri.path().is_empty() || uri.path().eq("/")) {
            return Err(UnitClientError::TcpSocketAddressParseError {
                message: format!("Path is not empty or is not / [path={}]", uri.path()),
                control_socket_address: http_address,
            });
        }

        Ok(())
    }

    pub fn validate_unix_address(socket: PathBuf) -> Result<(), UnitClientError> {
        if !socket.exists() {
            return Err(UnitClientError::UnixSocketNotFound {
                control_socket_address: socket.to_string_lossy().to_string(),
            });
        }
        let metadata = fs::metadata(&socket).map_err(|error| UnitClientError::UnixSocketAddressError {
            source: error,
            control_socket_address: socket.to_string_lossy().to_string(),
        })?;
        let file_type = metadata.file_type();
        if !file_type.is_socket() {
            return Err(UnitClientError::UnixSocketAddressError {
                source: std::io::Error::new(std::io::ErrorKind::Other, "Control socket path is not a socket"),
                control_socket_address: socket.to_string_lossy().to_string(),
            });
        }

        Ok(())
    }

    pub fn validate(&self) -> Result<Self, UnitClientError> {
        match self {
            UnixLocalAbstractSocket(socket_name) => {
                let socket_path = PathBuf::from(format!("@{}", socket_name));
                Self::validate_unix_address(socket_path.clone())
            }
            UnixLocalSocket(socket_path) => Self::validate_unix_address(socket_path.clone()),
            TcpSocket(socket_uri) => Self::validate_http_address(socket_uri.clone()),
        }
        .map(|_| self.to_owned())
    }

    fn normalize_and_parse_http_address(http_address: String) -> Result<Uri, UnitClientError> {
        // Convert *:1 style network addresses to URI format
        let address = if http_address.starts_with("*:") {
            http_address.replacen("*:", "http://127.0.0.1:", 1)
        // Add scheme if not present
        } else if !(http_address.starts_with("http://") || http_address.starts_with("https://")) {
            format!("http://{}", http_address)
        } else {
            http_address.to_owned()
        };

        let is_https = address.starts_with("https://");

        let parsed_uri =
            Uri::try_from(address.as_str()).map_err(|error| UnitClientError::TcpSocketAddressUriError {
                source: error,
                control_socket_address: address,
            })?;
        let authority = parsed_uri.authority().expect("Authority should not be None");
        let expected_port = if is_https { HTTPS.port() } else { HTTP.port() };
        let normalized_authority = match authority.port_u16() {
            Some(_) => authority.to_owned(),
            None => {
                let host = format!("{}:{}", authority.host(), expected_port);
                Authority::try_from(host.as_str()).expect("Authority should be valid")
            }
        };

        let normalized_uri = Uri::builder()
            .scheme(parsed_uri.scheme_str().expect("Scheme should not be None"))
            .authority(normalized_authority)
            .path_and_query(PathAndQuery::from_static(""))
            .build()
            .map_err(|error| UnitClientError::TcpSocketAddressParseError {
                message: error.to_string(),
                control_socket_address: http_address.clone(),
            })?;

        Ok(normalized_uri)
    }

    /// Flexibly parse a textual representation of a socket address
    pub fn parse_address<S: Into<String>>(socket_address: S) -> Result<Self, UnitClientError> {
        let full_socket_address: String = socket_address.into();
        let socket_prefix = "unix:";
        let socket_uri_prefix = "unix://";
        let mut buf = String::with_capacity(socket_prefix.len());
        for (i, c) in full_socket_address.char_indices() {
            // Abstract unix socket with no prefix
            if i == 0 && c == '@' {
                return Ok(UnixLocalAbstractSocket(full_socket_address[1..].to_string()));
            }
            buf.push(c);
            // Unix socket with prefix
            if i == socket_prefix.len() - 1 && buf.eq(socket_prefix) {
                let path_text = full_socket_address[socket_prefix.len()..].to_string();
                // Return here if this URI does not have a scheme followed by double slashes
                if !path_text.starts_with("//") {
                    return match path_text.strip_prefix('@') {
                        Some(name) => Ok(UnixLocalAbstractSocket(name.to_string())),
                        None => {
                            let path = PathBuf::from(path_text);
                            Ok(UnixLocalSocket(path))
                        }
                    };
                }
            }

            // Unix socket with URI prefix
            if i == socket_uri_prefix.len() - 1 && buf.eq(socket_uri_prefix) {
                let uri = Uri::try_from(full_socket_address.as_str()).map_err(|error| {
                    UnitClientError::TcpSocketAddressParseError {
                        message: error.to_string(),
                        control_socket_address: full_socket_address.clone(),
                    }
                })?;
                return ControlSocket::try_from(uri);
            }
        }

        /* Sockets on Windows are not supported, so there is no need to check
         * if the socket address is a valid path, so we can do this shortcut
         * here to see if a path was specified without a unix: prefix. */
        if buf.starts_with(MAIN_SEPARATOR) {
            let path = PathBuf::from(buf);
            return Ok(UnixLocalSocket(path));
        }

        let uri = Self::normalize_and_parse_http_address(buf)?;
        Ok(TcpSocket(uri))
    }

    pub fn is_local_socket(&self) -> bool {
        match self {
            UnixLocalAbstractSocket(_) | UnixLocalSocket(_) => true,
            TcpSocket(_) => false,
        }
    }
}


#[cfg(test)]
mod tests {
    use rand::distributions::{Alphanumeric, DistString};
    use std::env::temp_dir;
    use std::fmt::Display;
    use std::io;
    use std::os::unix::net::UnixListener;

    use super::*;

    struct TempSocket {
        socket_path: PathBuf,
        _listener: UnixListener,
    }

    impl TempSocket {
        fn shutdown(&mut self) -> io::Result<()> {
            fs::remove_file(&self.socket_path)
        }
    }

    impl Display for TempSocket {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "unix:{}", self.socket_path.to_string_lossy().to_string())
        }
    }

    impl Drop for TempSocket {
        fn drop(&mut self) {
            self.shutdown()
                .expect(format!("Unable to shutdown socket {}", self.socket_path.to_string_lossy()).as_str());
        }
    }

    #[test]
    fn will_error_with_nonexistent_unix_socket() {
        let socket_address = "unix:/tmp/some_random_filename_that_doesnt_exist.sock";
        let control_socket =
            ControlSocket::try_from(socket_address).expect("No error should be returned until validate() is called");
        assert!(control_socket.is_local_socket(), "Not parsed as a local socket");
        assert!(control_socket.validate().is_err(), "Socket should not be valid");
    }

    #[test]
    fn can_parse_socket_with_prefix() {
        let temp_socket = create_file_socket().expect("Unable to create socket");
        let control_socket = ControlSocket::try_from(temp_socket.to_string()).expect("Error parsing good socket path");
        assert!(control_socket.is_local_socket(), "Not parsed as a local socket");
        if let Err(e) = control_socket.validate() {
            panic!("Socket should be valid: {}", e);
        }
    }

    #[test]
    fn can_parse_socket_from_uri() {
        let temp_socket = create_file_socket().expect("Unable to create socket");
        let uri: Uri = hyperlocal::Uri::new(temp_socket.socket_path.clone(), "").into();
        let control_socket = ControlSocket::try_from(uri).expect("Error parsing good socket path");
        assert!(control_socket.is_local_socket(), "Not parsed as a local socket");
        if let Err(e) = control_socket.validate() {
            panic!("Socket should be valid: {}", e);
        }
    }

    #[test]
    fn can_parse_socket_from_uri_text() {
        let temp_socket = create_file_socket().expect("Unable to create socket");
        let uri: Uri = hyperlocal::Uri::new(temp_socket.socket_path.clone(), "").into();
        let control_socket = ControlSocket::parse_address(uri.to_string()).expect("Error parsing good socket path");
        assert!(control_socket.is_local_socket(), "Not parsed as a local socket");
        if let Err(e) = control_socket.validate() {
            panic!("Socket for input text should be valid: {}", e);
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn can_parse_abstract_socket_from_uri() {
        let temp_socket = create_abstract_socket().expect("Unable to create socket");
        let uri: Uri = hyperlocal::Uri::new(temp_socket.socket_path.clone(), "").into();
        let control_socket = ControlSocket::try_from(uri).expect("Error parsing good socket path");
        assert!(control_socket.is_local_socket(), "Not parsed as a local socket");
        if let Err(e) = control_socket.validate() {
            panic!("Socket should be valid: {}", e);
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn can_parse_abstract_socket_from_uri_text() {
        let temp_socket = create_abstract_socket().expect("Unable to create socket");
        let uri: Uri = hyperlocal::Uri::new(temp_socket.socket_path.clone(), "").into();
        let control_socket = ControlSocket::parse_address(uri.to_string()).expect("Error parsing good socket path");
        assert!(control_socket.is_local_socket(), "Not parsed as a local socket");
        if let Err(e) = control_socket.validate() {
            panic!("Socket should be valid: {}", e);
        }
    }

    #[test]
    fn can_parse_socket_without_prefix() {
        let temp_socket = create_file_socket().expect("Unable to create socket");
        let control_socket = ControlSocket::try_from(temp_socket.socket_path.to_string_lossy().to_string())
            .expect("Error parsing good socket path");
        assert!(control_socket.is_local_socket(), "Not parsed as a local socket");
        if let Err(e) = control_socket.validate() {
            panic!("Socket should be valid: {}", e);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn can_parse_abstract_socket() {
        let temp_socket = create_abstract_socket().expect("Unable to create socket");
        let control_socket = ControlSocket::try_from(temp_socket.to_string()).expect("Error parsing good socket path");
        assert!(control_socket.is_local_socket(), "Not parsed as a local socket");
        if let Err(e) = control_socket.validate() {
            panic!("Socket should be valid: {}", e);
        }
    }

    #[test]
    fn can_normalize_good_http_socket_addresses() {
        let valid_socket_addresses = vec![
            "http://127.0.0.1:8080",
            "https://127.0.0.1:8080",
            "http://127.0.0.1:8080/",
            "127.0.0.1:8080",
            "http://0.0.0.0:8080",
            "https://0.0.0.0:8080",
            "http://0.0.0.0:8080/",
            "0.0.0.0:8080",
            "http://localhost:8080",
            "https://localhost:8080",
            "http://localhost:8080/",
            "localhost:8080",
            "http://[::1]:8080",
            "https://[::1]:8080",
            "http://[::1]:8080/",
            "[::1]:8080",
            "http://[0000:0000:0000:0000:0000:0000:0000:0000]:8080",
            "https://[0000:0000:0000:0000:0000:0000:0000:0000]:8080",
            "http://[0000:0000:0000:0000:0000:0000:0000:0000]:8080/",
            "[0000:0000:0000:0000:0000:0000:0000:0000]:8080",
        ];
        for socket_address in valid_socket_addresses {
            let mut expected = if socket_address.starts_with("http") {
                socket_address.to_string().trim_end_matches('/').to_string()
            } else {
                format!("http://{}", socket_address).trim_end_matches('/').to_string()
            };
            expected.push('/');

            let control_socket = ControlSocket::try_from(socket_address).expect("Error parsing good socket path");
            assert!(!control_socket.is_local_socket(), "Not parsed as a local socket");
            if let Err(e) = control_socket.validate() {
                panic!("Socket should be valid: {}", e);
            }
        }
    }

    #[test]
    fn can_normalize_wildcard_http_socket_address() {
        let socket_address = "*:8080";
        let expected = "http://127.0.0.1:8080/";
        let normalized_result = ControlSocket::normalize_and_parse_http_address(socket_address.to_string());
        let normalized = normalized_result
            .expect("Unable to normalize socket address")
            .to_string();
        assert_eq!(normalized, expected);
    }

    #[test]
    fn can_normalize_http_socket_address_with_no_port() {
        let socket_address = "http://localhost";
        let expected = "http://localhost:80/";
        let normalized_result = ControlSocket::normalize_and_parse_http_address(socket_address.to_string());
        let normalized = normalized_result
            .expect("Unable to normalize socket address")
            .to_string();
        assert_eq!(normalized, expected);
    }

    #[test]
    fn can_normalize_https_socket_address_with_no_port() {
        let socket_address = "https://localhost";
        let expected = "https://localhost:443/";
        let normalized_result = ControlSocket::normalize_and_parse_http_address(socket_address.to_string());
        let normalized = normalized_result
            .expect("Unable to normalize socket address")
            .to_string();
        assert_eq!(normalized, expected);
    }

    #[test]
    fn can_parse_http_addresses() {
        let valid_socket_addresses = vec![
            "http://127.0.0.1:8080",
            "https://127.0.0.1:8080",
            "http://127.0.0.1:8080/",
            "127.0.0.1:8080",
            "http://0.0.0.0:8080",
            "https://0.0.0.0:8080",
            "http://0.0.0.0:8080/",
            "0.0.0.0:8080",
            "http://localhost:8080",
            "https://localhost:8080",
            "http://localhost:8080/",
            "localhost:8080",
            "http://[::1]:8080",
            "https://[::1]:8080",
            "http://[::1]:8080/",
            "[::1]:8080",
            "http://[0000:0000:0000:0000:0000:0000:0000:0000]:8080",
            "https://[0000:0000:0000:0000:0000:0000:0000:0000]:8080",
            "http://[0000:0000:0000:0000:0000:0000:0000:0000]:8080/",
            "[0000:0000:0000:0000:0000:0000:0000:0000]:8080",
        ];
        for socket_address in valid_socket_addresses {
            let mut expected = if socket_address.starts_with("http") {
                socket_address.to_string().trim_end_matches('/').to_string()
            } else {
                format!("http://{}", socket_address).trim_end_matches('/').to_string()
            };
            expected.push('/');

            let normalized = ControlSocket::normalize_and_parse_http_address(socket_address.to_string())
                .expect("Unable to normalize socket address")
                .to_string();
            assert_eq!(normalized, expected);
        }
    }

    fn create_file_socket() -> Result<TempSocket, io::Error> {
        let random = Alphanumeric.sample_string(&mut rand::thread_rng(), 10);
        let socket_name = format!("unit-client-socket-test-{}.sock", random);
        let socket_path = temp_dir().join(socket_name);
        let listener = UnixListener::bind(&socket_path)?;
        Ok(TempSocket {
            socket_path,
            _listener: listener,
        })
    }

    #[cfg(target_os = "linux")]
    fn create_abstract_socket() -> Result<TempSocket, io::Error> {
        let random = Alphanumeric.sample_string(&mut rand::thread_rng(), 10);
        let socket_name = format!("@unit-client-socket-test-{}.sock", random);
        let socket_path = PathBuf::from(socket_name);
        let listener = UnixListener::bind(&socket_path)?;
        Ok(TempSocket {
            socket_path,
            _listener: listener,
        })
    }
}
