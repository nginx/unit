use crate::unitctl::UnitCtl;
use crate::unitctl_error::{ControlSocketErrorKind, UnitctlError};
use std::time::Duration;
use unit_client_rs::control_socket_address::ControlSocket;
use unit_client_rs::unit_client::{UnitClient, UnitClientError};
use unit_client_rs::unitd_instance::UnitdInstance;

/// Waits for a socket to become available. Availability is tested by attempting to access the
/// status endpoint via the control socket. When socket is available, ControlSocket instance
/// is returned.
pub async fn wait_for_socket(cli: &UnitCtl) -> Result<ControlSocket, UnitctlError> {
    // Don't wait, if wait_time is not specified
    if cli.wait_time_seconds.is_none() {
        return cli.control_socket_address.instance_value_if_none().await.and_validate();
    }

    let wait_time =
        Duration::from_secs(cli.wait_time_seconds.expect("wait_time_option default was not applied") as u64);
    let max_tries = cli.wait_max_tries.expect("max_tries_option default was not applied");

    let mut attempt: u8 = 0;
    let mut control_socket: ControlSocket;
    while attempt < max_tries {
        if attempt > 0 {
            eprintln!(
                "Waiting for {}s control socket to be available try {}/{}...",
                wait_time.as_secs(),
                attempt + 1,
                max_tries
            );
            std::thread::sleep(wait_time);
        }

        attempt += 1;

        let result = cli.control_socket_address.instance_value_if_none().await.and_validate();

        if let Err(error) = result {
            if error.retryable() {
                continue;
            } else {
                return Err(error);
            }
        }

        control_socket = result.unwrap();
        let client = UnitClient::new(control_socket.clone());

        match client.status().await {
            Ok(_) => {
                return Ok(control_socket.to_owned());
            }
            Err(error) => {
                eprintln!("Unable to access status endpoint: {}", *error);
                continue;
            }
        }
    }

    if attempt >= max_tries {
        Err(UnitctlError::WaitTimeoutError)
    } else {
        panic!("Unexpected state - this should never happen");
    }
}

trait OptionControlSocket {
    async fn instance_value_if_none(&self) -> Result<ControlSocket, UnitctlError>;
}

impl OptionControlSocket for Option<ControlSocket> {
    async fn instance_value_if_none(&self) -> Result<ControlSocket, UnitctlError> {
        if let Some(control_socket) = self {
            Ok(control_socket.to_owned())
        } else {
            find_socket_address_from_instance().await
        }
    }
}

trait ResultControlSocket<T, E> {
    fn and_validate(self) -> Result<ControlSocket, UnitctlError>;
}

impl ResultControlSocket<ControlSocket, UnitctlError> for Result<ControlSocket, UnitctlError> {
    fn and_validate(self) -> Result<ControlSocket, UnitctlError> {
        self.and_then(|control_socket| {
            control_socket.validate().map_err(|error| match error {
                UnitClientError::UnixSocketNotFound { .. } => UnitctlError::ControlSocketError {
                    kind: ControlSocketErrorKind::NotFound,
                    message: format!("{}", error),
                },
                UnitClientError::SocketPermissionsError { .. } => UnitctlError::ControlSocketError {
                    kind: ControlSocketErrorKind::Permissions,
                    message: format!("{}", error),
                },
                UnitClientError::TcpSocketAddressUriError { .. }
                | UnitClientError::TcpSocketAddressNoPortError { .. }
                | UnitClientError::TcpSocketAddressParseError { .. } => UnitctlError::ControlSocketError {
                    kind: ControlSocketErrorKind::Parse,
                    message: format!("{}", error),
                },
                _ => UnitctlError::ControlSocketError {
                    kind: ControlSocketErrorKind::General,
                    message: format!("{}", error),
                },
            })
        })
    }
}

async fn find_socket_address_from_instance() -> Result<ControlSocket, UnitctlError> {
    let instances = UnitdInstance::running_unitd_instances().await;
    if instances.is_empty() {
        return Err(UnitctlError::NoUnitInstancesError);
    } else if instances.len() > 1 {
        let suggestion: String = "Multiple unit instances found. Specify the socket address to the instance you wish \
            to control using the `--control-socket-address` flag"
            .to_string();
        return Err(UnitctlError::MultipleUnitInstancesError { suggestion });
    }

    let instance = instances.first().unwrap();
    match instance.control_api_socket_address() {
        Some(path) => Ok(ControlSocket::try_from(path).unwrap()),
        None => Err(UnitctlError::NoSocketPathError),
    }
}

#[tokio::test]
async fn wait_for_unavailable_unix_socket() {
    let control_socket = ControlSocket::try_from("unix:/tmp/this_socket_does_not_exist.sock");
    let cli = UnitCtl {
        control_socket_address: Some(control_socket.unwrap()),
        wait_time_seconds: Some(1u8),
        wait_max_tries: Some(3u8),
        command: crate::unitctl::Commands::Status {
            output_format: crate::output_format::OutputFormat::JsonPretty,
        },
    };
    let error = wait_for_socket(&cli)
        .await
        .expect_err("Expected error, but no error received");
    match error {
        UnitctlError::WaitTimeoutError => {}
        _ => panic!("Expected WaitTimeoutError: {}", error),
    }
}

#[tokio::test]
async fn wait_for_unavailable_tcp_socket() {
    let control_socket = ControlSocket::try_from("http://127.0.0.1:9783456");
    let cli = UnitCtl {
        control_socket_address: Some(control_socket.unwrap()),
        wait_time_seconds: Some(1u8),
        wait_max_tries: Some(3u8),
        command: crate::unitctl::Commands::Status {
            output_format: crate::output_format::OutputFormat::JsonPretty,
        },
    };

    let error = wait_for_socket(&cli)
        .await
        .expect_err("Expected error, but no error received");
    match error {
        UnitctlError::WaitTimeoutError => {}
        _ => panic!("Expected WaitTimeoutError"),
    }
}
