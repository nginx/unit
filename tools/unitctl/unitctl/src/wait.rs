use crate::unitctl::UnitCtl;
use crate::unitctl_error::{ControlSocketErrorKind, UnitctlError};
use std::time::Duration;
use unit_client_rs::control_socket_address::ControlSocket;
use unit_client_rs::unit_client::{UnitClient, UnitClientError};
use unit_client_rs::unitd_instance::UnitdInstance;

/// Waits for a socket to become available. Availability is tested by attempting to access the
/// status endpoint via the control socket. When socket is available, ControlSocket instance
/// is returned.
pub async fn wait_for_sockets(cli: &UnitCtl) -> Result<Vec<ControlSocket>, UnitctlError> {
    let socks: Vec<ControlSocket>;
    match &cli.control_socket_addresses {
        None => {
            socks = vec![find_socket_address_from_instance().await?];
        },
        Some(s) => socks = s.clone(),
    }

    let mut mapped = vec![];
    for addr in socks {
        if cli.wait_time_seconds.is_none() {
            mapped.push(addr.to_owned().validate()?);
            continue;
        }

        let wait_time =
            Duration::from_secs(cli.wait_time_seconds.expect("wait_time_option default was not applied") as u64);
        let max_tries = cli.wait_max_tries.expect("max_tries_option default was not applied");

        let mut attempt = 0;
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

            let res = addr.to_owned().validate();
            if res.is_err() {
                let err = res.map_err(|error| match error {
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
                });
                if err.as_ref().is_err_and(|e| e.retryable()) {
                    continue;
                } else {
                    return Err(err.expect_err("impossible error condition"));
                }
            } else {
                let sock = res.unwrap();
                if let Err(e) = UnitClient::new(sock.clone()).status().await {
                    eprintln!("Unable to access status endpoint: {}", *e);
                    continue;
                }
                mapped.push(sock);
                break;
            }
        }

        if attempt >= max_tries {
            return Err(UnitctlError::WaitTimeoutError);
        }
    }

    return Ok(mapped);
}

async fn find_socket_address_from_instance() -> Result<ControlSocket, UnitctlError> {
    let instances = UnitdInstance::running_unitd_instances().await;
    if instances.is_empty() {
        return Err(UnitctlError::NoUnitInstancesError);
    } else if instances.len() > 1 {
        let suggestion: String = "Multiple unit instances found. Specify the socket address(es) to the instance you wish \
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
        control_socket_addresses: Some(vec![control_socket.unwrap()]),
        wait_time_seconds: Some(1u8),
        wait_max_tries: Some(3u8),
        command: crate::unitctl::Commands::Status {
            output_format: crate::output_format::OutputFormat::JsonPretty,
        },
    };
    let error = wait_for_sockets(&cli)
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
        control_socket_addresses: Some(vec![control_socket.unwrap()]),
        wait_time_seconds: Some(1u8),
        wait_max_tries: Some(3u8),
        command: crate::unitctl::Commands::Status {
            output_format: crate::output_format::OutputFormat::JsonPretty,
        },
    };

    let error = wait_for_sockets(&cli)
        .await
        .expect_err("Expected error, but no error received");
    match error {
        UnitctlError::WaitTimeoutError => {}
        _ => panic!("Expected WaitTimeoutError"),
    }
}
