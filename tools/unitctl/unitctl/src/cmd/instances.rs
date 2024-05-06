use crate::unitctl::{InstanceArgs, InstanceCommands};
use crate::{OutputFormat, UnitctlError};
use crate::unitctl_error::ControlSocketErrorKind;

use std::path::PathBuf;
use unit_client_rs::unitd_docker::deploy_new_container;
use unit_client_rs::unitd_instance::UnitdInstance;
use unit_client_rs::control_socket_address::ControlSocket;

pub(crate) async fn cmd(args: InstanceArgs) -> Result<(), UnitctlError> {
    if let Some(cmd) = args.command {
        match cmd {
            InstanceCommands::New {
                ref socket,
                ref application,
                ref image,
            } => {
                // validation for application dir
                if !PathBuf::from(application).is_dir() {
                    eprintln!("application path must be a directory");
                    Err(UnitctlError::NoFilesImported)
                } else if !PathBuf::from(application).as_path().exists() {
                    eprintln!("application path must exist");
                    Err(UnitctlError::NoFilesImported)

                } else {
                    let addr = ControlSocket::parse_address(socket);
                    if let Err(e) = addr {
                        return Err(UnitctlError::UnitClientError{source: e});
                    }

                    // validate we arent processing an abstract socket
                    if let ControlSocket::UnixLocalAbstractSocket(_) = addr.as_ref().unwrap() {
                        return Err(UnitctlError::ControlSocketError{
                            kind: ControlSocketErrorKind::General,
                            message: "cannot pass abstract socket to docker container".to_string(),
                        })
                    }

                    // warn user of OSX docker limitations
                    if let ControlSocket::UnixLocalSocket(ref sock_path) = addr.as_ref().unwrap() {
                        if cfg!(target_os = "macos") {
                            return Err(UnitctlError::ControlSocketError{
                                kind: ControlSocketErrorKind::General,
                                message: format!("Docker on OSX will break unix sockets mounted {} {}",
                                                 "in containers, see the following link for more information",
                                                 "https://github.com/docker/for-mac/issues/483"),
                            })
                        }

                        if !sock_path.is_dir() {
                          return Err(UnitctlError::ControlSocketError{
                                kind: ControlSocketErrorKind::General,
                                message: format!("user must specify a directory of UNIX socket directory"),
                            })
                        }
                    }

                    // validate a TCP URI
                    if let ControlSocket::TcpSocket(uri) = addr.as_ref().unwrap() {
                        if let Some(host) = uri.host() {
                            if host != "127.0.0.1" {
                                return Err(UnitctlError::ControlSocketError{
                                    kind: ControlSocketErrorKind::General,
                                    message: "TCP URI must point to 127.0.0.1".to_string(),
                                })
                            }
                        } else {
                            return Err(UnitctlError::ControlSocketError{
                                kind: ControlSocketErrorKind::General,
                                message: "TCP URI must point to a host".to_string(),
                            })
                        }

                        if let Some(port) = uri.port_u16() {
                            if port < 1025 {
                                eprintln!("warning! you are asking docker to forward a privileged port. {}",
                                          "please make sure docker has access to it");
                            }
                        } else {
                            return Err(UnitctlError::ControlSocketError{
                                kind: ControlSocketErrorKind::General,
                                message: "TCP URI must specify a port".to_string(),
                            })
                        }

                        if uri.path() != "/" {
                            eprintln!("warning! path {} will be ignored", uri.path())
                        }
                    }

                    // reflect changes to user
                    // print this to STDERR to avoid polluting deserialized data output
                    eprintln!("> Pulling and starting a container from {}", image);
                    eprintln!("> Will READ ONLY mount {} to /www for application access", application);
                    eprintln!("> Container will be on host network");
                    match addr.as_ref().unwrap() {
                        ControlSocket::UnixLocalSocket(path) =>
                            eprintln!("> Will mount directory containing {} to /var/www for control API",
                                      path.as_path().to_string_lossy()),
                        ControlSocket::TcpSocket(uri) =>
                            eprintln!("> Will forward port {} for control API", uri.port_u16().unwrap()),
                        _ => unimplemented!(), // abstract socket case ruled out previously
                    }

                    if cfg!(target_os = "macos") {
                        eprintln!("> mac users: enable host networking in docker desktop");
                    }

                    // do the actual deployment
                    deploy_new_container(addr.unwrap(), application, image).await.map_or_else(
                        |e| Err(UnitctlError::UnitClientError { source: e }),
                        |warn| {
                            for i in warn {
                                eprintln!("warning! from docker: {}", i);
                            }
                            Ok(())
                        },
                    )
                }
            }
        }
    } else {
        let instances = UnitdInstance::running_unitd_instances().await;
        if instances.is_empty() {
            Err(UnitctlError::NoUnitInstancesError)
        } else if args.output_format.eq(&OutputFormat::Text) {
            instances.iter().for_each(|instance| {
                println!("{}", instance);
            });
            Ok(())
        } else {
            args.output_format.write_to_stdout(&instances)
        }
    }
}
