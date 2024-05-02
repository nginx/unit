extern crate clap;
extern crate colored_json;
extern crate custom_error;
extern crate nu_json;
extern crate rustls_pemfile;
extern crate serde;
extern crate unit_client_rs;

use clap::Parser;

use crate::cmd::{edit, execute as execute_cmd, import, instances, listeners, status};
use crate::output_format::OutputFormat;
use crate::unitctl::{Commands, UnitCtl};
use crate::unitctl_error::UnitctlError;
use unit_client_rs::unit_client::{UnitClient, UnitClientError, UnitSerializableMap};

mod cmd;
mod inputfile;
pub mod known_size;
mod output_format;
mod requests;
mod unitctl;
mod unitctl_error;
mod wait;

#[tokio::main]
async fn main() -> Result<(), UnitctlError> {
    let cli = UnitCtl::parse();

    match cli.command {
        Commands::Instances(args) => instances::cmd(args).await,

        Commands::Edit { output_format } => edit::cmd(&cli, output_format).await,

        Commands::Import { ref directory } => import::cmd(&cli, directory).await,

        Commands::Execute {
            ref output_format,
            ref input_file,
            ref method,
            ref path,
        } => execute_cmd::cmd(&cli, output_format, input_file, method, path).await,

        Commands::Status { output_format } => status::cmd(&cli, output_format).await,

        Commands::Listeners { output_format } => listeners::cmd(&cli, output_format).await,
    }
    .map_err(|error| {
        eprint_error(&error);
        std::process::exit(error.exit_code());
    })
}

fn eprint_error(error: &UnitctlError) {
    match error {
        UnitctlError::NoUnitInstancesError => {
            eprintln!("No running unit instances found");
        }
        UnitctlError::MultipleUnitInstancesError { ref suggestion } => {
            eprintln!("{}", suggestion);
        }
        UnitctlError::NoSocketPathError => {
            eprintln!("Unable to detect socket path from running instance");
        }
        UnitctlError::UnitClientError { source } => match source {
            UnitClientError::SocketPermissionsError { .. } => {
                eprintln!("{}", source);
                eprintln!("Try running again with the same permissions as the unit control socket");
            }
            _ => {
                eprintln!("Unit client error: {}", source);
            }
        },
        UnitctlError::SerializationError { message } => {
            eprintln!("Serialization error: {}", message);
        }
        UnitctlError::DeserializationError { message } => {
            eprintln!("Deserialization error: {}", message);
        }
        UnitctlError::IoError { ref source } => {
            eprintln!("IO error: {}", source);
        }
        UnitctlError::PathNotFound { path } => {
            eprintln!("Path not found: {}", path);
        }
        UnitctlError::EditorError { message } => {
            eprintln!("Error opening editor: {}", message);
        }
        UnitctlError::CertificateError { message } => {
            eprintln!("Certificate error: {}", message);
        }
        UnitctlError::NoInputFileError => {
            eprintln!("No input file specified when required");
        }
        UnitctlError::UiServerError { ref message } => {
            eprintln!("UI server error: {}", message);
        }
        _ => {
            eprintln!("{}", error);
        }
    }
}
