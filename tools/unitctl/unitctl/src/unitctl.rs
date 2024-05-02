extern crate clap;

use crate::output_format::OutputFormat;
use clap::error::ErrorKind::ValueValidation;
use clap::{Args, Error as ClapError, Parser, Subcommand};
use std::path::PathBuf;
use unit_client_rs::control_socket_address::ControlSocket;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about)]
pub(crate) struct UnitCtl {
    #[arg(
        required = false,
        short = 's',
        long = "control-socket-address",
        value_parser = parse_control_socket_address,
        help = "Path (unix:/var/run/unit/control.sock), tcp address with port (127.0.0.1:80), or URL"
    )]
    pub(crate) control_socket_address: Option<ControlSocket>,
    #[arg(
        required = false,
        default_missing_value = "1",
        value_parser = parse_u8,
        short = 'w',
        long = "wait-timeout-seconds",
        help = "Number of seconds to wait for control socket to become available"
    )]
    pub(crate) wait_time_seconds: Option<u8>,
    #[arg(
        required = false,
        default_value = "3",
        value_parser = parse_u8,
        short = 't',
        long = "wait-max-tries",
        help = "Number of times to try to access control socket when waiting"
    )]
    pub(crate) wait_max_tries: Option<u8>,
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    #[command(about = "List all running UNIT processes")]
    Instances(InstanceArgs),
    #[command(about = "Open current UNIT configuration in editor")]
    Edit {
        #[arg(
            required = false,
            global = true,
            short = 't',
            long = "output-format",
            default_value = "json-pretty",
            help = "Output format: yaml, json, json-pretty (default)"
        )]
        output_format: OutputFormat,
    },
    #[command(about = "Import configuration from a directory")]
    Import {
        #[arg(required = true, help = "Directory to import from")]
        directory: PathBuf,
    },
    #[command(about = "Sends raw JSON payload to UNIT")]
    Execute {
        #[arg(
            required = false,
            global = true,
            short = 't',
            long = "output-format",
            default_value = "json-pretty",
            help = "Output format: yaml, json, json-pretty (default)"
        )]
        output_format: OutputFormat,
        #[arg(
            required = false,
            global = true,
            short = 'f',
            long = "file",
            help = "Input file (json, json5, cjson, hjson yaml, pem) to send to unit when applicable use - for stdin"
        )]
        input_file: Option<String>,
        #[arg(
        help = "HTTP method to use (GET, POST, PUT, DELETE)",
        required = true,
        short = 'm',
        long = "http-method",
        value_parser = parse_http_method,
        )]
        method: String,
        #[arg(required = true, short = 'p', long = "path")]
        path: String,
    },
    #[command(about = "Get the current status of UNIT")]
    Status {
        #[arg(
            required = false,
            global = true,
            short = 't',
            long = "output-format",
            default_value = "json-pretty",
            help = "Output format: yaml, json, json-pretty (default)"
        )]
        output_format: OutputFormat,
    },
    #[command(about = "List active listeners")]
    Listeners {
        #[arg(
            required = false,
            global = true,
            short = 't',
            long = "output-format",
            default_value = "json-pretty",
            help = "Output format: yaml, json, json-pretty (default)"
        )]
        output_format: OutputFormat,
    },
}

#[derive(Debug, Args)]
pub struct InstanceArgs {
    #[arg(
        required = false,
        global = true,
        short = 't',
        long = "output-format",
        default_value = "text",
        help = "Output format: text, yaml, json, json-pretty (default)"
    )]
    pub output_format: OutputFormat,

    #[command(subcommand)]
    pub command: Option<InstanceCommands>,
}

#[derive(Debug, Subcommand)]
#[command(args_conflicts_with_subcommands = true)]
pub enum InstanceCommands {
    #[command(about = "deploy a new docker instance of unitd")]
    New {
        #[arg(required = true, help = "Path to mount control socket to host")]
        socket: String,

        #[arg(required = true, help = "Path to mount application into container")]
        application: String,

        #[arg(
            help = "Unitd Image to deploy",
            default_value = env!("CARGO_PKG_VERSION"),
        )]
        image: String,
    },
}

fn parse_control_socket_address(s: &str) -> Result<ControlSocket, ClapError> {
    ControlSocket::try_from(s).map_err(|e| ClapError::raw(ValueValidation, e.to_string()))
}

fn parse_http_method(s: &str) -> Result<String, ClapError> {
    let method = s.to_uppercase();
    match method.as_str() {
        "GET" | "POST" | "PUT" | "DELETE" => Ok(method),
        _ => Err(ClapError::raw(ValueValidation, format!("Invalid HTTP method: {}", s))),
    }
}

fn parse_u8(s: &str) -> Result<u8, ClapError> {
    s.parse::<u8>()
        .map_err(|e| ClapError::raw(ValueValidation, format!("Invalid number: {}", e)))
}
