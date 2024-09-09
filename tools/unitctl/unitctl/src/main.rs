extern crate clap;
extern crate colored_json;
extern crate custom_error;
extern crate nu_json;
extern crate rustls_pemfile;
extern crate serde;
extern crate unit_client_rs;

use clap::Parser;

use crate::cmd::{applications, edit, execute as execute_cmd, import, instances, listeners, save, status};
use crate::output_format::OutputFormat;
use crate::unitctl::{Commands, UnitCtl};
use crate::unitctl_error::{eprint_error, UnitctlError};
use unit_client_rs::unit_client::{UnitClient, UnitSerializableMap};

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

        Commands::Apps(ref args) => applications::cmd(&cli, args).await,

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

        Commands::Export { ref filename } => save::cmd(&cli, filename).await,
    }
    .map_err(|error| {
        eprint_error(&error);
        std::process::exit(error.exit_code());
    })
}
