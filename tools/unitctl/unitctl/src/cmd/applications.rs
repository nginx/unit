use crate::requests::send_empty_body_deserialize_response;
use crate::unitctl::{ApplicationArgs, ApplicationCommands, UnitCtl};
use crate::{eprint_error, wait, UnitctlError};
use unit_client_rs::unit_client::UnitClient;

pub(crate) async fn cmd(cli: &UnitCtl, args: &ApplicationArgs) -> Result<(), UnitctlError> {
    let clients: Vec<UnitClient> = wait::wait_for_sockets(cli)
        .await?
        .into_iter()
        .map(|sock| UnitClient::new(sock))
        .collect();

    for client in clients {
        let _ = match &args.command {
            ApplicationCommands::Restart { ref name } => client
                .restart_application(name)
                .await
                .map_err(|e| UnitctlError::UnitClientError { source: *e })
                .and_then(|r| args.output_format.write_to_stdout(&r)),

            /* we should be able to use this but the openapi generator library
             * is fundamentally incorrect and provides a broken API for the
             * applications endpoint.
            ApplicationCommands::List {} => client
                .applications()
                .await
                .map_err(|e| UnitctlError::UnitClientError { source: *e })
                .and_then(|response| args.output_format.write_to_stdout(&response)),*/
            ApplicationCommands::List {} => args
                .output_format
                .write_to_stdout(&send_empty_body_deserialize_response(&client, "GET", "/config/applications").await?),
        }
        .map_err(|error| {
            eprint_error(&error);
            std::process::exit(error.exit_code());
        });
    }

    Ok(())
}
