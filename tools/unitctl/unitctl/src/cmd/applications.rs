use crate::unitctl::{ApplicationArgs, ApplicationCommands, UnitCtl};
use crate::{wait, UnitctlError};
use crate::requests::send_empty_body_deserialize_response;
use unit_client_rs::unit_client::UnitClient;

pub(crate) async fn cmd(cli: &UnitCtl, args: &ApplicationArgs) -> Result<(), UnitctlError> {
    let control_socket = wait::wait_for_socket(cli).await?;
    let client = UnitClient::new(control_socket);

    match &args.command {
        ApplicationCommands::Reload { ref name } => client
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

        ApplicationCommands::List {} => {
            args.output_format.write_to_stdout(
                &send_empty_body_deserialize_response(
                    &client,
                    "GET",
                    "/config/applications",
                ).await?
            )
        },
    }
}
