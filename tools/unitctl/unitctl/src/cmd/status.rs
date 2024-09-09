use crate::unitctl::UnitCtl;
use crate::wait;
use crate::{eprint_error, OutputFormat, UnitctlError};
use unit_client_rs::unit_client::UnitClient;

pub async fn cmd(cli: &UnitCtl, output_format: OutputFormat) -> Result<(), UnitctlError> {
    let socks = wait::wait_for_sockets(cli).await?;
    let clients = socks.iter().map(|sock| UnitClient::new(sock.clone()));

    for client in clients {
        let _ = client
            .status()
            .await
            .map_err(|e| {
                let err = UnitctlError::UnitClientError { source: *e };
                eprint_error(&err);
                std::process::exit(err.exit_code());
            })
            .and_then(|response| output_format.write_to_stdout(&response));
    }
    Ok(())
}
