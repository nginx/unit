use crate::unitctl::UnitCtl;
use crate::wait;
use crate::{OutputFormat, UnitctlError};
use unit_client_rs::unit_client::UnitClient;

pub fn cmd(cli: &UnitCtl, output_format: OutputFormat) -> Result<(), UnitctlError> {
    let control_socket = wait::wait_for_socket(cli)?;
    let client = UnitClient::new(control_socket);
    client
        .status()
        .map_err(|e| UnitctlError::UnitClientError { source: *e })
        .and_then(|response| output_format.write_to_stdout(&response))
}
