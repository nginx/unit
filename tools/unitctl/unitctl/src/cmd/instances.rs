use crate::{OutputFormat, UnitctlError};
use unit_client_rs::unitd_instance::UnitdInstance;

pub(crate) fn cmd(output_format: OutputFormat) -> Result<(), UnitctlError> {
    let instances = UnitdInstance::running_unitd_instances();
    if instances.is_empty() {
        Err(UnitctlError::NoUnitInstancesError)
    } else if output_format.eq(&OutputFormat::Text) {
        instances.iter().for_each(|instance| {
            println!("{}", instance);
        });
        Ok(())
    } else {
        output_format.write_to_stdout(&instances)
    }
}
