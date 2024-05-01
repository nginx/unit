use crate::{OutputFormat, UnitctlError};
use crate::unitctl::{InstanceArgs, InstanceCommands};
use unit_client_rs::unitd_instance::UnitdInstance;
use unit_client_rs::unitd_docker::deploy_new_container;
use std::path::PathBuf;

pub(crate) async fn cmd(args: InstanceArgs) -> Result<(), UnitctlError> {
    if let Some(cmd) = args.command {
        match cmd {
            InstanceCommands::New{
                ref socket,
                ref application,
                ref image
            } => {
                if !PathBuf::from(socket).is_dir() || !PathBuf::from(application).is_dir() {
                    eprintln!("application and socket paths must be directories");
                    Err(UnitctlError::NoFilesImported)
                } else {
                    deploy_new_container(socket, application, image)
                        .or_else(|e| Err(UnitctlError::UnitClientError{source: e}))
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
