use crate::unit_client::UnitClientError;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use std::error::Error as StdError;
use std::path::{Path, PathBuf};
use std::{fmt, io};
use which::which;

use crate::runtime_flags::RuntimeFlags;
use crate::unitd_configure_options::UnitdConfigureOptions;
use crate::unitd_process::UnitdProcess;

pub const UNITD_PATH_ENV_KEY: &str = "UNITD_PATH";
pub const UNITD_BINARY_NAMES: [&str; 2] = ["unitd", "unitd-debug"];

#[derive(Debug)]
pub struct UnitdInstance {
    pub process: UnitdProcess,
    pub configure_options: Option<UnitdConfigureOptions>,
    pub errors: Vec<UnitClientError>,
}

impl Serialize for UnitdInstance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_map(Some(15))?;
        let runtime_flags = self
            .process
            .cmd()
            .and_then(|cmd| cmd.flags)
            .map(|flags| flags.to_string());

        let configure_flags = self.configure_options.as_ref().map(|opts| opts.all_flags.clone());

        state.serialize_entry("pid", &self.process.process_id)?;
        state.serialize_entry("version", &self.version())?;
        state.serialize_entry("user", &self.process.user)?;
        state.serialize_entry("effective_user", &self.process.effective_user)?;
        state.serialize_entry("executable", &self.process.executable_path())?;
        state.serialize_entry("control_socket", &self.control_api_socket_address())?;
        state.serialize_entry("child_pids", &self.process.child_pids)?;
        state.serialize_entry("log_path", &self.log_path())?;
        state.serialize_entry("pid_path", &self.pid_path())?;
        state.serialize_entry("modules_directory", &self.modules_directory())?;
        state.serialize_entry("state_directory", &self.state_directory())?;
        state.serialize_entry("tmp_directory", &self.tmp_directory())?;
        state.serialize_entry("runtime_flags", &runtime_flags)?;
        state.serialize_entry("configure_flags", &configure_flags)?;
        let string_errors = &self.errors.iter().map(|e| e.to_string()).collect::<Vec<String>>();
        state.serialize_entry("errors", string_errors)?;

        state.end()
    }
}

impl UnitdInstance {
    pub fn running_unitd_instances() -> Vec<UnitdInstance> {
        Self::collect_unitd_processes(UnitdProcess::find_unitd_processes())
    }

    /// Find all running unitd processes and convert them into UnitdInstances and filter
    /// out all errors by printing them to stderr and leaving errored instances out of
    /// the returned vector.
    fn collect_unitd_processes(processes: Vec<UnitdProcess>) -> Vec<UnitdInstance> {
        Self::map_processes_to_instances(processes).into_iter().collect()
    }

    fn map_processes_to_instances(processes: Vec<UnitdProcess>) -> Vec<UnitdInstance> {
        fn unitd_path_from_process(process: &UnitdProcess) -> Result<Box<Path>, UnitClientError> {
            match process.executable_path() {
                Some(executable_path) => {
                    let is_absolute_working_dir = process
                        .working_dir
                        .as_ref()
                        .map(|p| p.is_absolute())
                        .unwrap_or_default();
                    if executable_path.is_absolute() {
                        Ok(executable_path.to_owned())
                    } else if executable_path.is_relative() && is_absolute_working_dir {
                        let new_path = process
                            .working_dir
                            .as_ref()
                            .unwrap()
                            .join(executable_path)
                            .canonicalize()
                            .map(|path| path.into_boxed_path())
                            .map_err(|error| UnitClientError::UnitdProcessParseError {
                                message: format!("Error canonicalizing unitd executable path: {}", error),
                                pid: process.process_id,
                            })?;
                        Ok(new_path)
                    } else {
                        Err(UnitClientError::UnitdProcessParseError {
                            message: "Unable to get absolute unitd executable path from process".to_string(),
                            pid: process.process_id,
                        })
                    }
                }
                None => Err(UnitClientError::UnitdProcessParseError {
                    message: "Unable to get unitd executable path from process".to_string(),
                    pid: process.process_id,
                }),
            }
        }

        fn map_process_to_unitd_instance(process: &UnitdProcess) -> UnitdInstance {
            match unitd_path_from_process(process) {
                Ok(unitd_path) => match UnitdConfigureOptions::new(&unitd_path.clone().into_path_buf()) {
                    Ok(configure_options) => UnitdInstance {
                        process: process.to_owned(),
                        configure_options: Some(configure_options),
                        errors: vec![],
                    },
                    Err(error) => {
                        let error = UnitClientError::UnitdProcessExecError {
                            source: error,
                            executable_path: unitd_path.to_string_lossy().parse().unwrap_or_default(),
                            message: "Error running unitd binary to get configure options".to_string(),
                            pid: process.process_id,
                        };
                        UnitdInstance {
                            process: process.to_owned(),
                            configure_options: None,
                            errors: vec![error],
                        }
                    }
                },
                Err(err) => UnitdInstance {
                    process: process.to_owned(),
                    configure_options: None,
                    errors: vec![err],
                },
            }
        }

        processes
            .iter()
            // This converts processes into a UnitdInstance
            .map(map_process_to_unitd_instance)
            .collect()
    }

    fn version(&self) -> Option<String> {
        match self.process.cmd()?.version {
            Some(version) => Some(version),
            None => self.configure_options.as_ref().map(|opts| opts.version.to_string()),
        }
    }

    fn flag_or_default_option<R>(
        &self,
        read_flag: fn(RuntimeFlags) -> Option<R>,
        read_opts: fn(UnitdConfigureOptions) -> Option<R>,
    ) -> Option<R> {
        self.process
            .cmd()?
            .flags
            .and_then(read_flag)
            .or_else(|| self.configure_options.to_owned().and_then(read_opts))
    }

    pub fn control_api_socket_address(&self) -> Option<String> {
        self.flag_or_default_option(
            |flags| flags.control_api_socket_address(),
            |opts| opts.default_control_api_socket_address(),
        )
    }

    pub fn pid_path(&self) -> Option<Box<Path>> {
        self.flag_or_default_option(|flags| flags.pid_path(), |opts| opts.default_pid_path())
    }

    pub fn log_path(&self) -> Option<Box<Path>> {
        self.flag_or_default_option(|flags| flags.log_path(), |opts| opts.default_log_path())
    }

    pub fn modules_directory(&self) -> Option<Box<Path>> {
        self.flag_or_default_option(
            |flags| flags.modules_directory(),
            |opts| opts.default_modules_directory(),
        )
    }

    pub fn state_directory(&self) -> Option<Box<Path>> {
        self.flag_or_default_option(|flags| flags.state_directory(), |opts| opts.default_state_directory())
    }

    pub fn tmp_directory(&self) -> Option<Box<Path>> {
        self.flag_or_default_option(|flags| flags.tmp_directory(), |opts| opts.default_tmp_directory())
    }
}

impl fmt::Display for UnitdInstance {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const UNKNOWN: &str = "[unknown]";
        let version = self.version().unwrap_or_else(|| String::from("[unknown]"));
        let runtime_flags = self
            .process
            .cmd()
            .and_then(|cmd| cmd.flags)
            .map(|flags| flags.to_string())
            .unwrap_or_else(|| UNKNOWN.into());
        let configure_flags = self
            .configure_options
            .as_ref()
            .map(|opts| opts.all_flags.clone())
            .unwrap_or_else(|| UNKNOWN.into());
        let unitd_path: String = self
            .process
            .executable_path()
            .map(|p| p.to_string_lossy().into())
            .unwrap_or_else(|| UNKNOWN.into());
        let working_dir: String = self
            .process
            .working_dir
            .as_ref()
            .map(|p| p.to_string_lossy().into())
            .unwrap_or_else(|| UNKNOWN.into());
        let socket_address = self.control_api_socket_address().unwrap_or_else(|| UNKNOWN.to_string());
        let child_pids = self
            .process
            .child_pids
            .iter()
            .map(u64::to_string)
            .collect::<Vec<String>>()
            .join(", ");

        writeln!(
            f,
            "{} instance [pid: {}, version: {}]:",
            self.process.binary_name, self.process.process_id, version
        )?;
        writeln!(f, "  Executable: {}", unitd_path)?;
        writeln!(f, "  Process working directory: {}", working_dir)?;
        write!(f, "  Process ownership: ")?;
        if let Some(user) = &self.process.user {
            writeln!(f, "name: {}, uid: {}, gid: {}", user.name, user.uid, user.gid)?;
        } else {
            writeln!(f, "{}", UNKNOWN)?;
        }
        write!(f, "  Process effective ownership: ")?;
        if let Some(user) = &self.process.effective_user {
            writeln!(f, "name: {}, uid: {}, gid: {}", user.name, user.uid, user.gid)?;
        } else {
            writeln!(f, "{}", UNKNOWN)?;
        }

        writeln!(f, "  API control unix socket: {}", socket_address)?;
        writeln!(f, "  Child processes ids: {}", child_pids)?;
        writeln!(f, "  Runtime flags: {}", runtime_flags)?;
        write!(f, "  Configure options: {}", configure_flags)?;

        if !self.errors.is_empty() {
            write!(f, "\n  Errors:")?;
            for error in &self.errors {
                write!(f, "\n    {}", error)?;
            }
        }

        Ok(())
    }
}

pub fn find_executable_path(specific_path: Result<String, Box<dyn StdError>>) -> Result<PathBuf, Box<dyn StdError>> {
    fn find_unitd_in_system_path() -> Vec<PathBuf> {
        UNITD_BINARY_NAMES
            .iter()
            .map(which)
            .filter_map(Result::ok)
            .collect::<Vec<PathBuf>>()
    }

    match specific_path {
        Ok(path) => Ok(PathBuf::from(path)),
        Err(_) => {
            let unitd_paths = find_unitd_in_system_path();
            if unitd_paths.is_empty() {
                let err_msg = format!(
                    "Could not find unitd in system path or in UNITD_PATH environment variable. Searched for: {:?}",
                    UNITD_BINARY_NAMES
                );
                let err = io::Error::new(io::ErrorKind::NotFound, err_msg);
                Err(Box::from(err))
            } else {
                Ok(unitd_paths[0].clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    // We don't need a secure seed for testing, in fact it is better that we have a
    // predictable value
    const SEED: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31,
    ];
    #[test]
    fn can_find_unitd_instances() {
        UnitdInstance::running_unitd_instances().iter().for_each(|p| {
            println!("{:?}", p);
            println!("Runtime Flags: {:?}", p.process.cmd().map(|c| c.flags));
            println!("Temp directory: {:?}", p.tmp_directory());
        })
    }

    fn mock_process<S: Into<String>>(
        rng: &mut StdRng,
        binary_name: S,
        executable_path: Option<String>,
    ) -> UnitdProcess {
        UnitdProcess {
            process_id: rng.next_u32() as u64,
            binary_name: binary_name.into(),
            executable_path: executable_path.map(|p| Box::from(Path::new(&p))),
            environ: vec![],
            all_cmds: vec![],
            working_dir: Some(Box::from(Path::new("/opt/unit"))),
            child_pids: vec![],
            user: None,
            effective_user: None,
        }
    }

    #[test]
    fn will_list_without_errors_valid_processes() {
        let specific_path = std::env::var(UNITD_PATH_ENV_KEY).map_err(|error| Box::new(error) as Box<dyn StdError>);
        let binding = match find_executable_path(specific_path) {
            Ok(path) => path,
            Err(error) => {
                eprintln!("Could not find unitd executable path: {} - skipping test", error);
                return;
            }
        };
        let binary_name = binding
            .file_name()
            .expect("Could not get binary name")
            .to_string_lossy()
            .to_string();
        let unitd_path = binding.to_string_lossy();
        let mut rng: StdRng = SeedableRng::from_seed(SEED);

        let processes = vec![
            mock_process(&mut rng, &binary_name, Some(unitd_path.to_string())),
            mock_process(&mut rng, &binary_name, Some(unitd_path.to_string())),
        ];
        let instances = UnitdInstance::collect_unitd_processes(processes);
        // assert_eq!(instances.len(), 3);
        instances.iter().for_each(|p| {
            assert_eq!(p.errors.len(), 0, "Expected no errors, got: {:?}", p.errors);
        })
    }
}
