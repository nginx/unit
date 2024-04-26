use std::error::Error as StdError;
use std::io::{Error as IoError, ErrorKind};

use crate::runtime_flags::RuntimeFlags;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct UnitdCmd {
    pub(crate) process_executable_path: Option<Box<Path>>,
    pub version: Option<String>,
    pub flags: Option<RuntimeFlags>,
}

impl UnitdCmd {
    pub(crate) fn new<S>(full_cmd: S, binary_name: &str) -> Result<UnitdCmd, Box<dyn StdError>>
    where
        S: Into<String>,
    {
        let process_cmd: String = full_cmd.into();
        let parsable = process_cmd
            .strip_prefix("unit: main v")
            .and_then(|s| s.strip_suffix(']'));
        if parsable.is_none() {
            let msg = format!("cmd does not have the expected format: {}", process_cmd);
            return Err(IoError::new(ErrorKind::InvalidInput, msg).into());
        }
        let parts = parsable
            .expect("Unable to parse cmd")
            .splitn(2, " [")
            .collect::<Vec<&str>>();

        if parts.len() != 2 {
            let msg = format!("cmd does not have the expected format: {}", process_cmd);
            return Err(IoError::new(ErrorKind::InvalidInput, msg).into());
        }

        let version = Some(parts[0].to_string());
        let executable_path = UnitdCmd::parse_executable_path_from_cmd(parts[1], binary_name);
        let flags = UnitdCmd::parse_runtime_flags_from_cmd(parts[1]);

        Ok(UnitdCmd {
            process_executable_path: executable_path,
            version,
            flags,
        })
    }

    fn parse_executable_path_from_cmd<S>(full_cmd: S, binary_name: &str) -> Option<Box<Path>>
    where
        S: Into<String>,
    {
        let cmd = full_cmd.into();
        if cmd.is_empty() {
            return None;
        }

        let split = cmd.splitn(2, binary_name).collect::<Vec<&str>>();
        if split.is_empty() {
            return None;
        }

        let path = format!("{}{}", split[0], binary_name);
        Some(PathBuf::from(path).into_boxed_path())
    }

    fn parse_runtime_flags_from_cmd<S>(full_cmd: S) -> Option<RuntimeFlags>
    where
        S: Into<String>,
    {
        let cmd = full_cmd.into();
        if cmd.is_empty() {
            return None;
        }

        // Split out everything in between the brackets [ and ]
        let split = cmd.trim_end_matches(']').splitn(2, '[').collect::<Vec<&str>>();
        if split.is_empty() {
            return None;
        }
        /* Now we need to parse a string like this:
         * ./sbin/unitd --no-daemon --tmp /tmp
         * and only return what is after the invoking command */
        split[0]
            .find("--")
            .map(|index| cmd[index..].to_string())
            .map(RuntimeFlags::new)
    }
}
