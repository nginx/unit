use crate::unitd_cmd::UnitdCmd;
use crate::unitd_instance::UNITD_BINARY_NAMES;
use crate::unitd_process_user::UnitdProcessUser;
use std::collections::HashMap;
use std::path::Path;
use sysinfo::{Pid, Process, ProcessRefreshKind, System, UpdateKind, Users};

#[derive(Debug, Clone)]
pub struct UnitdProcess {
    pub binary_name: String,
    pub process_id: u64,
    pub executable_path: Option<Box<Path>>,
    pub environ: Vec<String>,
    pub all_cmds: Vec<String>,
    pub working_dir: Option<Box<Path>>,
    pub child_pids: Vec<u64>,
    pub user: Option<UnitdProcessUser>,
    pub effective_user: Option<UnitdProcessUser>,
}

impl UnitdProcess {
    pub fn find_unitd_processes() -> Vec<UnitdProcess> {
        let process_refresh_kind = ProcessRefreshKind::new()
            .with_cmd(UpdateKind::Always)
            .with_cwd(UpdateKind::Always)
            .with_exe(UpdateKind::Always)
            .with_user(UpdateKind::Always);
        let refresh_kind = sysinfo::RefreshKind::new().with_processes(process_refresh_kind);
        let sys = System::new_with_specifics(refresh_kind);
        let unitd_processes: HashMap<&Pid, &Process> = sys
            .processes()
            .iter()
            .filter(|p| {
                let process_name = p.1.name();
                UNITD_BINARY_NAMES.contains(&process_name)
            })
            .collect::<HashMap<&Pid, &Process>>();
        let users = Users::new_with_refreshed_list();

        unitd_processes
            .iter()
            // Filter out child processes
            .filter(|p| {
                let parent_pid = p.1.parent();
                match parent_pid {
                    Some(pid) => !unitd_processes.contains_key(&pid),
                    None => false,
                }
            })
            .map(|p| {
                let tuple = p.to_owned();
                /* The sysinfo library only supports 32-bit pids, yet larger values are possible
                 * if the OS is configured to support it, thus we use 64-bit integers internally
                 * because it is just a matter of time until the library changes to larger values. */
                let pid = *tuple.0;
                let process = *tuple.1;
                let process_id: u64 = pid.as_u32().into();
                let executable_path: Option<Box<Path>> = process.exe().map(|p| p.to_path_buf().into_boxed_path());
                let environ: Vec<String> = process.environ().into();
                let cmd: Vec<String> = process.cmd().into();
                let working_dir: Option<Box<Path>> = process.cwd().map(|p| p.to_path_buf().into_boxed_path());
                let child_pids = unitd_processes
                    .iter()
                    .filter_map(|p| p.to_owned().1.parent())
                    .filter(|parent_pid| parent_pid == pid)
                    .map(|p| p.as_u32() as u64)
                    .collect::<Vec<u64>>();

                let user = process
                    .user_id()
                    .and_then(|uid| users.get_user_by_id(uid))
                    .map(UnitdProcessUser::from);
                let effective_user = process
                    .effective_user_id()
                    .and_then(|uid| users.get_user_by_id(uid))
                    .map(UnitdProcessUser::from);

                UnitdProcess {
                    binary_name: process.name().to_string(),
                    process_id,
                    executable_path,
                    environ,
                    all_cmds: cmd,
                    working_dir,
                    child_pids,
                    user,
                    effective_user,
                }
            })
            .collect::<Vec<UnitdProcess>>()
    }

    pub fn cmd(&self) -> Option<UnitdCmd> {
        if self.all_cmds.is_empty() {
            return None;
        }

        match UnitdCmd::new(self.all_cmds[0].clone(), self.binary_name.as_ref()) {
            Ok(cmd) => Some(cmd),
            Err(error) => {
                eprintln!("Failed to parse process cmd: {}", error);
                None
            }
        }
    }

    pub fn executable_path(&self) -> Option<Box<Path>> {
        if self.executable_path.is_some() {
            return self.executable_path.clone();
        }
        self.cmd().and_then(|cmd| cmd.process_executable_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn can_parse_runtime_cmd_absolute_path(binary_name: &str) {
        let cmd = format!(
            "unit: main v1.28.0 [/usr/sbin/{} --log /var/log/unit.log --pid /var/run/unit.pid]",
            binary_name
        );
        let unitd_cmd = UnitdCmd::new(cmd, binary_name).expect("Failed to parse unitd cmd");
        assert_eq!(unitd_cmd.version.unwrap(), "1.28.0");
        assert_eq!(
            unitd_cmd.process_executable_path.unwrap().to_string_lossy(),
            format!("/usr/sbin/{}", binary_name)
        );
        let flags = unitd_cmd.flags.unwrap();
        assert_eq!(flags.get_flag_value("log").unwrap(), "/var/log/unit.log");
        assert_eq!(flags.get_flag_value("pid").unwrap(), "/var/run/unit.pid");
    }

    fn can_parse_runtime_cmd_relative_path(binary_name: &str) {
        let cmd = format!(
            "unit: main v1.29.0 [./sbin/{} --no-daemon --tmp /tmp --something]",
            binary_name
        );
        let unitd_cmd = UnitdCmd::new(cmd, binary_name).expect("Failed to parse unitd cmd");
        assert_eq!(unitd_cmd.version.unwrap(), "1.29.0");
        assert_eq!(
            unitd_cmd.process_executable_path.unwrap().to_string_lossy(),
            format!("./sbin/{}", binary_name)
        );
        let flags = unitd_cmd.flags.unwrap();
        assert_eq!(flags.get_flag_value("tmp").unwrap(), "/tmp");
        assert!(flags.has_flag("something"));
    }

    #[test]
    fn can_parse_runtime_cmd_unitd_absolute_path() {
        can_parse_runtime_cmd_absolute_path("unitd");
    }

    #[test]
    fn can_parse_runtime_cmd_unitd_debug_absolute_path() {
        can_parse_runtime_cmd_absolute_path("unitd-debug");
    }

    #[test]
    fn can_parse_runtime_cmd_unitd_relative_path() {
        can_parse_runtime_cmd_relative_path("unitd");
    }

    #[test]
    fn can_parse_runtime_cmd_unitd_debug_relative_path() {
        can_parse_runtime_cmd_relative_path("unitd-debug");
    }
}
