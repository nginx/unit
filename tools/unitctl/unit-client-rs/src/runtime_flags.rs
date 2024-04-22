use std::borrow::Cow;
use std::fmt;
use std::fmt::Display;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct RuntimeFlags {
    pub flags: Cow<'static, str>,
}

impl Display for RuntimeFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.flags)
    }
}

impl RuntimeFlags {
    pub fn new<S>(flags: S) -> RuntimeFlags
    where
        S: Into<String>,
    {
        RuntimeFlags {
            flags: Cow::from(flags.into()),
        }
    }

    pub fn has_flag(&self, flag_name: &str) -> bool {
        self.flags.contains(format!("--{}", flag_name).as_str())
    }

    pub fn get_flag_value(&self, flag_name: &str) -> Option<String> {
        let flag_parts = self.flags.split_ascii_whitespace().collect::<Vec<&str>>();
        for (i, flag) in flag_parts.iter().enumerate() {
            if let Some(name) = flag.strip_prefix("--") {
                /* If there is no flag value after the current one, there is by definition no
                 * flag value for the current flag. */
                let index_lt_len = flag_parts.len() > i + 1;
                if index_lt_len {
                    let next_value_isnt_flag = !flag_parts[i + 1].starts_with("--");
                    if name.eq(flag_name) && next_value_isnt_flag {
                        return Some(flag_parts[i + 1].to_string());
                    }
                }
            }
        }
        None
    }

    pub fn control_api_socket_address(&self) -> Option<String> {
        self.get_flag_value("control")
    }

    pub fn pid_path(&self) -> Option<Box<Path>> {
        self.get_flag_value("pid")
            .map(PathBuf::from)
            .map(PathBuf::into_boxed_path)
    }

    pub fn log_path(&self) -> Option<Box<Path>> {
        self.get_flag_value("log")
            .map(PathBuf::from)
            .map(PathBuf::into_boxed_path)
    }

    pub fn modules_directory(&self) -> Option<Box<Path>> {
        self.get_flag_value("modules")
            .map(PathBuf::from)
            .map(PathBuf::into_boxed_path)
    }

    pub fn state_directory(&self) -> Option<Box<Path>> {
        self.get_flag_value("state")
            .map(PathBuf::from)
            .map(PathBuf::into_boxed_path)
    }

    pub fn tmp_directory(&self) -> Option<Box<Path>> {
        self.get_flag_value("tmp")
            .map(PathBuf::from)
            .map(PathBuf::into_boxed_path)
    }

    pub fn user(&self) -> Option<String> {
        self.get_flag_value("user").map(String::from)
    }

    pub fn group(&self) -> Option<String> {
        self.get_flag_value("group").map(String::from)
    }
}
