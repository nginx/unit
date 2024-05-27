use custom_error::custom_error;
use std::borrow::Cow;
use std::error::Error as stdError;
use std::io::{BufRead, BufReader, Lines};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

custom_error! {UnitdStderrParseError
    VersionNotFound = "Version string output not found",
    BuildSettingsNotFound = "Build settings not found"
}

#[derive(Debug, Clone)]
pub struct UnitdConfigureOptions {
    pub version: Cow<'static, str>,
    pub all_flags: Cow<'static, str>,
}

impl UnitdConfigureOptions {
    pub fn new(unitd_path: &Path) -> Result<UnitdConfigureOptions, Box<dyn stdError>> {
        fn parse_configure_settings_from_unitd_stderr_output<B: BufRead>(
            lines: &mut Lines<B>,
        ) -> Result<UnitdConfigureOptions, Box<dyn stdError>> {
            const VERSION_PREFIX: &str = "unit version: ";
            const CONFIGURED_AS_PREFIX: &str = "configured as ";
            const CONFIGURE_PREFIX: &str = "configured as ./configure ";

            fn aggregate_parsable_lines(
                mut accum: (Option<String>, Option<String>),
                line: String,
            ) -> (Option<String>, Option<String>) {
                if line.starts_with(VERSION_PREFIX) {
                    accum.0 = line.strip_prefix(VERSION_PREFIX).map(|l| l.to_string());
                } else if line.starts_with(CONFIGURED_AS_PREFIX) {
                    accum.1 = line.strip_prefix(CONFIGURE_PREFIX).map(|l| l.to_string());
                }

                accum
            }

            let options_lines = lines
                .filter_map(|line| line.ok())
                .fold((None, None), aggregate_parsable_lines);

            if options_lines.0.is_none() {
                return Err(Box::new(UnitdStderrParseError::VersionNotFound) as Box<dyn stdError>);
            } else if options_lines.1.is_none() {
                return Err(Box::new(UnitdStderrParseError::BuildSettingsNotFound) as Box<dyn stdError>);
            }

            Ok(UnitdConfigureOptions {
                version: options_lines.0.unwrap().into(),
                all_flags: options_lines.1.unwrap().into(),
            })
        }

        let program = unitd_path.as_os_str();
        let child = Command::new(program)
            .arg("--version")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let output = child.wait_with_output()?;
        let err = BufReader::new(&*output.stderr);
        parse_configure_settings_from_unitd_stderr_output(&mut err.lines())
    }

    pub fn has_flag(&self, flag_name: &str) -> bool {
        self.all_flags
            .split_ascii_whitespace()
            .any(|flag| flag.starts_with(format!("--{}", flag_name).as_str()))
    }

    pub fn get_flag_value(&self, flag_name: &str) -> Option<String> {
        self.all_flags
            .split_ascii_whitespace()
            .find(|flag| flag.starts_with(format!("--{}", flag_name).as_str()))
            .and_then(|flag| {
                let parts: Vec<&str> = flag.split('=').collect();
                if parts.len() >= 2 {
                    Some(parts[1].to_owned())
                } else {
                    None
                }
            })
    }

    pub fn debug_enabled(&self) -> bool {
        self.has_flag("debug")
    }

    pub fn openssl_enabled(&self) -> bool {
        self.has_flag("openssl")
    }

    pub fn prefix_path(&self) -> Option<Box<Path>> {
        self.get_flag_value("prefix")
            .map(PathBuf::from)
            .map(PathBuf::into_boxed_path)
    }

    fn join_to_prefix_path<S>(&self, sub_path: S) -> Option<Box<Path>>
    where
        S: Into<String>,
    {
        self.prefix_path()
            .map(|path| path.join(sub_path.into()).into_boxed_path())
    }

    pub fn default_control_api_socket_address(&self) -> Option<String> {
        // If the socket address is specific configured in the configure options, we use
        // that. Otherwise, we use the default path as assumed to be unix:$prefix/control.unit.sock.
        match self.get_flag_value("control") {
            Some(socket_address) => Some(socket_address),
            None => {
                // Give up if the unitd is compiled with unix sockets disabled
                if self.has_flag("no-unix-sockets") {
                    return None;
                }
                let socket_path = self.join_to_prefix_path("control.unit.sock");
                socket_path.map(|path| format!("unix:{}", path.to_string_lossy()))
            }
        }
    }

    pub fn default_pid_path(&self) -> Option<Box<Path>> {
        match self.get_flag_value("pid") {
            Some(pid_path) => self.join_to_prefix_path(pid_path),
            None => self.join_to_prefix_path("unit.pid"),
        }
    }

    pub fn default_log_path(&self) -> Option<Box<Path>> {
        match self.get_flag_value("log") {
            Some(pid_path) => self.join_to_prefix_path(pid_path),
            None => self.join_to_prefix_path("unit.log"),
        }
    }

    pub fn default_modules_directory(&self) -> Option<Box<Path>> {
        match self.get_flag_value("modules") {
            Some(modules_dir_name) => self.join_to_prefix_path(modules_dir_name),
            None => self.join_to_prefix_path("modules"),
        }
    }

    pub fn default_state_directory(&self) -> Option<Box<Path>> {
        match self.get_flag_value("state") {
            Some(state_dir_name) => self.join_to_prefix_path(state_dir_name),
            None => self.join_to_prefix_path("state"),
        }
    }

    pub fn default_tmp_directory(&self) -> Option<Box<Path>> {
        match self.get_flag_value("tmp") {
            Some(tmp_dir_name) => self.join_to_prefix_path(tmp_dir_name),
            None => self.join_to_prefix_path("tmp"),
        }
    }
    pub fn default_user(&self) -> Option<String> {
        self.get_flag_value("user").map(String::from)
    }
    pub fn default_group(&self) -> Option<String> {
        self.get_flag_value("group").map(String::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unitd_instance;
    use crate::unitd_instance::UNITD_PATH_ENV_KEY;

    #[test]
    fn can_detect_key() {
        let options = UnitdConfigureOptions {
            version: Default::default(),
            all_flags: Cow::from("--debug --openssl --prefix=/opt/unit"),
        };
        assert!(options.has_flag("debug"));
        assert!(options.has_flag("openssl"));
        assert!(options.has_flag("prefix"));
        assert!(!options.has_flag("fobar"));
    }

    #[test]
    fn can_get_flag_value_by_key() {
        let expected = "/opt/unit";
        let options = UnitdConfigureOptions {
            version: Default::default(),
            all_flags: Cow::from("--debug --openssl --prefix=/opt/unit"),
        };

        let actual = options.get_flag_value("prefix");
        assert_eq!(expected, actual.unwrap())
    }

    #[test]
    fn can_get_prefix_path() {
        let expected: Box<Path> = Path::new("/opt/unit").into();
        let options = UnitdConfigureOptions {
            version: Default::default(),
            all_flags: Cow::from("--debug --openssl --prefix=/opt/unit"),
        };

        let actual = options.prefix_path();
        assert_eq!(expected, actual.unwrap())
    }

    #[test]
    fn can_parse_complicated_configure_options() {
        let expected: Box<Path> = Path::new("/usr").into();
        let options = UnitdConfigureOptions {
            version: Default::default(),
            all_flags: Cow::from("--prefix=/usr --state=/var/lib/unit --control=unix:/var/run/control.unit.sock --pid=/var/run/unit.pid --log=/var/log/unit.log --tmp=/var/tmp --user=unit --group=unit --tests --openssl --modules=/usr/lib/unit/modules --libdir=/usr/lib/x86_64-linux-gnu --cc-opt='-g -O2 -fdebug-prefix-map=/data/builder/debuild/unit-1.28.0/pkg/deb/debuild/unit-1.28.0=. -specs=/usr/share/dpkg/no-pie-compile.specs -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' --ld-opt='-Wl,-Bsymbolic-functions -specs=/usr/share/dpkg/no-pie-link.specs -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie'
"),
        };

        let actual = options.prefix_path();
        assert_eq!(expected, actual.unwrap())
    }

    #[test]
    #[ignore] // run this one manually - not in CI
    fn can_run_unitd() {
        let specific_path = std::env::var(UNITD_PATH_ENV_KEY).map_err(|error| Box::new(error) as Box<dyn stdError>);
        let unitd_path = unitd_instance::find_executable_path(specific_path);
        let config_options = UnitdConfigureOptions::new(&unitd_path.unwrap());
        match config_options {
            Ok(options) => {
                println!("{:?}", options)
            }
            Err(error) => panic!("{}", error),
        };
    }
}
