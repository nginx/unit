use std::collections::HashMap;
use std::io;
use std::io::{BufRead, BufReader, Error as IoError, Read};
use std::path::{Path, PathBuf};

use crate::known_size::KnownSize;
use clap::ValueEnum;

use super::UnitSerializableMap;
use super::UnitctlError;

/// Input file data format
#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum InputFormat {
    Yaml,
    Json,
    Json5,
    Hjson,
    Pem,
    JavaScript,
    Unknown,
}

impl InputFormat {
    pub fn from_file_extension<S>(file_extension: S) -> Self
    where
        S: Into<String>,
    {
        match file_extension.into().to_lowercase().as_str() {
            "yaml" => InputFormat::Yaml,
            "yml" => InputFormat::Yaml,
            "json" => InputFormat::Json,
            "json5" => InputFormat::Json5,
            "hjson" => InputFormat::Hjson,
            "cjson" => InputFormat::Hjson,
            "pem" => InputFormat::Pem,
            "js" => InputFormat::JavaScript,
            "njs" => InputFormat::JavaScript,
            _ => InputFormat::Unknown,
        }
    }

    /// This function allows us to infer the input format based on the remote path which is
    /// useful when processing input from STDIN.
    pub fn from_remote_path<S>(remote_path: S) -> Self
    where
        S: Into<String>,
    {
        let remote_upload_path = remote_path.into();
        let lead_slash_removed = remote_upload_path.trim_start_matches('/');
        let first_path = lead_slash_removed
            .split_once('/')
            .map_or(lead_slash_removed, |(first, _)| first);
        match first_path {
            "config" => InputFormat::Hjson,
            "certificates" => InputFormat::Pem,
            "js_modules" => InputFormat::JavaScript,
            _ => InputFormat::Json,
        }
    }
}

/// A "file" that can be used as input to a command
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputFile {
    // Data received via STDIN
    Stdin(InputFormat),
    // Data that is on the file system where the format is inferred from the extension
    File(Box<Path>),
    // Data that is on the file system where the format is explicitly specified
    FileWithFormat(Box<Path>, InputFormat),
}

impl InputFile {
    /// Creates a new instance of `InputFile` from a string
    pub fn new<S>(file_path_or_dash: S, remote_path: S) -> Self
    where
        S: Into<String>,
    {
        let file_path: String = file_path_or_dash.into();

        match file_path.as_str() {
            "-" => InputFile::Stdin(InputFormat::from_remote_path(remote_path)),
            _ => InputFile::File(PathBuf::from(&file_path).into_boxed_path()),
        }
    }

    /// Returns the format of the input file
    pub fn format(&self) -> InputFormat {
        match self {
            InputFile::Stdin(format) => *format,
            InputFile::File(path) => {
                // Figure out the file format based on the file extension
                match path.extension().and_then(|s| s.to_str()) {
                    Some(ext) => InputFormat::from_file_extension(ext),
                    None => InputFormat::Unknown,
                }
            }
            InputFile::FileWithFormat(_file, format) => *format,
        }
    }

    pub fn mime_type(&self) -> String {
        match self.format() {
            InputFormat::Yaml => "application/x-yaml".to_string(),
            InputFormat::Json => "application/json".to_string(),
            InputFormat::Json5 => "application/json5".to_string(),
            InputFormat::Hjson => "application/hjson".to_string(),
            InputFormat::Pem => "application/x-pem-file".to_string(),
            InputFormat::JavaScript => "application/javascript".to_string(),
            InputFormat::Unknown => "application/octet-stream".to_string(),
        }
    }

    /// Returns true if the input file is in the format of a configuration file
    pub fn is_config(&self) -> bool {
        matches!(
            self.format(),
            InputFormat::Yaml | InputFormat::Json | InputFormat::Json5 | InputFormat::Hjson
        )
    }

    pub fn is_javascript(&self) -> bool {
        matches!(self.format(), InputFormat::JavaScript)
    }

    pub fn is_pem_bundle(&self) -> bool {
        matches!(self.format(), InputFormat::Pem)
    }

    /// Returns the path to the input file if it is a file and not a stream
    pub fn to_path(&self) -> Result<&Path, UnitctlError> {
        match self {
            InputFile::Stdin(_) => {
                let io_error = IoError::new(std::io::ErrorKind::InvalidInput, "Input file is stdin");
                Err(UnitctlError::IoError { source: io_error })
            }
            InputFile::File(path) | InputFile::FileWithFormat(path, _) => Ok(path),
        }
    }

    /// Converts a HJSON Value type to a JSON Value type
    fn hjson_value_to_json_value(value: nu_json::Value) -> serde_json::Value {
        serde_json::to_value(value).expect("Failed to convert HJSON value to JSON value")
    }

    pub fn to_unit_serializable_map(&self) -> Result<UnitSerializableMap, UnitctlError> {
        let reader: Box<dyn BufRead + Send> = self.try_into()?;
        let body_data: UnitSerializableMap = match self.format() {
            InputFormat::Yaml => serde_yaml::from_reader(reader)
                .map_err(|e| UnitctlError::DeserializationError { message: e.to_string() })?,
            InputFormat::Json => serde_json::from_reader(reader)
                .map_err(|e| UnitctlError::DeserializationError { message: e.to_string() })?,
            InputFormat::Json5 => {
                let mut reader = BufReader::new(reader);
                let mut json5_string: String = String::new();
                reader
                    .read_to_string(&mut json5_string)
                    .map_err(|e| UnitctlError::DeserializationError { message: e.to_string() })?;
                json5::from_str(&json5_string)
                    .map_err(|e| UnitctlError::DeserializationError { message: e.to_string() })?
            }
            InputFormat::Hjson => {
                let hjson_value: HashMap<String, nu_json::Value> = nu_json::from_reader(reader)
                    .map_err(|e| UnitctlError::DeserializationError { message: e.to_string() })?;

                hjson_value
                    .iter()
                    .map(|(k, v)| {
                        let json_value = Self::hjson_value_to_json_value(v.clone());
                        (k.clone(), json_value)
                    })
                    .collect()
            }
            _ => Err(UnitctlError::DeserializationError {
                message: format!("Unsupported input format for serialization: {:?}", self),
            })?,
        };
        Ok(body_data)
    }
}

impl From<&Path> for InputFile {
    fn from(path: &Path) -> Self {
        InputFile::File(path.into())
    }
}

impl TryInto<Box<dyn BufRead + Send>> for &InputFile {
    type Error = UnitctlError;

    fn try_into(self) -> Result<Box<dyn BufRead + Send>, Self::Error> {
        let reader: Box<dyn BufRead + Send> = match self {
            InputFile::Stdin(_) => Box::new(BufReader::new(io::stdin())),
            InputFile::File(_) | InputFile::FileWithFormat(_, _) => {
                let path = self.to_path()?;
                let file = std::fs::File::open(path).map_err(|e| UnitctlError::IoError { source: e })?;
                let reader = Box::new(BufReader::new(file));
                Box::new(reader)
            }
        };
        Ok(reader)
    }
}

impl TryInto<Vec<u8>> for &InputFile {
    type Error = UnitctlError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut buf: Vec<u8> = vec![];
        let mut reader: Box<dyn BufRead + Send> = self.try_into()?;
        reader
            .read_to_end(&mut buf)
            .map_err(|e| UnitctlError::IoError { source: e })?;
        Ok(buf)
    }
}

impl TryInto<KnownSize> for &InputFile {
    type Error = UnitctlError;

    fn try_into(self) -> Result<KnownSize, Self::Error> {
        let known_size: KnownSize = match self {
            InputFile::Stdin(_) => {
                let mut buf: Vec<u8> = vec![];
                let _ = io::stdin()
                    .read_to_end(&mut buf)
                    .map_err(|e| UnitctlError::IoError { source: e })?;
                KnownSize::Vec(buf)
            }
            InputFile::File(_) | InputFile::FileWithFormat(_, _) => {
                let path = self.to_path()?;
                let file = std::fs::File::open(path).map_err(|e| UnitctlError::IoError { source: e })?;
                let len = file.metadata().map_err(|e| UnitctlError::IoError { source: e })?.len();
                let reader = Box::new(file);
                KnownSize::Read(reader, len)
            }
        };
        Ok(known_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_parse_file_extensions() {
        assert_eq!(InputFormat::from_file_extension("yaml"), InputFormat::Yaml);
        assert_eq!(InputFormat::from_file_extension("yml"), InputFormat::Yaml);
        assert_eq!(InputFormat::from_file_extension("json"), InputFormat::Json);
        assert_eq!(InputFormat::from_file_extension("json5"), InputFormat::Json5);
        assert_eq!(InputFormat::from_file_extension("pem"), InputFormat::Pem);
        assert_eq!(InputFormat::from_file_extension("js"), InputFormat::JavaScript);
        assert_eq!(InputFormat::from_file_extension("njs"), InputFormat::JavaScript);
        assert_eq!(InputFormat::from_file_extension("txt"), InputFormat::Unknown);
    }

    #[test]
    fn can_parse_remote_paths() {
        assert_eq!(InputFormat::from_remote_path("//config"), InputFormat::Hjson);
        assert_eq!(InputFormat::from_remote_path("/config"), InputFormat::Hjson);
        assert_eq!(InputFormat::from_remote_path("/config/"), InputFormat::Hjson);
        assert_eq!(InputFormat::from_remote_path("config/"), InputFormat::Hjson);
        assert_eq!(InputFormat::from_remote_path("config"), InputFormat::Hjson);
        assert_eq!(InputFormat::from_remote_path("/config/something/"), InputFormat::Hjson);
        assert_eq!(InputFormat::from_remote_path("config/something/"), InputFormat::Hjson);
        assert_eq!(InputFormat::from_remote_path("config/something"), InputFormat::Hjson);
        assert_eq!(InputFormat::from_remote_path("/certificates"), InputFormat::Pem);
        assert_eq!(InputFormat::from_remote_path("/certificates/"), InputFormat::Pem);
        assert_eq!(InputFormat::from_remote_path("certificates/"), InputFormat::Pem);
        assert_eq!(InputFormat::from_remote_path("certificates"), InputFormat::Pem);
        assert_eq!(InputFormat::from_remote_path("js_modules"), InputFormat::JavaScript);
        assert_eq!(InputFormat::from_remote_path("js_modules/"), InputFormat::JavaScript);

        assert_eq!(
            InputFormat::from_remote_path("/certificates/something/"),
            InputFormat::Pem
        );
        assert_eq!(
            InputFormat::from_remote_path("certificates/something/"),
            InputFormat::Pem
        );
        assert_eq!(
            InputFormat::from_remote_path("certificates/something"),
            InputFormat::Pem
        );
    }
}
