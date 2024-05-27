use std::fmt::{Display, Formatter};
use std::io::Error as IoError;
use std::process::{ExitCode, Termination};
use unit_client_rs::unit_client::UnitClientError;

use custom_error::custom_error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ControlSocketErrorKind {
    NotFound,
    Permissions,
    Parse,
    General,
}

impl Display for ControlSocketErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?}", self)
    }
}

custom_error! {pub UnitctlError
    ControlSocketError { kind: ControlSocketErrorKind, message: String } = "{message}",
    CertificateError { message: String } = "Certificate error: {message}",
    EditorError { message: String } = "Error opening editor: {message}",
    NoUnitInstancesError = "No running unit instances found",
    MultipleUnitInstancesError {
        suggestion: String} = "Multiple unit instances found: {suggestion}",
    NoSocketPathError = "Unable to detect socket path from running instance",
    NoInputFileError = "No input file specified when required",
    UiServerError { message: String } = "UI server error: {message}",
    UnitClientError { source: UnitClientError } = "Unit client error: {source}",
    SerializationError { message: String } = "Serialization error: {message}",
    DeserializationError { message: String } = "Deserialization error: {message}",
    IoError { source: IoError } = "IO error: {source}",
    PathNotFound { path: String } = "Path not found: {path}",
    UnknownInputFileType { path: String } = "Unknown input type for file: {path}",
    NoFilesImported = "All imports failed",
    WaitTimeoutError = "Timeout waiting for unit to start has been exceeded",
}

impl UnitctlError {
    pub fn exit_code(&self) -> i32 {
        match self {
            UnitctlError::NoUnitInstancesError => 10,
            UnitctlError::MultipleUnitInstancesError { .. } => 11,
            UnitctlError::NoSocketPathError => 12,
            UnitctlError::UnitClientError { .. } => 13,
            UnitctlError::WaitTimeoutError => 14,
            _ => 99,
        }
    }

    pub fn retryable(&self) -> bool {
        match self {
            UnitctlError::ControlSocketError { kind, .. } => {
                // try again because there is no socket created yet
                ControlSocketErrorKind::NotFound == *kind
            }
            // try again because unit isn't running
            UnitctlError::NoUnitInstancesError => true,
            // do not retry because this is an unrecoverable error
            _ => false,
        }
    }
}

impl Termination for UnitctlError {
    fn report(self) -> ExitCode {
        ExitCode::from(self.exit_code() as u8)
    }
}
