use crate::inputfile::{InputFile, InputFormat};
use crate::requests::{send_and_validate_config_deserialize_response, send_empty_body_deserialize_response};
use crate::unitctl::UnitCtl;
use crate::{wait, OutputFormat, UnitctlError};
use std::path::{Path, PathBuf};
use unit_client_rs::unit_client::UnitClient;
use which::which;

const EDITOR_ENV_VARS: [&str; 2] = ["EDITOR", "VISUAL"];
const EDITOR_KNOWN_LIST: [&str; 8] = [
    "sensible-editor",
    "editor",
    "vim",
    "nano",
    "nvim",
    "vi",
    "pico",
    "emacs",
];

pub(crate) fn cmd(cli: &UnitCtl, output_format: OutputFormat) -> Result<(), UnitctlError> {
    let control_socket = wait::wait_for_socket(cli)?;
    let client = UnitClient::new(control_socket);
    // Get latest configuration
    let current_config = send_empty_body_deserialize_response(&client, "GET", "/config")?;

    // Write JSON to temporary file - this file will automatically be deleted by the OS when
    // the last file handle to it is removed.
    let mut temp_file = tempfile::Builder::new()
        .prefix("unitctl-")
        .suffix(".json")
        .tempfile()
        .map_err(|e| UnitctlError::IoError { source: e })?;

    // Pretty format JSON received from UNIT and write to the temporary file
    serde_json::to_writer_pretty(temp_file.as_file_mut(), &current_config)
        .map_err(|e| UnitctlError::SerializationError { message: e.to_string() })?;

    // Load edited file
    let temp_file_path = temp_file.path();
    let before_edit_mod_time = temp_file_path.metadata().ok().map(|m| m.modified().ok());

    let inputfile = InputFile::FileWithFormat(temp_file_path.into(), InputFormat::Json5);
    open_editor(temp_file_path)?;
    let after_edit_mod_time = temp_file_path.metadata().ok().map(|m| m.modified().ok());

    // Check if file was modified before sending to UNIT
    if let (Some(before), Some(after)) = (before_edit_mod_time, after_edit_mod_time) {
        if before == after {
            eprintln!("File was not modified - no changes will be sent to UNIT");
            return Ok(());
        }
    };

    // Send edited file to UNIT to overwrite current configuration
    send_and_validate_config_deserialize_response(&client, "PUT", "/config", Some(&inputfile))
        .and_then(|status| output_format.write_to_stdout(&status))
}

/// Look for an editor in the environment variables
fn find_editor_from_env() -> Option<PathBuf> {
    EDITOR_ENV_VARS
        .iter()
        .filter_map(std::env::var_os)
        .filter(|s| !s.is_empty())
        .filter_map(|s| which(s).ok())
        .filter_map(|path| path.canonicalize().ok())
        .find(|path| path.exists())
}

/// Look for editor in path by matching against a list of known editors or aliases
fn find_editor_from_known_list() -> Option<PathBuf> {
    EDITOR_KNOWN_LIST
        .iter()
        .filter_map(|editor| which(editor).ok())
        .filter_map(|path| path.canonicalize().ok())
        .find(|editor| editor.exists())
}

/// Find the path to an editor
pub fn find_editor_path() -> Result<PathBuf, UnitctlError> {
    find_editor_from_env()
        .or_else(find_editor_from_known_list)
        .ok_or_else(|| UnitctlError::EditorError {
            message: "Could not find an editor".to_string(),
        })
}

/// Start an editor with a given path
pub fn open_editor(path: &Path) -> Result<(), UnitctlError> {
    let editor_path = find_editor_path()?;
    let status = std::process::Command::new(editor_path)
        .arg(path)
        .status()
        .map_err(|e| UnitctlError::EditorError {
            message: format!("Could not open editor: {}", e),
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(UnitctlError::EditorError {
            message: format!("Editor exited with non-zero status: {}", status),
        })
    }
}
