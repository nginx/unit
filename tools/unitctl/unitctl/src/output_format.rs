use crate::UnitctlError;
use clap::ValueEnum;
use colored_json::ColorMode;
use serde::Serialize;
use std::io::{stdout, BufWriter, Write};

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    Yaml,
    Json,
    #[value(id = "json-pretty")]
    JsonPretty,
    Text,
}

impl OutputFormat {
    pub fn write_to_stdout<T>(&self, object: &T) -> Result<(), UnitctlError>
    where
        T: ?Sized + Serialize,
    {
        let no_color = std::env::var("NO_COLOR").map_or(false, |_| true);
        let mut out = stdout();
        let value =
            serde_json::to_value(object).map_err(|e| UnitctlError::SerializationError { message: e.to_string() })?;

        match (self, no_color) {
            (OutputFormat::Yaml, _) => serde_yaml::to_writer(BufWriter::new(out), &value)
                .map_err(|e| UnitctlError::SerializationError { message: e.to_string() }),
            (OutputFormat::Json, _) => serde_json::to_writer(BufWriter::new(out), &value)
                .map_err(|e| UnitctlError::SerializationError { message: e.to_string() }),
            (OutputFormat::JsonPretty, true) => serde_json::to_writer_pretty(BufWriter::new(out), &value)
                .map_err(|e| UnitctlError::SerializationError { message: e.to_string() }),
            (OutputFormat::JsonPretty, false) => {
                let mode = ColorMode::Auto(colored_json::Output::StdOut);
                colored_json::write_colored_json_with_mode(&value, &mut out, mode)
                    .map_err(|e| UnitctlError::SerializationError { message: e.to_string() })
            }
            (OutputFormat::Text, _) => stdout()
                .write_fmt(format_args!("{:?}", &value))
                .map_err(|e| UnitctlError::IoError { source: e }),
        }
    }
}
