use crate::inputfile::InputFile;
use crate::requests::{
    send_and_validate_config_deserialize_response, send_and_validate_pem_data_deserialize_response,
    send_body_deserialize_response, send_empty_body_deserialize_response,
};
use crate::unitctl::UnitCtl;
use crate::wait;
use crate::{eprint_error, OutputFormat, UnitctlError};
use unit_client_rs::unit_client::UnitClient;

pub(crate) async fn cmd(
    cli: &UnitCtl,
    output_format: &OutputFormat,
    input_file: &Option<String>,
    method: &str,
    path: &str,
) -> Result<(), UnitctlError> {
    let clients: Vec<_> = wait::wait_for_sockets(cli)
        .await?
        .into_iter()
        .map(|sock| UnitClient::new(sock))
        .collect();

    let path_trimmed = path.trim();
    let method_upper = method.to_uppercase();
    let input_file_arg = input_file
        .as_ref()
        .map(|file| InputFile::new(file, &path_trimmed.to_string()));

    if method_upper.eq("GET") && input_file.is_some() {
        eprintln!("Cannot use GET method with input file - ignoring input file");
    }

    for client in clients {
        let _ = send_and_deserialize(
            client,
            method_upper.clone(),
            input_file_arg.clone(),
            path_trimmed,
            output_format,
        )
        .await
        .map_err(|e| {
            eprint_error(&e);
            std::process::exit(e.exit_code());
        });
    }

    Ok(())
}

async fn send_and_deserialize(
    client: UnitClient,
    method: String,
    input_file: Option<InputFile>,
    path: &str,
    output_format: &OutputFormat,
) -> Result<(), UnitctlError> {
    let is_js_modules_dir = path.starts_with("/js_modules/") || path.starts_with("js_modules/");

    // If we are sending a GET request to a JS modules directory, we want to print the contents of the JS file
    // instead of the JSON response
    if method.eq("GET") && is_js_modules_dir && path.ends_with(".js") {
        let script =
            send_body_deserialize_response::<String>(&client, method.as_str(), path, input_file.as_ref()).await?;
        println!("{}", script);
        return Ok(());
    }

    // Otherwise, we want to print the JSON response (a map) as represented by the output format
    match input_file {
        Some(input_file) => {
            if input_file.is_config() {
                send_and_validate_config_deserialize_response(&client, method.as_str(), path, Some(&input_file)).await
                // TLS certificate data
            } else if input_file.is_pem_bundle() {
                send_and_validate_pem_data_deserialize_response(&client, method.as_str(), path, &input_file).await
                // This is unknown data
            } else {
                panic!("Unknown input file type")
            }
        }
        // A none value for an input file can be considered a request to send an empty body
        None => send_empty_body_deserialize_response(&client, method.as_str(), path).await,
    }
    .and_then(|status| output_format.write_to_stdout(&status))
}
