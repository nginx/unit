use crate::apis::Error;
use std::error::Error as StdError;
use std::fmt::{Display, Formatter};

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Api(e) => write!(f, "ApiError: {:#?}", e),
            Error::Header(e) => write!(f, "HeaderError: {}", e),
            Error::Http(e) => write!(f, "HttpError: {:#?}", e),
            Error::Hyper(e) => write!(f, "HyperError: {:#?}", e),
            Error::Serde(e) => write!(f, "SerdeError: {:#?}", e),
            Error::UriError(e) => write!(f, "UriError: {:#?}", e),
        }
    }
}

impl StdError for Error {}
