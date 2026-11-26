//! OAuth request validation and protocol rules.

mod error;

pub use error::{EnvelopeError, OAuthErrorCode, ValidationError};

pub mod envelope;
pub mod pkce;
pub mod validate;

pub use validate::{
    AuthorizeRequest, AuthorizeRequestValidator, ValidatedAuthorizeRequest, validate,
};
