//! Secure fixture: the [`TableAuth`] authenticator (always available) and, with the
//! `json` feature, the `SecureApp` used by the security tests.

pub use crate::auth::TableAuth;

#[cfg(feature = "json")]
#[path = "secure_app.rs"]
mod app;
#[cfg(feature = "json")]
pub use app::*;
