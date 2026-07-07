//! KROT client library.
//!
//! The library exposes the client-side of every operation the CLI supports,
//! so tests and third-party programs can enroll, authenticate and publish
//! tunnels without going through `krot` on stdin.

#![deny(missing_debug_implementations)]

pub mod config;
pub mod enroll;
pub mod error;
pub mod inspector;
pub mod local_auth;
pub mod login_page;
pub mod proxy;
pub mod session;
pub mod tls;
pub mod tunnel;

pub use config::{ClientConfig, Identity, ServerPin};
pub use enroll::{enroll, EnrollOptions};
pub use error::ClientError;
pub use inspector::{spawn_ui as spawn_inspector_ui, Inspector};
pub use local_auth::{
    api_key_from_str, read_env, read_file, session_from_userpass, AuthConfig, AuthConfigError,
    AuthPolicy, DEFAULT_REALM,
};
pub use login_page::SessionStore;
pub use session::{AuthenticatedSession, SessionTransport};
pub use tunnel::{publish_http, publish_http_authed, publish_tcp};
