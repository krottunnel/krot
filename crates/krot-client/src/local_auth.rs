//! Client-side HTTP auth for published tunnels.
//!
//! Two policies, one flag each. `--auth user:pass` gives humans a
//! styled login page + session cookie ([`AuthPolicy::Session`]).
//! `--api-key <key>` gives machines a header-based bearer token
//! ([`AuthPolicy::ApiKey`]). Session flow lives in [`crate::login_page`];
//! this module handles the header-level checks and per-request
//! decision-making.
//!
//! Scope: HTTP tunnels only (`krot http`). HTTPS-passthrough streams
//! (first byte `0x16`, TLS ClientHello) are opaque — the client can't
//! read encrypted headers without terminating TLS, and passes them
//! through unauthenticated. A warning is printed at CLI startup so the
//! operator knows auth only protects the plain-HTTP branch.
//!
//! Constant-time comparison protects against timing side-channels
//! probing credential length or prefix.

use std::path::Path;
use std::sync::Arc;

use crate::login_page::{self, SessionStore, LOGIN_PATH, LOGOUT_PATH};

/// One authenticator policy attached to a tunnel. Cheap to clone.
#[derive(Debug, Clone)]
pub enum AuthPolicy {
    /// Human-facing form-based auth. A GET to any protected URL without
    /// a valid `__krot_session` cookie is rewritten to the login page;
    /// POST `/__krot/login` validates `user`/`pass` in constant time
    /// and installs a session cookie.
    Session {
        user: String,
        pass: String,
        store: Arc<SessionStore>,
    },
    /// A single opaque bearer token. Accepted on both
    /// `Authorization: Bearer <key>` and `X-API-Key: <key>` headers.
    ApiKey { key: String },
}

/// Complete auth configuration for one tunnel. `realm` is still carried
/// for API-key `WWW-Authenticate`-style diagnostics; the session UI
/// derives its title from the branding embedded in the login template.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub policy: AuthPolicy,
    pub realm: String,
}

/// Default realm string used when the CLI does not override it. Kept
/// deliberately anodyne — no service-identifying data leaks.
pub const DEFAULT_REALM: &str = "KROT Protected Tunnel";

/// Outcome of an API-key check against parsed HTTP headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Missing,
    BadCreds,
}

/// What the proxy should do after inspecting a request under a
/// [`AuthPolicy::Session`] policy.
#[derive(Debug, Clone)]
pub enum SessionAction {
    /// Valid session — forward buffered bytes to the local target.
    Forward,
    /// Serve the styled login page as the response for this request.
    /// `next` is the path the user was originally trying to reach.
    ServeLoginPage {
        next: String,
        error: Option<&'static str>,
    },
    /// Send a 302 redirect. `location` is the target URL; `set_cookie`
    /// (if present) is the raw `Set-Cookie` value line to attach.
    Redirect {
        location: String,
        set_cookie: Option<String>,
    },
}

impl AuthPolicy {
    /// Check `X-API-Key` / `Authorization: Bearer` against an `ApiKey`
    /// policy. Panics if called on a `Session` policy.
    #[must_use]
    pub fn check_api_key(&self, headers: &[httparse::Header<'_>]) -> Outcome {
        match self {
            Self::ApiKey { key } => check_api_key(key, headers),
            Self::Session { .. } => {
                debug_assert!(false, "check_api_key called on Session policy");
                Outcome::BadCreds
            }
        }
    }

    /// Decide what to do with a request under a `Session` policy. `body`
    /// is the request body slice (only used for `POST /__krot/login`).
    /// Panics if called on an `ApiKey` policy.
    #[must_use]
    pub fn decide_session(
        &self,
        method: &str,
        path: &str,
        headers: &[httparse::Header<'_>],
        body: &[u8],
    ) -> SessionAction {
        match self {
            Self::Session { user, pass, store } => {
                decide_session_inner(user, pass, store, method, path, headers, body)
            }
            Self::ApiKey { .. } => {
                debug_assert!(false, "decide_session called on ApiKey policy");
                SessionAction::Redirect {
                    location: "/".to_string(),
                    set_cookie: None,
                }
            }
        }
    }
}

fn decide_session_inner(
    user: &str,
    pass: &str,
    store: &SessionStore,
    method: &str,
    path: &str,
    headers: &[httparse::Header<'_>],
    body: &[u8],
) -> SessionAction {
    let (path_only, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };

    // /__krot/logout: clear cookie regardless of method, redirect home.
    if path_only == LOGOUT_PATH {
        if let Some(tok) = current_session_token(headers) {
            store.invalidate(tok);
        }
        return SessionAction::Redirect {
            location: "/".to_string(),
            set_cookie: Some(login_page::session_clear_cookie()),
        };
    }

    // /__krot/login (POST): validate creds.
    if path_only == LOGIN_PATH && method.eq_ignore_ascii_case("POST") {
        let body_str = std::str::from_utf8(body).unwrap_or("");
        let form = login_page::parse_login_form(body_str);
        let ok = form.user.as_deref() == Some(user)
            && constant_time_eq(
                form.pass.as_deref().unwrap_or("").as_bytes(),
                pass.as_bytes(),
            );
        let next = form
            .next
            .as_deref()
            .map_or_else(|| "/".to_string(), login_page::safe_next);
        if ok {
            let token = store.create();
            return SessionAction::Redirect {
                location: next,
                set_cookie: Some(login_page::session_set_cookie(&token)),
            };
        }
        return SessionAction::ServeLoginPage {
            next,
            error: Some("Invalid username or password."),
        };
    }

    // /__krot/login (GET): show the form.
    if path_only == LOGIN_PATH {
        let next = query
            .and_then(|q| q.split('&').find_map(|pair| pair.strip_prefix("next=")))
            .map(login_page::form_decode)
            .as_deref()
            .map_or_else(|| "/".to_string(), login_page::safe_next);
        return SessionAction::ServeLoginPage { next, error: None };
    }

    // Everything else: gate on the session cookie.
    if let Some(tok) = current_session_token(headers) {
        if store.validate_and_refresh(tok) {
            return SessionAction::Forward;
        }
    }
    SessionAction::Redirect {
        location: format!("{LOGIN_PATH}?next={}", percent_encode_path(path)),
        set_cookie: None,
    }
}

fn current_session_token<'a>(headers: &'a [httparse::Header<'_>]) -> Option<&'a str> {
    for h in headers {
        if h.name.eq_ignore_ascii_case("cookie") {
            if let Ok(value) = std::str::from_utf8(h.value) {
                if let Some(tok) = login_page::extract_session_cookie(value) {
                    return Some(tok);
                }
            }
        }
    }
    None
}

/// Minimal `application/x-www-form-urlencoded`-style percent-encoding
/// for a redirect path. Only escapes characters that would break the
/// query-string context (`&`, `#`, ` `, `%`, `?`, `+`, non-ASCII, CR/LF).
fn percent_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'/'
            | b':'
            | b'@'
            | b','
            | b';'
            | b'=' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(hex_upper(b >> 4));
                out.push(hex_upper(b & 0x0f));
            }
        }
    }
    out
}

const fn hex_upper(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'A' + n - 10) as char,
    }
}

fn check_api_key(key: &str, headers: &[httparse::Header<'_>]) -> Outcome {
    let mut saw_header = false;
    for h in headers {
        if h.name.eq_ignore_ascii_case("x-api-key") {
            saw_header = true;
            let Ok(value) = std::str::from_utf8(h.value) else {
                return Outcome::BadCreds;
            };
            if constant_time_eq(value.trim().as_bytes(), key.as_bytes()) {
                return Outcome::Ok;
            }
        }
        if h.name.eq_ignore_ascii_case("authorization") {
            saw_header = true;
            let Ok(value) = std::str::from_utf8(h.value) else {
                return Outcome::BadCreds;
            };
            let Some(rest) = strip_scheme_ci(value.trim(), "bearer") else {
                continue;
            };
            if constant_time_eq(rest.trim().as_bytes(), key.as_bytes()) {
                return Outcome::Ok;
            }
        }
    }
    if saw_header {
        Outcome::BadCreds
    } else {
        Outcome::Missing
    }
}

fn strip_scheme_ci<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    if value.len() <= scheme.len() {
        return None;
    }
    let (head, tail) = value.split_at(scheme.len());
    if !head.eq_ignore_ascii_case(scheme) {
        return None;
    }
    if !tail.starts_with(char::is_whitespace) {
        return None;
    }
    Some(tail)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Build the 403 reject response for a failed API-key check. (The
/// session flow uses [`login_page`] helpers directly.)
#[must_use]
pub fn api_key_reject_response() -> Vec<u8> {
    let body = b"Forbidden";
    let head = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len(),
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Heuristic on the first byte of a data stream: `0x16` is a TLS
/// record header, so the stream carries SNI-passthrough HTTPS and the
/// client cannot read the request line. Anything else is treated as
/// plain HTTP.
#[must_use]
pub const fn looks_like_tls(first_byte: u8) -> bool {
    first_byte == 0x16
}

/// Parse a `user:pass` string and pair it with a fresh session store,
/// producing an [`AuthPolicy::Session`].
pub fn session_from_userpass(
    s: &str,
    store: Arc<SessionStore>,
) -> Result<AuthPolicy, AuthConfigError> {
    let (user, pass) = s.split_once(':').ok_or(AuthConfigError::MissingColon)?;
    if user.is_empty() {
        return Err(AuthConfigError::EmptyUser);
    }
    Ok(AuthPolicy::Session {
        user: user.to_string(),
        pass: pass.to_string(),
        store,
    })
}

/// Wrap an opaque API key.
#[must_use]
pub fn api_key_from_str(s: &str) -> AuthPolicy {
    AuthPolicy::ApiKey {
        key: s.trim().to_string(),
    }
}

pub fn read_env(var: &str) -> Result<String, AuthConfigError> {
    let value = std::env::var(var).map_err(|_| AuthConfigError::EnvUnset(var.to_string()))?;
    if value.is_empty() {
        return Err(AuthConfigError::EnvUnset(var.to_string()));
    }
    Ok(value)
}

pub fn read_file(path: &Path) -> Result<String, AuthConfigError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| AuthConfigError::FileRead(path.display().to_string(), e.to_string()))?;
    let trimmed = raw.trim_end_matches(['\r', '\n']).to_string();
    if trimmed.is_empty() {
        return Err(AuthConfigError::FileEmpty(path.display().to_string()));
    }
    Ok(trimmed)
}

#[derive(Debug, thiserror::Error)]
pub enum AuthConfigError {
    #[error("--auth value missing the `:` separator")]
    MissingColon,
    #[error("--auth username is empty")]
    EmptyUser,
    #[error("env var `{0}` is unset or empty")]
    EnvUnset(String),
    #[error("cannot read `{0}`: {1}")]
    FileRead(String, String),
    #[error("file `{0}` is empty")]
    FileEmpty(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header<'a>(name: &'a str, value: &'a [u8]) -> httparse::Header<'a> {
        httparse::Header { name, value }
    }

    fn session_policy() -> AuthPolicy {
        AuthPolicy::Session {
            user: "alice".into(),
            pass: "s3cret".into(),
            store: SessionStore::new(),
        }
    }

    #[test]
    fn session_from_userpass_parses() {
        let store = SessionStore::new();
        let AuthPolicy::Session { user, pass, .. } =
            session_from_userpass("alice:s3cret", store).unwrap()
        else {
            panic!("expected Session");
        };
        assert_eq!(user, "alice");
        assert_eq!(pass, "s3cret");
    }

    #[test]
    fn session_from_userpass_requires_colon() {
        assert!(matches!(
            session_from_userpass("noColonHere", SessionStore::new()),
            Err(AuthConfigError::MissingColon),
        ));
    }

    #[test]
    fn session_from_userpass_rejects_empty_user() {
        assert!(matches!(
            session_from_userpass(":passonly", SessionStore::new()),
            Err(AuthConfigError::EmptyUser),
        ));
    }

    #[test]
    fn session_missing_cookie_redirects_to_login() {
        let policy = session_policy();
        let action = policy.decide_session("GET", "/dashboard", &[], b"");
        let SessionAction::Redirect {
            location,
            set_cookie,
        } = action
        else {
            panic!("expected Redirect, got {action:?}");
        };
        assert_eq!(set_cookie, None);
        assert!(location.starts_with("/__krot/login?next="));
        assert!(location.contains("%2Fdashboard") || location.contains("/dashboard"));
    }

    #[test]
    fn session_valid_cookie_forwards() {
        let policy = session_policy();
        let AuthPolicy::Session { ref store, .. } = policy else {
            unreachable!()
        };
        let token = store.create();
        let cookie = format!("__krot_session={token}");
        let hs = [header("Cookie", cookie.as_bytes())];
        let action = policy.decide_session("GET", "/dashboard", &hs, b"");
        assert!(matches!(action, SessionAction::Forward), "{action:?}");
    }

    #[test]
    fn session_login_get_serves_page() {
        let policy = session_policy();
        let action = policy.decide_session("GET", "/__krot/login", &[], b"");
        let SessionAction::ServeLoginPage { next, error } = action else {
            panic!("expected ServeLoginPage");
        };
        assert_eq!(next, "/");
        assert!(error.is_none());
    }

    #[test]
    fn session_login_get_honours_next_query() {
        let policy = session_policy();
        let action = policy.decide_session("GET", "/__krot/login?next=%2Fdash", &[], b"");
        let SessionAction::ServeLoginPage { next, .. } = action else {
            panic!("expected ServeLoginPage");
        };
        assert_eq!(next, "/dash");
    }

    #[test]
    fn session_login_post_correct_creds_sets_cookie() {
        let policy = session_policy();
        let body = b"user=alice&pass=s3cret&next=%2Fhome";
        let action = policy.decide_session("POST", "/__krot/login", &[], body);
        let SessionAction::Redirect {
            location,
            set_cookie,
        } = action
        else {
            panic!("expected Redirect");
        };
        assert_eq!(location, "/home");
        let sc = set_cookie.expect("cookie");
        assert!(sc.contains("__krot_session="));
        assert!(sc.contains("HttpOnly"));
    }

    #[test]
    fn session_login_post_wrong_creds_shows_error() {
        let policy = session_policy();
        let body = b"user=alice&pass=wrong&next=%2F";
        let action = policy.decide_session("POST", "/__krot/login", &[], body);
        let SessionAction::ServeLoginPage { error, .. } = action else {
            panic!("expected ServeLoginPage");
        };
        assert!(error.is_some());
    }

    #[test]
    fn session_logout_clears_cookie() {
        let policy = session_policy();
        let AuthPolicy::Session { ref store, .. } = policy else {
            unreachable!()
        };
        let token = store.create();
        let cookie = format!("__krot_session={token}");
        let hs = [header("Cookie", cookie.as_bytes())];
        let action = policy.decide_session("GET", "/__krot/logout", &hs, b"");
        let SessionAction::Redirect {
            location,
            set_cookie,
        } = action
        else {
            panic!("expected Redirect");
        };
        assert_eq!(location, "/");
        let sc = set_cookie.expect("clear cookie");
        assert!(sc.contains("Max-Age=0"));
        assert!(!store.validate_and_refresh(&token));
    }

    #[test]
    fn session_expired_cookie_redirects() {
        let policy = session_policy();
        let hs = [header("Cookie", b"__krot_session=nope")];
        let action = policy.decide_session("GET", "/x", &hs, b"");
        assert!(matches!(action, SessionAction::Redirect { .. }));
    }

    // -------- API-key path unchanged --------

    #[test]
    fn api_key_accepts_x_api_key() {
        let p = AuthPolicy::ApiKey {
            key: "sk_live_42".into(),
        };
        let hs = [header("X-API-Key", b"sk_live_42")];
        assert_eq!(p.check_api_key(&hs), Outcome::Ok);
    }

    #[test]
    fn api_key_accepts_bearer() {
        let p = AuthPolicy::ApiKey {
            key: "sk_live_42".into(),
        };
        let hs = [header("Authorization", b"Bearer sk_live_42")];
        assert_eq!(p.check_api_key(&hs), Outcome::Ok);
    }

    #[test]
    fn api_key_rejects_wrong() {
        let p = AuthPolicy::ApiKey {
            key: "sk_live_42".into(),
        };
        let hs = [header("X-API-Key", b"nope")];
        assert_eq!(p.check_api_key(&hs), Outcome::BadCreds);
    }

    #[test]
    fn api_key_missing_returns_missing() {
        let p = AuthPolicy::ApiKey {
            key: "sk_live_42".into(),
        };
        let hs = [header("Host", b"example")];
        assert_eq!(p.check_api_key(&hs), Outcome::Missing);
    }

    #[test]
    fn api_key_reject_shape() {
        let bytes = api_key_reject_response();
        let head = std::str::from_utf8(&bytes).unwrap();
        assert!(head.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(!head.contains("WWW-Authenticate"));
        assert!(head.ends_with("Forbidden"));
    }

    #[test]
    fn tls_heuristic() {
        assert!(looks_like_tls(0x16));
        assert!(!looks_like_tls(b'G'));
        assert!(!looks_like_tls(b'P'));
    }

    #[test]
    fn constant_time_eq_correctness() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"diff"));
        assert!(!constant_time_eq(b"a", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn read_file_trims_trailing_newlines() {
        use std::io::Write as _;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secret");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"hunter2\n\n").unwrap();
        assert_eq!(read_file(&path).unwrap(), "hunter2");
    }

    #[test]
    fn read_file_rejects_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("empty");
        std::fs::write(&path, b"").unwrap();
        assert!(matches!(
            read_file(&path),
            Err(AuthConfigError::FileEmpty(_))
        ));
    }

    proptest::proptest! {
        #[test]
        fn api_key_check_never_panics(
            name in ".{0,64}",
            value in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..1024),
        ) {
            let policy = AuthPolicy::ApiKey { key: "sk".into() };
            let hs = [httparse::Header { name: &name, value: &value }];
            let _ = policy.check_api_key(&hs);
        }

        #[test]
        fn decide_session_never_panics(
            method in "[A-Z]{0,10}",
            path in ".{0,256}",
            cookie in ".{0,256}",
            body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048),
        ) {
            let policy = AuthPolicy::Session {
                user: "u".into(),
                pass: "p".into(),
                store: SessionStore::new(),
            };
            let hs = [httparse::Header { name: "Cookie", value: cookie.as_bytes() }];
            let _ = policy.decide_session(&method, &path, &hs, &body);
        }

        #[test]
        fn session_from_userpass_never_panics(s in ".{0,256}") {
            let _ = session_from_userpass(&s, SessionStore::new());
        }
    }
}
