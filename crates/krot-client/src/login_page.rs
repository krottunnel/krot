//! Styled login page + in-memory session store for `--auth` tunnels.
//!
//! Replaces the browser's native Basic-auth dialog with a proper HTML
//! form. Successful POST yields a random session token stored server-side
//! (in-memory, per-process) and mirrored in an `HttpOnly;
//! SameSite=Lax` cookie. Subsequent requests carry the cookie and are
//! forwarded to localhost without re-prompting.
//!
//! Sessions have an 8-hour TTL that refreshes on every validated hit
//! (rolling window). The store is small — one entry per active browser
//! tab — so a `HashMap` behind a `Mutex` is fine.
//!
//! Cookie flags: `HttpOnly` (JS cannot read it) and `SameSite=Lax`
//! (CSRF defence). The `Secure` flag is deliberately **not** set —
//! the login-page auth branch only runs on plain-HTTP tunnel traffic
//! (HTTPS-passthrough is opaque to the client), so a `Secure`-flagged
//! cookie would be dropped by the browser on the very next request
//! and the user would loop back to the login page. If you need
//! encrypted end-to-end auth, terminate TLS on the tunnel target
//! itself rather than relying on `--auth`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;

/// Rolling session lifetime. Chosen to cover a full working day without
/// mid-session re-login; refreshed on each request.
pub const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);

/// Cookie name. Underscore-prefixed to avoid collisions with the wrapped
/// application's own cookies.
pub const SESSION_COOKIE: &str = "__krot_session";

/// URL path served by krot itself (intercepted before reaching the local
/// target). Chosen to be unlikely to collide with real routes.
pub const LOGIN_PATH: &str = "/__krot/login";
pub const LOGOUT_PATH: &str = "/__krot/logout";

/// Cap on the POST body we're willing to read for the login form. The
/// form has two short fields plus a redirect; 4 KiB is generous.
pub const LOGIN_BODY_CAP: usize = 4 * 1024;

/// Thread-safe map of `token -> expiry`. Cheap to clone via `Arc`.
#[derive(Debug, Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, Instant>>,
}

impl SessionStore {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Insert a fresh random token, evicting anything already expired.
    /// Returns the hex-encoded 32-byte token.
    pub fn create(&self) -> String {
        let token = new_token();
        let mut g = self.inner.lock().expect("session store poisoned");
        prune(&mut g);
        g.insert(token.clone(), Instant::now() + SESSION_TTL);
        token
    }

    /// If `token` exists and is still valid, extend its expiry and
    /// return `true`. Expired tokens are removed.
    pub fn validate_and_refresh(&self, token: &str) -> bool {
        let mut g = self.inner.lock().expect("session store poisoned");
        match g.get(token).copied() {
            Some(exp) if exp > Instant::now() => {
                g.insert(token.to_string(), Instant::now() + SESSION_TTL);
                true
            }
            Some(_) => {
                g.remove(token);
                false
            }
            None => false,
        }
    }

    pub fn invalidate(&self, token: &str) {
        let _ = self
            .inner
            .lock()
            .expect("session store poisoned")
            .remove(token);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

fn prune(map: &mut HashMap<String, Instant>) {
    let now = Instant::now();
    map.retain(|_, exp| *exp > now);
}

fn new_token() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push(hex_char(byte >> 4));
        s.push(hex_char(byte & 0x0f));
    }
    s
}

const fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + nibble - 10) as char,
    }
}

/// Extract the `__krot_session` value from a `Cookie:` header value.
/// Returns the first matching cookie's value (as `str`), or `None`.
#[must_use]
pub fn extract_session_cookie(cookie_header: &str) -> Option<&str> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(v) = pair.strip_prefix(SESSION_COOKIE) {
            if let Some(v) = v.strip_prefix('=') {
                return Some(v);
            }
        }
    }
    None
}

/// URL-decode a single form value (`application/x-www-form-urlencoded`).
/// Handles `+` → space and `%HH` → byte. Invalid `%HH` sequences are
/// left as-is (safer than panicking on adversarial input).
#[must_use]
pub fn form_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_val(bytes[i + 1]);
                let lo = hex_val(bytes[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4) | l);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse an `application/x-www-form-urlencoded` body, returning the
/// first `user`, `pass`, and `next` fields (all optional).
#[must_use]
pub fn parse_login_form(body: &str) -> LoginForm {
    let mut user = None;
    let mut pass = None;
    let mut next = None;
    for pair in body.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let value = form_decode(v);
        match k {
            "user" if user.is_none() => user = Some(value),
            "pass" if pass.is_none() => pass = Some(value),
            "next" if next.is_none() => next = Some(value),
            _ => {}
        }
    }
    LoginForm { user, pass, next }
}

#[derive(Debug, Clone, Default)]
pub struct LoginForm {
    pub user: Option<String>,
    pub pass: Option<String>,
    pub next: Option<String>,
}

/// HTML-escape a `next` path before echoing it into the form. Prevents
/// a crafted URL from breaking out of the `value=""` attribute.
#[must_use]
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Guard against open-redirect: only accept `next` values that are
/// site-relative paths (start with `/` and don't try to become
/// scheme-relative `//host` or protocol `http:` URLs).
#[must_use]
pub fn safe_next(candidate: &str) -> String {
    if candidate.starts_with('/')
        && !candidate.starts_with("//")
        && !candidate.contains('\r')
        && !candidate.contains('\n')
    {
        candidate.to_string()
    } else {
        "/".to_string()
    }
}

/// Build the HTML login page. `next` is echoed into a hidden input so
/// the POST handler can redirect back after auth. `error` renders a
/// small message under the form.
#[must_use]
pub fn render_login_page(next: &str, error: Option<&str>) -> String {
    let next_esc = html_escape(next);
    let error_block = match error {
        Some(msg) => format!(r#"<p class="err">{}</p>"#, html_escape(msg)),
        None => String::new(),
    };
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>krot · sign in</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  html,body {{ height: 100%; margin: 0; }}
  body {{
    background: #1a1410;
    color: #e8dcd0;
    font: 15px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, system-ui, sans-serif;
    display: grid; place-items: center;
  }}
  .card {{
    width: min(360px, 92vw);
    background: #221913;
    border: 1px solid #3a2a20;
    border-radius: 14px;
    padding: 32px 28px;
    box-shadow: 0 12px 40px rgba(0,0,0,.35);
  }}
  .brand {{ display: flex; align-items: center; gap: 12px; margin-bottom: 24px; }}
  .brand .mole {{ width: 48px; height: 48px; flex: 0 0 auto; }}
  .brand .word {{ display: flex; flex-direction: column; line-height: 1; }}
  .brand .word .name {{ font-size: 26px; font-weight: 800; letter-spacing: -0.5px; }}
  .brand .word .name em {{ font-style: normal; color: #e89a9a; }}
  .brand .word .trail {{ margin-top: 4px; width: 100%; height: 8px; display: block; }}
  .brand .word .tag {{ margin-top: 6px; font-size: 9px; letter-spacing: 3px; color: #8a7a6a; text-transform: uppercase; }}
  label {{ display: block; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #a89a8a; margin: 14px 0 6px; }}
  input[type=text], input[type=password] {{
    width: 100%; padding: 10px 12px;
    background: #1a1410; color: #f5ece0;
    border: 1px solid #3a2a20; border-radius: 8px;
    font: inherit;
  }}
  input:focus {{ outline: none; border-color: #e89a9a; }}
  button {{
    margin-top: 20px; width: 100%;
    padding: 11px 14px; border: 0; border-radius: 8px;
    background: #e89a9a; color: #2b1a14;
    font-weight: 700; font-size: 15px; cursor: pointer;
  }}
  button:hover {{ background: #f0b0b0; }}
  .err {{ margin: 14px 0 0; padding: 10px 12px; background: #3a1a1a; border: 1px solid #7a2a2a; border-radius: 8px; color: #f5b0b0; font-size: 13px; }}
  .foot {{ margin-top: 22px; text-align: center; font-size: 11px; color: #6a5a4a; }}
</style>
</head>
<body>
  <form class="card" method="post" action="{LOGIN_PATH}">
    <div class="brand">
      <svg class="mole" viewBox="0 0 120 120" aria-hidden="true">
        <ellipse cx="60" cy="70" rx="42" ry="34" fill="#5a3a28"/>
        <circle cx="60" cy="50" r="30" fill="#6a4a34"/>
        <path d="M42 46 h10 M68 46 h10" stroke="#2b1a12" stroke-width="3" stroke-linecap="round"/>
        <path d="M55 62 L60 70 L65 62 Z" fill="#e89a9a"/>
        <circle cx="60" cy="66" r="1.6" fill="#2b1a12"/>
        <ellipse cx="34" cy="82" rx="10" ry="8" fill="#e89a9a"/>
        <ellipse cx="86" cy="82" rx="10" ry="8" fill="#e89a9a"/>
      </svg>
      <div class="word">
        <div class="name">kr<em>o</em>t</div>
        <svg class="trail" viewBox="0 0 160 8" preserveAspectRatio="none" aria-hidden="true">
          <path d="M2 4 Q 12 0, 22 4 T 42 4 T 62 4 T 82 4 T 102 4 T 122 4 T 142 4"
                fill="none" stroke="#e89a9a" stroke-width="1.5" stroke-linecap="round"/>
          <circle cx="30" cy="6" r="0.8" fill="#8a5a4a"/>
          <circle cx="70" cy="6" r="0.8" fill="#8a5a4a"/>
          <circle cx="110" cy="6" r="0.8" fill="#8a5a4a"/>
          <circle cx="152" cy="4" r="2" fill="#2b1a12" stroke="#e89a9a" stroke-width="1"/>
        </svg>
        <div class="tag">tunnels that dig</div>
      </div>
    </div>
    {error_block}
    <label for="u">Username</label>
    <input id="u" name="user" type="text" autocomplete="username" autofocus required>
    <label for="p">Password</label>
    <input id="p" name="pass" type="password" autocomplete="current-password" required>
    <input type="hidden" name="next" value="{next_esc}">
    <button type="submit">Sign in</button>
    <div class="foot">protected by krot</div>
  </form>
</body>
</html>
"##
    )
}

/// Build a full HTTP/1.1 200 response wrapping the given HTML body.
#[must_use]
pub fn http_html_response(body: &str) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        len = body.len(),
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

/// Build a 302 redirect. If `set_cookie` is `Some(value)`, a
/// `HttpOnly; SameSite=Lax` cookie is attached. See the module docs
/// for why `Secure` is deliberately omitted.
#[must_use]
pub fn http_redirect(location: &str, set_cookie: Option<&str>) -> Vec<u8> {
    let cookie_line = match set_cookie {
        Some(v) => format!("Set-Cookie: {v}\r\n"),
        None => String::new(),
    };
    let body = b"";
    let head = format!(
        "HTTP/1.1 302 Found\r\n\
         Location: {location}\r\n\
         {cookie_line}\
         Content-Length: 0\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Assemble the `Set-Cookie` value that grants a session.
#[must_use]
pub fn session_set_cookie(token: &str) -> String {
    let ttl = SESSION_TTL.as_secs();
    format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={ttl}")
}

/// Assemble the `Set-Cookie` value that clears the session.
#[must_use]
pub fn session_clear_cookie() -> String {
    format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_validate_token() {
        let store = SessionStore::new();
        let t = store.create();
        assert_eq!(t.len(), 64);
        assert!(store.validate_and_refresh(&t));
    }

    #[test]
    fn validate_rejects_unknown() {
        let store = SessionStore::new();
        assert!(!store.validate_and_refresh("deadbeef"));
    }

    #[test]
    fn invalidate_removes() {
        let store = SessionStore::new();
        let t = store.create();
        store.invalidate(&t);
        assert!(!store.validate_and_refresh(&t));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn tokens_are_unique() {
        let store = SessionStore::new();
        let a = store.create();
        let b = store.create();
        assert_ne!(a, b);
    }

    #[test]
    fn extract_cookie_picks_ours() {
        assert_eq!(
            extract_session_cookie("foo=bar; __krot_session=abc; baz=qux"),
            Some("abc"),
        );
        assert_eq!(extract_session_cookie("foo=bar"), None);
        assert_eq!(extract_session_cookie("__krot_session=xyz"), Some("xyz"));
    }

    #[test]
    fn form_decode_basics() {
        assert_eq!(form_decode("hello+world"), "hello world");
        assert_eq!(form_decode("a%20b"), "a b");
        assert_eq!(form_decode("%2F"), "/");
        assert_eq!(form_decode("%zz"), "%zz");
    }

    #[test]
    fn parse_form_extracts_fields() {
        let f = parse_login_form("user=alice&pass=s%3Ecret&next=%2Fdash");
        assert_eq!(f.user.as_deref(), Some("alice"));
        assert_eq!(f.pass.as_deref(), Some("s>cret"));
        assert_eq!(f.next.as_deref(), Some("/dash"));
    }

    #[test]
    fn html_escape_covers_specials() {
        assert_eq!(
            html_escape("<a href=\"x\">"),
            "&lt;a href=&quot;x&quot;&gt;"
        );
    }

    #[test]
    fn safe_next_rejects_open_redirect() {
        assert_eq!(safe_next("/dashboard"), "/dashboard");
        assert_eq!(safe_next("//evil.example/x"), "/");
        assert_eq!(safe_next("http://evil"), "/");
        assert_eq!(safe_next("/ok\r\nHeader: bad"), "/");
    }

    #[test]
    fn set_cookie_has_required_attrs() {
        let c = session_set_cookie("tok");
        assert!(c.contains("__krot_session=tok"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Lax"));
        assert!(c.contains("Max-Age="));
        // The `Secure` flag is deliberately absent: this cookie is set
        // on the plain-HTTP tunnel branch and a browser would drop it
        // on the next request, breaking the login loop.
        assert!(!c.contains("Secure"));
    }

    #[test]
    fn login_page_echoes_next_escaped() {
        let html = render_login_page("/foo\"bar", None);
        assert!(html.contains(r#"value="/foo&quot;bar""#));
        assert!(!html.contains("<script"));
    }

    #[test]
    fn redirect_includes_cookie_when_provided() {
        let bytes = http_redirect("/", Some(&session_set_cookie("t")));
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 302 Found\r\n"));
        assert!(s.contains("Location: /\r\n"));
        assert!(s.contains("Set-Cookie: __krot_session=t;"));
    }

    proptest::proptest! {
        #[test]
        fn form_decode_never_panics(s in ".{0,512}") {
            let _ = form_decode(&s);
        }
        #[test]
        fn parse_form_never_panics(s in ".{0,1024}") {
            let _ = parse_login_form(&s);
        }
        #[test]
        fn extract_cookie_never_panics(s in ".{0,512}") {
            let _ = extract_session_cookie(&s);
        }
        #[test]
        fn safe_next_never_panics(s in ".{0,512}") {
            let _ = safe_next(&s);
        }
    }
}
