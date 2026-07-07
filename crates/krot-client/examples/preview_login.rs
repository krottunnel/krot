//! Dump the styled login page to a file so you can eyeball it in a
//! browser without spinning up a tunnel.
//!
//! Run: `cargo run -p krot-client --example preview_login`
//! → writes /tmp/krot-login.html and /tmp/krot-login-error.html.

use krot_client::login_page::render_login_page;

fn main() {
    let ok = render_login_page("/dashboard", None);
    let err = render_login_page("/dashboard", Some("Invalid username or password."));

    let ok_path = "/tmp/krot-login.html";
    let err_path = "/tmp/krot-login-error.html";
    std::fs::write(ok_path, ok).unwrap();
    std::fs::write(err_path, err).unwrap();

    println!("wrote {ok_path}");
    println!("wrote {err_path}");
    println!("open in browser, e.g.:  xdg-open {ok_path}");
}
