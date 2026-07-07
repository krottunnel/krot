//! KROT client CLI.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};

use krot_client::{
    api_key_from_str, config::default_dir, enroll, publish_http, publish_http_authed, publish_tcp,
    read_env, read_file, session_from_userpass, spawn_inspector_ui, AuthConfig, AuthConfigError,
    AuthenticatedSession, ClientConfig, ClientError, EnrollOptions, Inspector, SessionStore,
    DEFAULT_REALM,
};

const DEFAULT_QUIC_PORT: u16 = krot_proto::consts::DEFAULT_UDP_PORT;
const DEFAULT_INSPECTOR_BIND: &str = "127.0.0.1:4040";

#[derive(Debug, Parser)]
#[command(name = "krot", version, about)]
struct Cli {
    /// Override the default `~/.krot` data directory.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Enroll this machine with a KROT server (§14).
    Init {
        /// Server host or IP. Optionally `host:port`.
        #[arg(long)]
        server: String,
        /// One-shot admin token printed by the server on first startup.
        #[arg(long)]
        admin_token: String,
        /// Pinned server SPKI fingerprint (`sha256:HEX`). If omitted the
        /// client uses TOFU on this connection.
        #[arg(long)]
        fingerprint: Option<String>,
        /// TLS SNI to present (defaults to the server host).
        #[arg(long)]
        sni: Option<String>,
        /// Free-form label written into `authorized_keys` alongside the pubkey.
        #[arg(long)]
        label: Option<String>,
    },

    /// Publish a local TCP service through the enrolled KROT server.
    Tcp {
        /// Local port on `127.0.0.1` to forward.
        port: u16,
    },

    /// Publish a local HTTP service through the enrolled KROT server.
    ///
    /// Requires the server to be running in DomainMode. The tunnel is
    /// exposed at `https://<name>.<apex>`; the server does not terminate
    /// TLS on the subdomain, so the local target should speak plain HTTP.
    Http {
        /// Local port on `127.0.0.1` to forward.
        port: u16,
        /// Requested subdomain label. Defaults to a random-ish name.
        #[arg(long)]
        name: Option<String>,
        /// Enable the local inspector on 127.0.0.1:4040.
        #[arg(long)]
        inspect: bool,
        /// Bind address for the inspector UI when `--inspect` is set.
        #[arg(long, default_value = DEFAULT_INSPECTOR_BIND)]
        inspect_bind: SocketAddr,
        /// Require a login on the tunnel. Value is `user:pass`. Visitors
        /// see a styled sign-in page and receive an `HttpOnly;
        /// SameSite=Lax` session cookie on success (8-hour rolling TTL).
        /// Shows up in `ps` — use `--auth-env` / `--auth-file` for
        /// non-dev use. Mutually exclusive with `--auth-env` /
        /// `--auth-file` / any `--api-key*`.
        ///
        /// Only protects the plain-HTTP branch of the tunnel; HTTPS
        /// (SNI-passthrough) traffic is opaque to the client and
        /// bypasses the check. The local target must handle its own
        /// auth on that path.
        #[arg(
            long,
            conflicts_with_all = ["auth_env", "auth_file", "api_key", "api_key_env", "api_key_file"],
        )]
        auth: Option<String>,
        /// Read `user:pass` from the named environment variable.
        #[arg(long, conflicts_with_all = ["auth_file", "api_key", "api_key_env", "api_key_file"])]
        auth_env: Option<String>,
        /// Read `user:pass` from the named file (single line).
        #[arg(long, conflicts_with_all = ["api_key", "api_key_env", "api_key_file"])]
        auth_file: Option<std::path::PathBuf>,
        /// Require `X-API-Key` or `Authorization: Bearer <key>`.
        #[arg(long, conflicts_with_all = ["api_key_env", "api_key_file"])]
        api_key: Option<String>,
        /// Read the API key from the named environment variable.
        #[arg(long, conflicts_with = "api_key_file")]
        api_key_env: Option<String>,
        /// Read the API key from the named file (single line).
        #[arg(long)]
        api_key_file: Option<std::path::PathBuf>,
        /// Realm string carried in the auth config (used by the API-key
        /// branch for diagnostics). Defaults to `KROT Protected Tunnel`.
        #[arg(long)]
        auth_realm: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), ClientError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let dir = cli
        .data_dir
        .or_else(default_dir)
        .ok_or_else(|| ClientError::Config("cannot determine data dir".into()))?;

    match cli.cmd {
        Command::Init {
            server,
            admin_token,
            fingerprint,
            sni,
            label,
        } => run_init(&dir, server, admin_token, fingerprint, sni, label).await,
        Command::Tcp { port } => run_tcp(&dir, port).await,
        Command::Http {
            port,
            name,
            inspect,
            inspect_bind,
            auth,
            auth_env,
            auth_file,
            api_key,
            api_key_env,
            api_key_file,
            auth_realm,
        } => {
            let auth_cfg = build_auth_config(
                auth,
                auth_env,
                auth_file,
                api_key,
                api_key_env,
                api_key_file,
                auth_realm,
            )?;
            run_http(&dir, port, name, inspect, inspect_bind, auth_cfg).await
        }
    }
}

/// Resolve the CLI's auth flags into an optional [`AuthConfig`].
/// Clap already ensures no more than one source is set across the
/// Basic + API-key groups; this function just picks whichever is
/// present.
fn build_auth_config(
    auth: Option<String>,
    auth_env: Option<String>,
    auth_file: Option<PathBuf>,
    api_key: Option<String>,
    api_key_env: Option<String>,
    api_key_file: Option<PathBuf>,
    auth_realm: Option<String>,
) -> Result<Option<AuthConfig>, ClientError> {
    let realm = auth_realm.unwrap_or_else(|| DEFAULT_REALM.to_string());
    let session_store = SessionStore::new();
    let policy = if let Some(value) = auth {
        Some(session_from_userpass(&value, Arc::clone(&session_store)).map_err(auth_err)?)
    } else if let Some(var) = auth_env {
        let v = read_env(&var).map_err(auth_err)?;
        Some(session_from_userpass(&v, Arc::clone(&session_store)).map_err(auth_err)?)
    } else if let Some(path) = auth_file {
        let v = read_file(&path).map_err(auth_err)?;
        Some(session_from_userpass(&v, Arc::clone(&session_store)).map_err(auth_err)?)
    } else if let Some(v) = api_key {
        Some(api_key_from_str(&v))
    } else if let Some(var) = api_key_env {
        let v = read_env(&var).map_err(auth_err)?;
        Some(api_key_from_str(&v))
    } else if let Some(path) = api_key_file {
        let v = read_file(&path).map_err(auth_err)?;
        Some(api_key_from_str(&v))
    } else {
        None
    };
    Ok(policy.map(|p| AuthConfig { policy: p, realm }))
}

fn auth_err(e: AuthConfigError) -> ClientError {
    ClientError::Config(format!("auth flag: {e}"))
}

async fn run_init(
    dir: &std::path::Path,
    server: String,
    admin_token: String,
    fingerprint: Option<String>,
    sni: Option<String>,
    label: Option<String>,
) -> Result<(), ClientError> {
    let (host, port) = split_host_port(&server);
    let cfg = enroll(
        EnrollOptions {
            server_host: host,
            server_quic_port: port,
            sni,
            admin_token,
            label_hint: label,
            pinned_fingerprint: fingerprint,
        },
        dir,
    )
    .await?;
    println!("enrolled at {}:{}", cfg.server.host, cfg.server.quic_port);
    if let Some(fp) = &cfg.server.fingerprint {
        println!("pinned {fp}");
    }
    Ok(())
}

async fn run_tcp(dir: &std::path::Path, local_port: u16) -> Result<(), ClientError> {
    let cfg = ClientConfig::load_from(dir)?;
    let session = AuthenticatedSession::connect(&cfg.server, &cfg.identity).await?;
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_port);
    let (tunnel, handle, shutdown) = publish_tcp(session, "tcp", local).await?;
    println!("{}", tunnel.public_url);
    await_shutdown(handle, shutdown).await;
    Ok(())
}

async fn run_http(
    dir: &std::path::Path,
    local_port: u16,
    label: Option<String>,
    inspect: bool,
    inspect_bind: SocketAddr,
    auth: Option<AuthConfig>,
) -> Result<(), ClientError> {
    let cfg = ClientConfig::load_from(dir)?;
    let session = AuthenticatedSession::connect(&cfg.server, &cfg.identity).await?;
    let label = label.unwrap_or_else(default_label);
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_port);

    let inspector = if inspect {
        let insp = Arc::new(Inspector::new());
        let _ui = spawn_inspector_ui(Arc::clone(&insp), inspect_bind);
        println!("inspector: http://{inspect_bind}");
        Some(insp)
    } else {
        None
    };

    let (tunnel, handle, shutdown) = if let Some(auth) = auth {
        // Warn the operator that Basic-auth only protects the plain-HTTP
        // branch of the tunnel — HTTPS-passthrough traffic can't be
        // inspected without terminating TLS.
        eprintln!(
            "note: auth check applies to plain-HTTP requests only; \
             HTTPS traffic on this tunnel bypasses the client-side check."
        );
        publish_http_authed(session, &label, local, inspector, auth).await?
    } else {
        publish_http(session, &label, local, inspector).await?
    };
    println!("{}", tunnel.public_url);
    await_shutdown(handle, shutdown).await;
    Ok(())
}

async fn await_shutdown(
    handle: tokio::task::JoinHandle<Result<(), ClientError>>,
    shutdown: tokio::sync::mpsc::Sender<()>,
) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            let _ = shutdown.send(()).await;
        }
        _ = handle => {}
    }
}

fn split_host_port(server: &str) -> (String, u16) {
    if let Some((host, port)) = server.rsplit_once(':') {
        if let Ok(p) = port.parse::<u16>() {
            return (host.to_string(), p);
        }
    }
    (server.to_string(), DEFAULT_QUIC_PORT)
}

fn default_label() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n: u32 = rng.gen_range(0..u32::MAX);
    format!("krot-{n:08x}")
}
