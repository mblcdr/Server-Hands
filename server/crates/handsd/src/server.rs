//! TLS 1.3 + HTTP/1.1 front end, and the root-only control socket used by handsctl.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hands_proto::codec::{b64e, hex_encode, uuid_format, uuid_parse};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::daemon::{Ctx, PAIR_TOKEN_TTL};
use crate::store::Tls;

const MAX_BODY: usize = 64 * 1024;
const MAX_CONNS: usize = 24;

pub fn tls_acceptor(tls: &Tls) -> std::io::Result<TlsAcceptor> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls.key_der.to_vec()));
    let cfg = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(tls.cert_der.clone())], key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Listener passed by systemd (`handsd.socket`), if any.
pub fn inherited_listener() -> Option<std::net::TcpListener> {
    use std::os::fd::FromRawFd;
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    let fds: i32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if pid != std::process::id() || fds < 1 {
        return None;
    }
    let l = unsafe { std::net::TcpListener::from_raw_fd(3) };
    l.set_nonblocking(true).ok()?;
    Some(l)
}

pub async fn serve_http(ctx: Arc<Ctx>, listener: TcpListener, acceptor: TlsAcceptor) {
    let gate = Arc::new(Semaphore::new(MAX_CONNS));
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let Ok(permit) = gate.clone().try_acquire_owned() else {
            continue;
        };
        let (ctx, acceptor) = (ctx.clone(), acceptor.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tcp.set_nodelay(true);
            let Ok(Ok(tls)) =
                tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await
            else {
                return;
            };
            let svc = service_fn(move |req| handle(ctx.clone(), req));
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .keep_alive(false)
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}

async fn handle(
    ctx: Arc<Ctx>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let (status, text) = match Limited::new(body, MAX_BODY).collect().await {
        Ok(b) => {
            ctx.route(parts.method.as_str(), parts.uri.path(), &b.to_bytes())
                .await
        }
        Err(_) => (400, r#"{"error":"bad_request"}"#.to_string()),
    };
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(text)))
        .unwrap())
}

// ---- control socket ----------------------------------------------------------------------------

pub fn bind_control(ctx: &Ctx) -> std::io::Result<UnixListener> {
    let path = ctx.cfg.run_dir.join("control.sock");
    let _ = std::fs::remove_file(&path);
    let l = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(l)
}

pub async fn serve_control(ctx: Arc<Ctx>, listener: UnixListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        if !peer_is_root(&stream) {
            continue;
        }
        let ctx = ctx.clone();
        tokio::spawn(async move { control_conn(ctx, stream).await });
    }
}

fn peer_is_root(s: &UnixStream) -> bool {
    // The daemon runs as root, so this means root; the socket is also 0600 under a 0755 run dir.
    s.peer_cred()
        .map(|c| c.uid() == unsafe { libc::geteuid() })
        .unwrap_or(false)
}

async fn control_conn(ctx: Arc<Ctx>, stream: UnixStream) {
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    let mut presented = None;
    let mut decide = None;
    while let Ok(Some(line)) = lines.next_line().await {
        let Ok(cmd) = serde_json::from_str::<Value>(&line) else {
            break;
        };
        let reply = match cmd["cmd"].as_str().unwrap_or("") {
            "status" => {
                json!({ "ok": true, "drives": drive_status(&ctx), "pending": ctx.pending_count(), "devices": ctx.devices().len() })
            }
            "devices" => json!({ "ok": true, "devices": ctx.devices() }),
            "revoke" => match ctx.revoke(cmd["id"].as_str().unwrap_or("")) {
                Ok(d) => json!({ "ok": true, "revoked": d.id, "name": d.name }),
                Err(e) => json!({ "ok": false, "error": e }),
            },
            "reset_approval_key" => {
                match ctx.reset_approval_key(cmd["id"].as_str().unwrap_or("")) {
                    Ok(d) => json!({ "ok": true, "device": d.id, "name": d.name }),
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            }
            "pair_start" => {
                let (token, rx) = ctx.pair_start();
                presented = Some(rx);
                let port = ctx
                    .cfg
                    .listen
                    .rsplit(':')
                    .next()
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(7787);
                json!({
                    "ok": true,
                    "token": b64e(&token),
                    "spki": b64e(&ctx.spki_sha256),
                    "sid": b64e(&ctx.server_pub),
                    "port": port,
                    "host": ctx.cfg.advertise_host,
                    "expires_in": PAIR_TOKEN_TTL.as_secs(),
                })
            }
            "pair_wait" => match presented.take() {
                None => json!({ "ok": false, "error": "no pairing in progress" }),
                Some(rx) => match tokio::time::timeout(PAIR_TOKEN_TTL, rx).await {
                    Ok(Ok(p)) => {
                        decide = Some(p.decide);
                        json!({ "ok": true, "sas": p.sas, "name": p.name })
                    }
                    _ => {
                        ctx.pair_cancel();
                        json!({ "ok": false, "error": "pairing expired" })
                    }
                },
            },
            "pair_confirm" => match decide.take() {
                None => json!({ "ok": false, "error": "nothing to confirm" }),
                Some(tx) => {
                    let _ = tx.send(cmd["accept"].as_bool().unwrap_or(false));
                    json!({ "ok": true })
                }
            },
            _ => json!({ "ok": false, "error": "unknown command" }),
        };
        let mut out = reply.to_string();
        out.push('\n');
        if wr.write_all(out.as_bytes()).await.is_err() {
            break;
        }
    }
    ctx.pair_cancel();
}

fn drive_status(ctx: &Ctx) -> Vec<Value> {
    let locked = ctx.host.locked_drives();
    ctx.cfg
        .drives
        .iter()
        .map(|d| {
            let state = match uuid_parse(&d.luks_uuid) {
                Ok(u) if locked.iter().any(|l| l.luks_uuid == uuid_format(&u)) => "locked",
                Ok(u) if crate::luks::kernel_name(&u).is_none() => "absent",
                _ => "open_or_crypttab",
            };
            json!({ "luks_uuid": d.luks_uuid, "label": d.label, "state": state })
        })
        .collect()
}

pub fn fingerprint(b: &[u8]) -> String {
    hex_encode(&hands_proto::codec::sha256(b))
}
