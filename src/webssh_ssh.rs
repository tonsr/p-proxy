//! WebSSH: run SSH client handshake and shell on an existing TCP stream, bridge to channels.

use anyhow::{Context, Result};
use ssh2::Session;
use std::io::{Read, Write};
use std::net::TcpStream as StdTcpStream;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::mpsc as tokio_mpsc;

/// True if the read error is "would block" / EAGAIN (retry instead of closing).
fn is_would_block(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    if let Some(code) = e.raw_os_error() {
        // EAGAIN (11), EWOULDBLOCK (11 on Linux, 35 on some), WSAEWOULDBLOCK (10035)
        if code == 11 || code == 35 || code == 10035 {
            return true;
        }
    }
    // libssh2 returns [-37] LIBSSH2_ERROR_EAGAIN, ssh2-rs may expose as message "would block"
    let msg = e.to_string();
    if msg.to_lowercase().contains("would block") || msg.contains("-37") {
        return true;
    }
    false
}

/// Run SSH handshake, authenticate, open shell; optionally send FILE_LIST via tx_control; then bridge.
pub async fn run_ssh_shell(
    stream: TokioTcpStream,
    username: &str,
    password: &str,
    tx_control: Option<tokio_mpsc::Sender<String>>,
) -> Result<(
    mpsc::Sender<Vec<u8>>,
    tokio_mpsc::Receiver<Vec<u8>>,
)> {
    let std_stream = stream
        .into_std()
        .context("TcpStream::into_std")?;
    let (tx_ws_to_ssh, rx_ws_to_ssh) = mpsc::channel();
    let (tx_ssh_to_ws, rx_ssh_to_ws) = tokio_mpsc::channel(64);
    let (tx_handshake, rx_handshake) = mpsc::channel();

    let username = username.to_string();
    let password = password.to_string();
    let tx_ssh_to_ws_clone = tx_ssh_to_ws.clone();

    tokio::task::spawn_blocking(move || {
        let r = run_ssh_shell_blocking(
            std_stream,
            &username,
            &password,
            rx_ws_to_ssh,
            tx_ssh_to_ws_clone,
            tx_handshake,
            tx_control,
        );
        if let Err(e) = r {
            tracing::info!("webssh ssh session error: {e:#}");
        }
    });

    let handshake_result = tokio::task::spawn_blocking(move || rx_handshake.recv())
        .await
        .context("spawn_blocking join")?
        .context("handshake result channel closed")?;
    handshake_result?;
    Ok((tx_ws_to_ssh, rx_ssh_to_ws))
}

fn run_ssh_shell_blocking(
    std_stream: StdTcpStream,
    username: &str,
    password: &str,
    rx_ws_to_ssh: mpsc::Receiver<Vec<u8>>,
    tx_ssh_to_ws: tokio_mpsc::Sender<Vec<u8>>,
    tx_handshake: mpsc::Sender<Result<(), anyhow::Error>>,
    tx_control: Option<tokio_mpsc::Sender<String>>,
) -> Result<()> {
    std_stream.set_nonblocking(false)?;
    std_stream.set_nodelay(true)?; // send keystrokes immediately, no Nagle
    let mut sess = Session::new().context("Session::new")?;
    if let Err(e) = sess.handshake(&std_stream) {
        let _ = tx_handshake.send(Err(anyhow::anyhow!("SSH handshake: {}", e)));
        return Err(e.into());
    }
    if let Err(e) = sess.userauth_password(username, password) {
        let _ = tx_handshake.send(Err(anyhow::anyhow!("SSH password auth: {}", e)));
        return Err(e.into());
    }
    if !sess.authenticated() {
        let err = anyhow::anyhow!("SSH authentication failed (wrong password?)");
        let _ = tx_handshake.send(Err(anyhow::anyhow!("{}", err)));
        return Err(err);
    }

    let mut channel = sess.channel_session().context("channel_session")?;
    if let Err(e) = channel.request_pty("xterm", None, Some((80, 24, 0, 0))) {
        let _ = tx_handshake.send(Err(anyhow::anyhow!("request_pty: {}", e)));
        return Err(e.into());
    }
    if let Err(e) = channel.shell() {
        let _ = tx_handshake.send(Err(anyhow::anyhow!("request shell: {}", e)));
        return Err(e.into());
    }
    let _ = tx_handshake.send(Ok(()));

    // SFTP: list /root and send FILE_LIST JSON so frontend can show file tree (then drop tx_control).
    if let Some(tx) = tx_control {
        sess.set_blocking(true);
        if let Ok(sftp) = sess.sftp() {
            let root = Path::new("/root");
            if let Ok(entries) = sftp.readdir(root) {
                let list: Vec<serde_json::Value> = entries
                    .into_iter()
                    .map(|(path, stat)| {
                        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                        let path_str = path.to_string_lossy().to_string();
                        serde_json::json!({ "path": path_str, "name": name, "dir": stat.is_dir() })
                    })
                    .collect();
                if let Ok(json) = serde_json::to_string(&list) {
                    let _ = tx.blocking_send(json);
                }
            }
        }
        sess.set_blocking(false);
    }

    let mut buf = [0u8; 16 * 1024];
    // Very short timeout/sleep: read SSH output as fast as possible so buffers don't fill and
    // connection doesn't get dropped by proxy/server; keystrokes feel instant.
    let timeout = Duration::from_millis(5);
    let poll_sleep = Duration::from_millis(0);
    loop {
        // SSH -> WS: drain channel quickly to avoid backpressure / proxy timeout
        match channel.read(&mut buf) {
            Ok(n) if n > 0 => {
                if tx_ssh_to_ws.blocking_send(buf[..n].to_vec()).is_err() {
                    break; // client disconnected
                }
            }
            Ok(_) => {}
            Err(e) if is_would_block(&e) => {}
            Err(e) => {
                tracing::info!("ssh channel read error (connection closed?): {e}");
                break;
            }
        }
        // WS -> SSH
        match rx_ws_to_ssh.recv_timeout(timeout) {
            Ok(data) => {
                if channel.write_all(&data).is_err() {
                    break;
                }
                channel.flush().ok();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if poll_sleep.as_millis() > 0 {
            std::thread::sleep(poll_sleep);
        }
    }
    channel.close().ok();
    channel.wait_close().ok();
    Ok(())
}
