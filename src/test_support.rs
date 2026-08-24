// Test-only judge fixtures shared by validator test modules: loopback HTTP
// servers around the anti-replay token check, so preflight and probe tests
// never touch the network. Not compiled outside `cargo test`.
#![allow(dead_code)]

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// Spawns a one-shot judge that echoes the request's `X-Fluxy-Token` back in
/// the marker format the checks require.
pub async fn spawn_echo_judge() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            serve_echo_judge(stream).await;
        }
    });
    judge_url(address)
}

/// Drops the first connection and echoes the token on the second, exercising
/// the preflight retry path.
pub async fn spawn_flaky_echo_judge() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
        if let Ok((stream, _)) = listener.accept().await {
            serve_echo_judge(stream).await;
        }
    });
    judge_url(address)
}

/// Answers 200 without echoing the token, producing a "did not echo" failure.
pub async fn spawn_no_echo_judge() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nno echo",
                )
                .await;
        }
    });
    judge_url(address)
}

/// Serves a single echo-judge response on `stream`.
pub async fn serve_echo_judge(mut stream: TcpStream) {
    let received = read_request_head(&mut stream).await;
    let token = extract_token(&received);
    let body = format!("HTTP_X_FLUXY_TOKEN = {token}");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

async fn read_request_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = [0u8; 4096];
    let mut received = Vec::new();
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        received.extend_from_slice(&buf[..n]);
        if received.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    received
}

fn extract_token(request: &[u8]) -> String {
    for line in request.split(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(line);
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("x-fluxy-token") {
                return value.trim().to_owned();
            }
        }
    }
    String::new()
}

fn judge_url(address: SocketAddr) -> String {
    format!("http://{address}/azenv.php")
}
