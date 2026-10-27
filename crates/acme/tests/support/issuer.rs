use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

pub(super) struct Mock {
    pub task: tokio::task::JoinHandle<()>,
    pub entered: oneshot::Receiver<()>,
}

pub(super) async fn start(
    token: &str,
    hold_challenge: bool,
) -> (reqwest::Client, Mock) {
    let listener =
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    // A local explicit HTTP proxy preserves the public account URL contract
    // without requiring port 80 or involving DNS or a real certificate issuer.
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{address}")).unwrap())
        .build()
        .unwrap();
    let token = token.to_owned();
    let (entered, receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut entered = Some(entered);
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut wire = Vec::new();
            let mut buffer = [0; 1024];
            let head = loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0, "unexpected EOF before mock request head");
                wire.extend_from_slice(&buffer[..read]);
                if let Some(end) =
                    wire.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                {
                    break end + 4;
                }
            };
            let headers = String::from_utf8(wire[..head].to_vec()).unwrap();
            let length: usize = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map_or(0, |(_, value)| value.trim().parse().unwrap());
            while wire.len() < head + length {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0, "unexpected EOF before mock request body");
                wire.extend_from_slice(&buffer[..read]);
            }
            let target = headers
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let path = url::Url::parse(target).unwrap();
            let (body, extra) = match path.path() {
                "/acme/new-nonce" => (String::new(), "Replay-Nonce: test-nonce\r\n"),
                "/acme/new-order" => (
                    r#"{"authorizations":["http://issuer.test/auth"],"finalize":"http://issuer.test/finalize"}"#.into(),
                    "Location: http://issuer.test/order\r\n",
                ),
                "/auth" => (serde_json::json!({"status":"pending", "challenges":[{"type":"http-01", "token":token, "url":"http://issuer.test/challenge"}]}).to_string(), ""),
                "/challenge" => {
                    if let Some(entered) = entered.take() { let _ = entered.send(()); }
                    if hold_challenge { std::future::pending::<()>().await; }
                    (r#"{"status":"invalid"}"#.into(), "")
                }
                other => panic!("unexpected mock path {other}"),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n{extra}\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (client, Mock { task, entered: receiver })
}
