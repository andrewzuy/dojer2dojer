//! Integration smoke test for the Telegram bot-to-bot signaling layer.
//!
//! Spawns `tests/telegram/mock_bot_api.py` (a tiny mock of the Bot API),
//! points the client at it via `PTUN_TELEGRAM_API_BASE`, and verifies the
//! full exchange: `getMe` → `sendMessage(our addr)` → `getUpdates` poll →
//! peer address parsed, with our own echoed send ignored.
//!
//! Skipped automatically when `python3` is unavailable.

use std::net::SocketAddr;
use std::time::Duration;

use p2p_tunnel_lib::config::TelegramConfig;
use p2p_tunnel_lib::telegram::Telegram;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn telegram_exchange_against_mock_bot_api() {
    // Find python3; skip if absent (CI runners all have it, but be polite).
    let python = match which_python() {
        Some(p) => p,
        None => {
            eprintln!("skip: python3 not found");
            return;
        }
    };

    // Pick a free port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let mut mock = std::process::Command::new(&python)
        .arg("tests/telegram/mock_bot_api.py")
        .arg(port.to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mock bot api");
    let mut mock_out = mock.stdout.take().expect("mock stdout");
    let mock_out_handle = std::thread::spawn(move || {
        let mut buf = String::new();
        use std::io::Read;
        let _ = mock_out.read_to_string(&mut buf);
        buf
    });

    // Give the server a moment to bind.
    wait_for_port(port).await;

    // The env var is process-global; this is the only test that sets it.
    // SAFETY: single-threaded set before any concurrent reader; the lib's
    // `api_base()` only reads it at call time.
    unsafe { std::env::set_var("PTUN_TELEGRAM_API_BASE", format!("http://127.0.0.1:{port}")) };

    let cfg = TelegramConfig {
        token: "test:token".into(),
        peer_bot_id: 9001,
        timeout_secs: 15,
        secret: Some("test-secret".into()),
    };
    let mut tg = Telegram::init(&cfg).await.expect("build client");

    // The exchange (send our addr → poll) is `send_own_addr` +
    // `wait_peer_addr`. The mock keeps a stale PTUN line in the queue;
    // the client must skip it via its `update_id` offset and reject it as
    // stale by `date`, accepting only the peer's *fresh* address, which
    // the mock posts once it sees our send.
    let own: SocketAddr = "198.51.100.9:4433".parse().unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        tg.send_own_addr(own).await?;
        tg.wait_peer_addr(&cfg, || false)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    })
    .await;

    let _ = mock.kill();
    let _ = mock.wait();
    let mock_log = mock_out_handle.join().unwrap_or_default();

    let got = match result {
        Ok(r) => r.unwrap_or_else(|e| {
            eprintln!("--- mock log ---\n{mock_log}\n--- end mock log ---");
            panic!("address exchange failed: {e:#}")
        }),
        Err(_) => {
            eprintln!("--- mock log ---\n{mock_log}\n--- end mock log ---");
            panic!("address exchange hung")
        }
    };
    assert_eq!(got, "203.0.113.7:48000".parse::<SocketAddr>().unwrap());
}

fn which_python() -> Option<String> {
    std::process::Command::new("python3")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()
        .filter(|s| s.success())
        .map(|_| "python3".to_string())
}

async fn wait_for_port(port: u16) {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("mock bot api did not start on port {port}");
}
