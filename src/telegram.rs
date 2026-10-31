//! Telegram bot-to-bot signaling (optional second negotiation channel).
//!
//! Besides the manual "type the peer's address into the prompt" exchange, two
//! peers can exchange their public addresses automatically through a private
//! Telegram chat between *two bots* — one per machine — using Telegram's
//! [bot-to-bot communication](https://core.telegram.org/api/bots/bot-to-bot).
//!
//! **Transport: the Bot API, long-polling.** Each bot needs only its API token
//! (from @BotFather) and the *user id* of the peer's bot. We `sendMessage`
//! our address to the peer bot and long-poll `getUpdates` until a message
//! carrying the peer's address arrives. No MTProto auth handshake, no
//! `dc_id` ceremony — just plain HTTPS to `api.telegram.org`.
//!
//! **Prerequisites** (per the Telegram docs):
//! - Bot-to-Bot Communication Mode is enabled in @BotFather for **both** bots
//!   (otherwise sending returns `USER_BOT_TO_BOT_DISABLED`);
//! - `privacy` is irrelevant here: private bot-to-bot messages are delivered
//!   to `getUpdates` as ordinary `message` updates.
//!
//! **Protocol.** One line of text, self-describing:
//!
//! ```text
//! PTUN v1 <ip:port>
//! ```
//!
//! **Loop prevention** (the docs warn bots must terminate predictably):
//! - we only ever *send* our own address — never a reaction to an incoming
//!   bot message;
//! - Telegram echoes our own sends back to us, so we ignore `PTUN` messages
//!   whose sender is *our own* bot;
//! - we never auto-reply to incoming bot messages.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::config::TelegramConfig;

/// Marker line format shared with the peer: `PTUN v1 <ip:port>`.
const PAYLOAD_PREFIX: &str = "PTUN v1 ";

/// `getUpdates` long-poll window. Telegram holds the request up to 50 s; 30 s
/// leaves headroom under client-side read timeouts and re-polls quickly.
const GET_UPDATES_TIMEOUT_SECS: u64 = 30;

/// Base URL of the Bot API. Overridable via `PTUN_TELEGRAM_API_BASE` for
/// tests against a mock server (e.g. `http://127.0.0.1:8931`).
///
/// Normalized to have NO trailing slash: the endpoint is built as
/// `{base}/bot{token}/{method}`.
fn api_base() -> String {
    let base = std::env::var("PTUN_TELEGRAM_API_BASE")
        .unwrap_or_else(|_| "https://api.telegram.org".to_string());
    base.trim_end_matches('/').to_string()
}

/// Errors from the Telegram signaling exchange.
#[derive(Debug, thiserror::Error)]
pub enum TelegramError {
    #[error("Telegram API request failed: {0}")]
    Request(String),
    #[error("Telegram API returned ok=false: {0}")]
    Api(String),
    #[error("peer bot {peer_bot_id} did not announce its address within {timeout_secs}s")]
    Timeout { peer_bot_id: i64, timeout_secs: u64 },
}

/// Handle for the bot-to-bot signaling exchange.
pub struct Telegram {
    client: reqwest::Client,
    token: String,
    /// User id of the peer's bot (the `chat_id` we send to).
    peer_bot_id: i64,
}

impl Telegram {
    /// Build a signaling handle. `peer_bot_id` is the numeric id of the other
    /// party's bot (a bot's own id is what `getMe.id` returns).
    pub fn new(cfg: &TelegramConfig) -> anyhow::Result<Self> {
        let token = cfg.token.trim().to_string();
        anyhow::ensure!(
            !token.is_empty(),
            "config: `[telegram].token` must not be empty"
        );
        let client = reqwest::Client::builder()
            // The long poll can be held ~30 s by the server; allow generous
            // read time, no overall request timeout.
            .read_timeout(Duration::from_secs(GET_UPDATES_TIMEOUT_SECS + 30))
            .build()
            .context("building HTTPS client for api.telegram.org")?;
        Ok(Self {
            client,
            token,
            peer_bot_id: cfg.peer_bot_id,
        })
    }

    /// Our own bot's numeric id (from `getMe`), so incoming echoes of our
    /// own sends can be recognized and ignored.
    async fn own_bot_id(&self) -> anyhow::Result<i64> {
        // `getMe`'s result is a bare object, so parse it straight rather than
        // through the typed envelope (avoids a `Default` requirement).
        let base = api_base();
        let url = format!("{base}/bot{}/getMe", self.token);
        let resp = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| TelegramError::Request(format!("getMe: {e}")))?;
        let raw = resp.text().await.unwrap_or_default();
        let id: i64 = serde_json::from_str::<serde_json::Value>(&raw)
            .ok()
            .and_then(|v| v["result"]["id"].as_i64())
            .ok_or_else(|| anyhow::anyhow!("getMe returned no result.id (raw={raw})"))?;
        debug!(bot_id = id, "identified our own bot");
        Ok(id)
    }

    /// Ask the peer bot to send us its address.
    ///
    /// We cannot send the address to the peer directly *and* wait for theirs
    /// in one shot — the peer only learns *our* address after it starts. The
    /// protocol is simply: each side sends its own `PTUN v1 <addr>` line to
    /// the peer bot on startup; each side waits for the peer's line. The
    /// messages cross in flight and both sides proceed.
    pub async fn send_own_addr(&self, own_addr: SocketAddr) -> anyhow::Result<()> {
        let text = format!("{PAYLOAD_PREFIX}{own_addr}");
        let chat_id = self.peer_bot_id.to_string();
        let fields: [(&str, &str); 2] = [("chat_id", &chat_id), ("text", &text)];
        self.call_with::<serde_json::Value>("sendMessage", &fields)
            .await
            .with_context(|| {
                format!(
                    "sending our address to peer bot {} — is Bot-to-Bot Communication \
                     Mode enabled for BOTH bots in @BotFather? Is `[telegram].peer_bot_id` \
                     the peer bot's numeric id?",
                    self.peer_bot_id
                )
            })?;
        info!(peer_bot_id = self.peer_bot_id, %own_addr, "sent our address to peer bot");
        Ok(())
    }

    /// Long-poll `getUpdates` until the peer bot announces its address.
    ///
    /// Resolves with the peer's public address, or [`TelegramError::Timeout`]
    /// after `cfg.timeout_secs`. The caller typically falls back to the
    /// manual address prompt on timeout.
    pub async fn await_peer_addr(&self, cfg: &TelegramConfig) -> Result<SocketAddr, TelegramError> {
        let own_id = self
            .own_bot_id()
            .await
            .map_err(|e| TelegramError::Request(e.to_string()))?;

        let timeout = Duration::from_secs(cfg.timeout_secs);
        let deadline = tokio::time::Instant::now() + timeout;
        info!(
            peer_bot_id = self.peer_bot_id,
            timeout_secs = cfg.timeout_secs,
            "waiting for the peer bot's address (you can press Ctrl-C to cancel)"
        );

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(TelegramError::Timeout {
                    peer_bot_id: self.peer_bot_id,
                    timeout_secs: cfg.timeout_secs,
                });
            }
            // Never long-poll past the overall deadline.
            let poll = remaining.min(Duration::from_secs(GET_UPDATES_TIMEOUT_SECS));

            let res = tokio::time::timeout(
                poll + Duration::from_secs(15), // client-side guard vs. a stuck read
                self.fetch_updates(),
            )
            .await;

            let updates = match res {
                Ok(Ok(updates)) => updates,
                Ok(Err(e)) => {
                    warn!(error = %e, "getUpdates failed; retrying");
                    continue;
                }
                Err(_) => {
                    warn!("getUpdates hung past its guard; retrying");
                    continue;
                }
            };

            for msg in updates {
                if let Some(addr) = self.classify(&msg, own_id) {
                    info!(%addr, "received the peer's address via Telegram");
                    return Ok(addr);
                }
            }
        }
    }

    /// If this message is the peer bot's `PTUN v1 <addr>` line, return the
    /// address. Own-bot echoes and non-payload messages are ignored (loop
    /// prevention — we never reply to bot messages).
    fn classify(&self, msg: &UpdateMessage, own_id: i64) -> Option<SocketAddr> {
        let text = msg.message.text.as_deref()?;
        let body = text.trim().strip_prefix(PAYLOAD_PREFIX)?;
        // Only trust the payload from the *peer* bot, never our own echo.
        let from = msg.message.from.as_ref()?;
        if from.id == own_id || !from.is_bot {
            debug!("ignoring non-peer message in the signaling chat");
            return None;
        }
        if from.id != self.peer_bot_id {
            warn!(
                sender = from.id,
                "ignoring PTUN message from unexpected sender"
            );
            return None;
        }
        match crate::cli::parse_peer_addr(body) {
            Ok(addr) => Some(addr),
            Err(e) => {
                warn!(text, error = %e, "ignoring malformed PTUN payload");
                None
            }
        }
    }

    async fn fetch_updates(&self) -> Result<Vec<UpdateMessage>, TelegramError> {
        let timeout = GET_UPDATES_TIMEOUT_SECS.to_string();
        // `result` of `getUpdates` is the array itself, so `T` is the vec.
        self.call_with::<Vec<UpdateMessage>>("getUpdates", &[("timeout", timeout.as_str())])
            .await
    }

    async fn call_with<T>(&self, method: &str, fields: &[(&str, &str)]) -> Result<T, TelegramError>
    where
        T: for<'de> Deserialize<'de> + Default,
    {
        // Build an absolute URL so reqwest targets the right host (its
        // relative-path handling would otherwise drop the scheme).
        let base = api_base();
        let url = format!("{base}/bot{}/{method}", self.token);
        let mut form = Vec::with_capacity(fields.len());
        for (k, v) in fields {
            form.push((k.to_string(), v.to_string()));
        }
        let resp = self
            .client
            .post(&url)
            .form(&form)
            .send()
            .await
            .map_err(|e| TelegramError::Request(format!("{method}: {e}")))?;
        let status = resp.status();
        let raw = resp.text().await.unwrap_or_default();
        // Parse the envelope as a plain `Value` and extract fields manually.
        // This sidesteps a serde-derive codegen bug in this toolchain where a
        // generic `ApiEnvelope<T>` struct's derived `Deserialize` mis-parses
        // the `ok`/`result` fields (reporting "expected a boolean" at the
        // position of `result`). Manual extraction is unambiguous.
        let value: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
            TelegramError::Request(format!("{method}: bad JSON: {e} (status {status})"))
        })?;
        let ok = value.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        if !ok {
            let reason = value
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("(no description)")
                .to_string();
            return Err(TelegramError::Api(format!("{method}: {reason}")));
        }
        let result = value
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        T::deserialize(result)
            .map_err(|e| TelegramError::Request(format!("{method}: bad result: {e}")))
    }
}

/// One entry of `getUpdates` that carries a private message. We ignore every
/// field we don't need; unknown top-level update types are dropped by serde.
#[derive(Debug, Deserialize)]
struct UpdateMessage {
    #[serde(default)]
    message: Message,
}

#[derive(Debug, Default, Deserialize)]
struct Message {
    #[serde(default)]
    from: Option<ChatUser>,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatUser {
    id: i64,
    #[serde(default)]
    is_bot: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic `getUpdates` entry for `classify` tests.
    fn msg(from_id: i64, is_bot: bool, text: &str) -> UpdateMessage {
        UpdateMessage {
            message: Message {
                from: Some(ChatUser {
                    id: from_id,
                    is_bot,
                }),
                text: text.to_string().into(),
            },
        }
    }

    /// A `Telegram` with a fixed peer-bot id, for `classify` tests. No HTTP
    /// calls happen in `classify`, so the token is irrelevant.
    fn tg_for_test(peer_bot_id: i64) -> Telegram {
        Telegram {
            client: reqwest::Client::new(),
            token: "test-token".into(),
            peer_bot_id,
        }
    }

    #[test]
    fn payload_is_well_formed() {
        let own = "1.2.3.4:1234".parse::<SocketAddr>().unwrap();
        let line = format!("{PAYLOAD_PREFIX}{own}");
        assert_eq!(line, "PTUN v1 1.2.3.4:1234");
    }

    /// `classify` lives on `Telegram`, which needs a token to construct. Test
    /// the parse path through `cli::parse_peer_addr` instead, mirroring the
    /// strip-prefix logic.
    #[test]
    fn payload_round_trips_through_parser() {
        let own = "[2001:db8::7]:4433".parse::<SocketAddr>().unwrap();
        let line = format!("{PAYLOAD_PREFIX}{own}");
        let body = line.strip_prefix(PAYLOAD_PREFIX).unwrap();
        assert_eq!(crate::cli::parse_peer_addr(body).unwrap(), own);
    }

    #[test]
    fn rejects_garbage_payload() {
        assert!(crate::cli::parse_peer_addr("nope").is_err());
        assert!(crate::cli::parse_peer_addr("").is_err());
    }

    /// The full envelope (as `call_with` parses it) must deserialize a
    /// `getUpdates` array. Guards against the `Default`-bound regression.
    /// The `getUpdates` result array must deserialize into `UpdateMessage`s.
    #[test]
    fn parses_get_updates_result() {
        let raw = r#"[{"update_id": 8, "message": {"message_id": 3, "from": {"id": 1001, "is_bot": true, "username": "own_bot"}, "chat": {"id": 9001, "type": "private"}, "text": "PTUN v1 1.2.3.4:5"}}, {"update_id": 9, "message": {"from": {"id": 9001, "is_bot": true}, "text": "PTUN v1 2.3.4.5:6"}}]"#;
        let updates: Vec<UpdateMessage> =
            serde_json::from_str(raw).expect("getUpdates result deserializes");
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].message.from.as_ref().map(|f| f.id), Some(1001));
    }

    #[test]
    fn classify_accepts_peer_payload() {
        let tg = tg_for_test(9001);
        let own_id = 1001;
        let m = msg(9001, true, "PTUN v1 10.1.2.3:4321");
        assert_eq!(
            tg.classify(&m, own_id),
            Some("10.1.2.3:4321".parse().unwrap())
        );
    }

    #[test]
    fn classify_ignores_own_echo() {
        let tg = tg_for_test(9001);
        let own_id = 1001;
        // Telegram echoes our own sends back; sender == own_id → ignore.
        let m = msg(1001, true, "PTUN v1 10.1.2.3:4321");
        assert_eq!(tg.classify(&m, own_id), None);
    }

    #[test]
    fn classify_ignores_unexpected_sender() {
        let tg = tg_for_test(9001);
        let own_id = 1001;
        // A third bot in the chat (e.g. the user's other bot) must not
        // be mistaken for the peer.
        let m = msg(7777, true, "PTUN v1 10.1.2.3:4321");
        assert_eq!(tg.classify(&m, own_id), None);
    }

    #[test]
    fn classify_ignores_non_bot_and_garbage() {
        let tg = tg_for_test(9001);
        let own_id = 1001;
        assert_eq!(
            tg.classify(&msg(9001, false, "PTUN v1 10.1.2.3:4321"), own_id),
            None
        );
        assert_eq!(tg.classify(&msg(9001, true, "hello there"), own_id), None);
        assert_eq!(
            tg.classify(&msg(9001, true, "PTUN v1 not-an-addr"), own_id),
            None
        );
    }
}
