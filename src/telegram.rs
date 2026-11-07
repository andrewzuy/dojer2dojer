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
//! **Protocol.** Two kinds of one-line text, both self-describing:
//!
//! ```text
//! PTUN READY <secret>     ; "I'm up and listening" (sent at startup, before STUN)
//! PTUN v1 <ip:port>       ; the public address (sent only after the READY handshake)
//! ```
//!
//! **Readiness handshake (the `PTUN READY` line).** Each side announces
//! `PTUN READY <secret>` to the peer bot at startup — *before* it discovers
//! its public address — and waits for the peer bot's `PTUN READY` line. Only
//! once both sides know the other is up do they call STUN and announce their
//! `PTUN v1` address. Without this gate the messages cross in flight and a
//! side can end up punching toward the peer's *previous* run's address.
//! The `<secret>` (a shared `[telegram].secret` value) proves the READY line
//! is the peer's, not a stale or foreign message; the `date` staleness check
//! guards against READY lines from earlier runs.
//!
//! **Stale-announcement handling.** Each side announces exactly once at the
//! start of its exchange, so the *newest* `PTUN` line in the bot's update
//! queue is the peer's most recent announcement — even if it was sent by an
//! earlier run of the peer (a few minutes ago, while we were still starting
//! up). We therefore never clear the queue; we track the highest `update_id`
//! consumed and accept any peer line younger than [`MAX_ADDR_AGE_SECS`]. A
//! line older than that (an announcement from before the NAT mapping we are
//! about to punch through) is ignored, so a stale address can't silently
//! break hole-punching.
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

/// Marker line for the "I'm up, come find me" readiness handshake that must
/// complete before either side announces an address (see [`handshake`]).
const READY_PREFIX: &str = "PTUN READY ";

/// How long `handshake` waits for the peer bot's `PTUN READY` line before
/// giving up (falling back to the manual address prompt).
const READY_TIMEOUT_SECS: u64 = 60;

/// A `PTUN READY` line older than this is ignored: it belongs to a previous
/// run of the peer, and acting on it would let us STUN + punch toward a peer
/// that is not actually listening. Ten minutes comfortably covers two
/// machines being started a few minutes apart.
const MAX_READY_AGE_SECS: i64 = 600;

/// `getUpdates` long-poll window. Telegram holds the request up to 50 s; a
/// shorter window means the exchange loop wakes more often, so user aborts
/// (Ctrl-C / `q` in the TUI) take effect within seconds instead of up to
/// 30.
const GET_UPDATES_TIMEOUT_SECS: u64 = 10;

/// A `PTUN` announcement older than this is ignored as stale: the NAT
/// mapping it refers to is almost certainly gone, so acting on it would only
/// burn the punch timeout. (Ten minutes comfortably covers two machines being
/// started a few minutes apart while staying well under typical NAT
/// idle-timeout × keep-alive windows.)
const MAX_ADDR_AGE_SECS: i64 = 600;

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
    #[error("aborted by the user")]
    Aborted,
}

/// Handle for the bot-to-bot signaling exchange.
///
/// Stateful: `own_bot_id` is resolved once at construction and `seen` tracks
/// the highest `update_id` consumed, so re-polling never replays messages.
pub struct Telegram {
    client: reqwest::Client,
    token: String,
    /// User id of the peer's bot (the `chat_id` we send to).
    peer_bot_id: i64,
    /// Our own bot's numeric id (from `getMe`), so incoming echoes of our own
    /// sends can be recognized and ignored.
    own_bot_id: Option<i64>,
    /// Next `getUpdates` offset: one past the highest `update_id` seen.
    seen: i64,
}

impl Telegram {
    /// Build a signaling handle and identify our own bot (`getMe`).
    /// `cfg.peer_bot_id` is the numeric id of the other party's bot (a bot's
    /// own id is what `getMe.id` returns).
    pub async fn init(cfg: &TelegramConfig) -> anyhow::Result<Self> {
        let token = cfg.token.trim().to_string();
        anyhow::ensure!(
            !token.is_empty(),
            "config: `[telegram].token` must not be empty"
        );
        let client = reqwest::Client::builder()
            // The long poll can be held ~10 s by the server; allow generous
            // read time, no overall request timeout.
            .read_timeout(Duration::from_secs(GET_UPDATES_TIMEOUT_SECS + 30))
            .build()
            .context("building HTTPS client for api.telegram.org")?;
        let tg = Self {
            client,
            token,
            peer_bot_id: cfg.peer_bot_id,
            own_bot_id: None,
            seen: 0,
        };
        let own_bot_id = tg.own_bot_id().await?;
        Ok(Self {
            own_bot_id: Some(own_bot_id),
            ..tg
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

    /// Announce our address to the peer bot.
    ///
    /// Send this *after* [`handshake`](Self::handshake) succeeded — i.e. once
    /// we know the peer is up. The protocol is: each side sends its own
    /// `PTUN v1 <addr>` line to the peer bot; each side waits for the peer's
    /// line via [`wait_peer_addr`](Self::wait_peer_addr).
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

    /// Wait for the peer's address: long-poll `getUpdates` and accept the
    /// peer bot's `PTUN` line, provided it is fresh (younger than
    /// [`MAX_ADDR_AGE_SECS`]) and not an echo of our own send.
    ///
    /// Call this *after* [`handshake`](Self::handshake): the READY exchange
    /// guarantees the peer is up before either side spends time on STUN and
    /// address announcements, so a `PTUN v1` line we receive here is from a
    /// live peer (staleness is still enforced by `date`).
    ///
    /// Resolves with the peer's public address, [`TelegramError::Timeout`] after
    /// `cfg.timeout_secs`, or [`TelegramError::Aborted`] as soon as
    /// `is_aborted()` returns true (checked before and after every poll, so a
    /// user abort lands within one short poll window).
    ///
    /// The queue is *not* cleared on entry: the newest peer line already in
    /// the queue may be exactly the one we want (the peer started first and
    /// has been waiting for us). Staleness is decided by the message `date`,
    /// not by when this process started.
    pub async fn wait_peer_addr(
        &mut self,
        cfg: &TelegramConfig,
        is_aborted: impl Fn() -> bool + Send,
    ) -> Result<SocketAddr, TelegramError> {
        let own_id = self.own_bot_id.ok_or_else(|| {
            TelegramError::Request("Telegram::init must be called before waiting".into())
        })?;

        let timeout = Duration::from_secs(cfg.timeout_secs);
        let deadline = tokio::time::Instant::now() + timeout;
        info!(
            peer_bot_id = self.peer_bot_id,
            timeout_secs = cfg.timeout_secs,
            "waiting for the peer bot's address (q / Esc / Ctrl-C to cancel)"
        );

        loop {
            if is_aborted() {
                return Err(TelegramError::Aborted);
            }
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
                // Track the highest update id we've seen so the next poll
                // starts strictly after it — no re-delivery.
                if msg.update_id + 1 > self.seen {
                    self.seen = msg.update_id + 1;
                }
                if let Some(addr) = self.classify(&msg, own_id) {
                    info!(%addr, "received the peer's address via Telegram");
                    return Ok(addr);
                }
            }
        }
    }

    /// Send our `PTUN READY <secret>` line to the peer bot and wait for the
    /// peer bot's own `PTUN READY <secret>` line.
    ///
    /// This is the first step of the address exchange: it proves the peer's
    /// process (and its bot) is up and *listening*, before either side calls
    /// STUN or announces an address. Both sides run this at startup, so the
    /// two READY messages cross in flight and each side proceeds as soon as
    /// it has seen the other's.
    ///
    /// The secret must match `[telegram].secret` on both machines: a READY
    /// line with a different (or missing) secret is ignored, and a READY line
    /// older than [`MAX_READY_AGE_SECS`] is ignored as stale. Own-bot echoes
    /// are ignored like everywhere else (loop prevention — we never auto-
    /// reply to incoming bot messages).
    ///
    /// Resolves once the peer's READY line is seen, [`TelegramError::Timeout`]
    /// after [`READY_TIMEOUT_SECS`], or [`TelegramError::Aborted`] as soon as
    /// `is_aborted()` returns true (checked before and after every poll).
    pub async fn handshake(
        &mut self,
        cfg: &TelegramConfig,
        is_aborted: impl Fn() -> bool + Send,
    ) -> anyhow::Result<()> {
        let secret = cfg
            .secret
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or_default()
            .to_string();
        anyhow::ensure!(
            !secret.is_empty(),
            "config: `[telegram].secret` is required for the bot-to-bot readiness handshake"
        );

        let own_id = self.own_bot_id.ok_or_else(|| {
            TelegramError::Request("Telegram::init must be called before the handshake".into())
        })?;

        let text = format!("{READY_PREFIX}{secret}");
        let chat_id = self.peer_bot_id.to_string();
        let fields: [(&str, &str); 2] = [("chat_id", &chat_id), ("text", &text)];
        self.call_with::<serde_json::Value>("sendMessage", &fields)
            .await
            .with_context(|| {
                format!(
                    "sending our PTUN READY line to peer bot {} — is Bot-to-Bot Communication \
                     Mode enabled for BOTH bots in @BotFather? Is `[telegram].peer_bot_id` \
                     the peer bot's numeric id?",
                    self.peer_bot_id
                )
            })?;
        info!(
            peer_bot_id = self.peer_bot_id,
            "sent PTUN READY; waiting for the peer bot to confirm it is up (q / Esc / Ctrl-C to cancel)"
        );

        let deadline = tokio::time::Instant::now() + Duration::from_secs(READY_TIMEOUT_SECS);
        loop {
            if is_aborted() {
                return Err(anyhow::Error::from(TelegramError::Aborted));
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(anyhow::Error::from(TelegramError::Timeout {
                    peer_bot_id: self.peer_bot_id,
                    timeout_secs: READY_TIMEOUT_SECS,
                }));
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
                    warn!(error = %e, "getUpdates failed during handshake; retrying");
                    continue;
                }
                Err(_) => {
                    warn!("getUpdates hung past its guard during handshake; retrying");
                    continue;
                }
            };

            for msg in updates {
                // Track the highest update id we've seen so the next poll
                // starts strictly after it — no re-delivery. (The same
                // `Telegram` instance is reused for `wait_peer_addr`, whose
                // offset picks up right where this loop left off.)
                if msg.update_id + 1 > self.seen {
                    self.seen = msg.update_id + 1;
                }
                if self.classify_ready(&msg, own_id, &secret) {
                    info!("peer bot confirmed it is up — the readiness handshake is complete");
                    return Ok(());
                }
            }
        }
    }

    /// If this message is a *fresh* `PTUN READY <secret>` line from the peer
    /// bot (matching secret, younger than [`MAX_READY_AGE_SECS`]), return
    /// true. Own-bot echoes, other senders, mismatched/missing secrets and
    /// stale lines are ignored.
    fn classify_ready(&self, msg: &UpdateMessage, own_id: i64, secret: &str) -> bool {
        let Some(text) = msg.message.text.as_deref() else {
            return false;
        };
        let Some(body) = text.trim().strip_prefix(READY_PREFIX) else {
            return false;
        };
        let Some(from) = msg.message.from.as_ref() else {
            return false;
        };
        if from.id == own_id || !from.is_bot {
            return false;
        }
        if from.id != self.peer_bot_id {
            warn!(
                sender = from.id,
                "ignoring PTUN READY message from unexpected sender"
            );
            return false;
        }
        // The secret must match exactly: this is what distinguishes "the peer
        // is up right now" from a stray line in the chat.
        if body.trim() != secret {
            warn!("ignoring PTUN READY line with a mismatched secret");
            return false;
        }
        // Staleness: a READY line from a previous run of the peer (before the
        // process that is actually listening started) is not proof of
        // readiness. A missing date (0, synthetic test messages) is accepted.
        if msg.message.date > 0 {
            let age = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
                - msg.message.date;
            if age > MAX_READY_AGE_SECS {
                warn!(
                    age_secs = age,
                    "ignoring stale PTUN READY line (older than {MAX_READY_AGE_SECS}s)"
                );
                return false;
            }
        }
        true
    }

    /// If this message is a *fresh* `PTUN v1 <addr>` line from the peer bot,
    /// return the address. Own-bot echoes, other senders, malformed payloads
    /// and stale announcements are ignored (loop prevention — we never reply
    /// to bot messages).
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
        // Reject announcements older than MAX_ADDR_AGE_SECS: the NAT mapping
        // behind that address is almost certainly gone, and acting on it
        // would only burn the whole punch timeout. `date` is unix seconds
        // (Telegram server time); a missing date (0) is treated as "unknown"
        // and accepted rather than deadlocking the exchange.
        if msg.message.date > 0 {
            let age = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
                - msg.message.date;
            if age > MAX_ADDR_AGE_SECS {
                warn!(
                    age_secs = age,
                    "ignoring stale PTUN announcement (older than {MAX_ADDR_AGE_SECS}s)"
                );
                return None;
            }
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
        let offset_s = self.seen.to_string();
        // `result` of `getUpdates` is the array itself, so `T` is the vec.
        self.call_with::<Vec<UpdateMessage>>(
            "getUpdates",
            &[("timeout", timeout.as_str()), ("offset", offset_s.as_str())],
        )
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
    update_id: i64,
    #[serde(default)]
    message: Message,
}

#[derive(Debug, Default, Deserialize)]
struct Message {
    #[serde(default)]
    from: Option<ChatUser>,
    #[serde(default)]
    text: Option<String>,
    /// Unix timestamp (seconds) when Telegram delivered the message; 0 for
    /// synthetic test messages (treated as "unknown age" — accepted).
    #[serde(default)]
    date: i64,
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
            update_id: 0,
            message: Message {
                from: Some(ChatUser {
                    id: from_id,
                    is_bot,
                }),
                text: text.to_string().into(),
                date: 0, // unknown age -> accepted, like a dateless test message
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
            own_bot_id: Some(1001),
            seen: 0,
        }
    }

    /// A `getUpdates` entry with an explicit `date` (unix seconds).
    fn msg_at(from_id: i64, is_bot: bool, text: &str, date: i64) -> UpdateMessage {
        UpdateMessage {
            update_id: 0,
            message: Message {
                from: Some(ChatUser {
                    id: from_id,
                    is_bot,
                }),
                text: text.to_string().into(),
                date,
            },
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

    #[test]
    fn classify_accepts_fresh_peer_payload() {
        let tg = tg_for_test(9001);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let m = msg_at(9001, true, "PTUN v1 10.1.2.3:4321", now - 5);
        assert_eq!(
            tg.classify(&m, 1001),
            Some("10.1.2.3:4321".parse().unwrap())
        );
    }

    #[test]
    fn classify_rejects_stale_peer_payload() {
        let tg = tg_for_test(9001);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // An hour-old announcement: the NAT mapping is long gone.
        let m = msg_at(9001, true, "PTUN v1 10.1.2.3:4321", now - 3600);
        assert_eq!(tg.classify(&m, 1001), None);
    }

    #[test]
    fn classify_accepts_payload_without_date() {
        // A missing `date` (0) must not deadlock the exchange.
        let tg = tg_for_test(9001);
        let m = msg_at(9001, true, "PTUN v1 10.1.2.3:4321", 0);
        assert_eq!(
            tg.classify(&m, 1001),
            Some("10.1.2.3:4321".parse().unwrap())
        );
    }

    #[test]
    fn ready_line_is_well_formed() {
        let line = format!("{READY_PREFIX}my-secret");
        assert_eq!(line, "PTUN READY my-secret");
    }

    #[test]
    fn classify_ready_accepts_peer_line() {
        let tg = tg_for_test(9001);
        let m = msg(9001, true, "PTUN READY my-secret");
        assert!(tg.classify_ready(&m, 1001, "my-secret"));
    }

    #[test]
    fn classify_ready_ignores_own_echo() {
        let tg = tg_for_test(9001);
        let m = msg(1001, true, "PTUN READY my-secret");
        assert!(!tg.classify_ready(&m, 1001, "my-secret"));
    }

    #[test]
    fn classify_ready_ignores_unexpected_sender_and_non_bot() {
        let tg = tg_for_test(9001);
        assert!(!tg.classify_ready(&msg(7777, true, "PTUN READY my-secret"), 1001, "my-secret"));
        assert!(!tg.classify_ready(&msg(9001, false, "PTUN READY my-secret"), 1001, "my-secret"));
    }

    #[test]
    fn classify_ready_rejects_mismatched_or_missing_secret() {
        let tg = tg_for_test(9001);
        assert!(!tg.classify_ready(&msg(9001, true, "PTUN READY wrong"), 1001, "my-secret"));
        assert!(!tg.classify_ready(&msg(9001, true, "PTUN READY"), 1001, "my-secret"));
        assert!(!tg.classify_ready(&msg(9001, true, "PTUN v1 1.2.3.4:5"), 1001, "my-secret"));
        assert!(!tg.classify_ready(&msg(9001, true, "hello"), 1001, "my-secret"));
    }

    #[test]
    fn classify_ready_rejects_stale_line() {
        let tg = tg_for_test(9001);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let m = msg_at(9001, true, "PTUN READY my-secret", now - 3600);
        assert!(!tg.classify_ready(&m, 1001, "my-secret"));
    }

    #[test]
    fn classify_ready_accepts_fresh_line() {
        let tg = tg_for_test(9001);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let m = msg_at(9001, true, "PTUN READY my-secret", now - 5);
        assert!(tg.classify_ready(&m, 1001, "my-secret"));
    }
}
