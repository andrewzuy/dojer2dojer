//! Reconnect supervisor (v2): the full re-negotiation loop.
//!
//! One attempt = address exchange (Telegram-first with the READY + role
//! handshake, manual fallback) → STUN → role cross-check (Telegram mode) →
//! hole punch → QUIC handshake → tunnel. On tunnel loss — the connection
//! closing, a STUN/punch/handshake failure — the supervisor backs off and
//! re-negotiates everything from scratch (the NAT bindings and the peer
//! process are stale).
//!
//! Behaviour invariants (v2):
//! - A tunnel that stays up for at least [`STABLE_SECS`] resets the backoff
//!   clock — a later loss is a transient blip, not an ongoing misconfiguration.
//! - The Telegram channel lives for the whole app: one instance (with its own
//!   getUpdates cursor) is shared across attempts, so each attempt only sees
//!   fresh lines.
//! - Manual mode caches the peer address between attempts; after two
//!   consecutive punch failures with the cached address, the next attempt
//!   re-prompts (showing the previous value) instead of reusing it.
//! - If STUN fails inside the Telegram path, the run aborts with the error —
//!   the root cause is almost certainly an unreachable STUN server, not
//!   Telegram.
//!
//! Exits only on:
//! - user abort (q / Esc / Ctrl-C) — clean exit,
//! - fatal setup errors (bad CLI flag, misconfiguration, EOF with nothing
//!   configured) — non-zero exit,
//! - structural runtime errors (e.g. the local TCP port is already in use) —
//!   non-zero exit,
//!
//! and forces a fresh re-selection at the setup screen when the peer's
//! declared role conflicts with ours (v2): a stale config selection must
//! never silently survive a conflict.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Context;
use tracing::{Instrument, info};

use crate::cli::{self, Cli};
use crate::config::Config;
use crate::punch::punch;
use crate::quic;
use crate::role::{self, Role};
use crate::setup::{self, Setting, Setup, SetupBail};
use crate::stun::discover_public_addr;
use crate::telegram::Telegram;
use crate::tui::{self, PromptOutcome, TuiEvent, TuiHandle};
use crate::tui_state::{ExchangeMode, Phase, PhaseStatus};
use crate::tunnel::{run_client_side, run_server_side};

/// Base delay for the exponential backoff between attempts.
const BASE_BACKOFF_SECS: u64 = 2;
/// Cap on the exponential backoff — never wait longer than this.
const MAX_BACKOFF_SECS: u64 = 30;
/// A tunnel up for at least this long resets the backoff clock.
const STABLE_SECS: u64 = 30;

/// Exponential backoff with full jitter, keyed off the number of the just-failed
/// attempt (1-based): a delay uniform in `[0, min(MAX, BASE * 2^(n-1)))` seconds.
///
/// `jitter01` is a uniform random in `[0, 1)` — injected in tests.
pub fn retry_delay(failed_attempt: u32, jitter01: f64) -> Duration {
    let raw = BASE_BACKOFF_SECS << failed_attempt.saturating_sub(1).min(5);
    let cap = raw.min(MAX_BACKOFF_SECS);
    let frac = jitter01.clamp(0.0, 0.999_999);
    Duration::from_millis((cap as f64 * frac * 1000.0).max(0.0) as u64)
}

/// Why an attempt ended (everything other than a fatal error, which is
/// returned as `Err` from the attempt).
#[derive(Debug)]
enum AttemptOutcome {
    /// Transient failure or a closed tunnel — retry after backoff.
    Retry(String),
    /// The user aborted — the supervisor exits cleanly.
    Abort,
    /// Role conflict: the peer declared the same role we selected.
    RoleConflict(Role),
}

/// What one attempt told the supervisor: how it ended, how long the tunnel
/// ran (zero when setup/punch/handshake failed before the tunnel), and the
/// peer address used (for the manual cached-address rule).
#[derive(Debug)]
struct AttemptReport {
    outcome: AttemptOutcome,
    tunnel_up_for: Duration,
    peer_addr: Option<SocketAddr>,
}

/// The v2 startup-setup + supervisor loop.
pub async fn run(cfg: &Config, cli: &Cli, ui: &TuiHandle) -> anyhow::Result<()> {
    // ── Startup setup (v2): role + setting + channel, before the loop. ──
    let mut setup = match setup::setup(cfg, cli, ui) {
        Ok(s) => s,
        Err(SetupBail::Aborted) => return Ok(()),
        Err(SetupBail::Fatal(msg)) => return Err(anyhow::anyhow!(msg)),
    };
    emit_selected_role(ui, &setup);

    // The Telegram channel lives for the whole app: one instance (with its own
    // getUpdates cursor) is shared across attempts and created lazily.
    let mut telegram: Option<Telegram> = None;

    // Manual-mode state: the last peer address the operator gave us, and the
    // number of consecutive punch failures since that address was freshly
    // entered (or freshly re-prompted after the streak was exceeded).
    let mut manual_cached_addr: Option<SocketAddr> = None;
    let mut consecutive_punch_failures = 0u32;

    let mut attempt = 0u32;
    let mut stable_for = Duration::ZERO;
    let mut started = false;

    loop {
        // A tunnel that ran stable for STABLE_SECS resets the backoff clock —
        // the next loss is a transient blip, not an ongoing misconfiguration.
        if stable_for >= Duration::from_secs(STABLE_SECS) {
            attempt = 0;
        }
        attempt += 1;

        if started {
            // Later attempts re-enter the retry flow (the state is reset and
            // the phases start over). Attempt 1 starts from a clean slate —
            // setup already emitted the role line.
            ui.emit(TuiEvent::RetryBegin { attempt });
        }
        started = true;

        let manual_mode = matches!(setup.channel, ExchangeMode::Manual);
        let reuse_addr =
            if manual_mode && consecutive_punch_failures < 2 && manual_cached_addr.is_some() {
                manual_cached_addr
            } else {
                None
            };
        // The previous address is shown to the operator as a hint when a fresh
        // prompt is required (e.g. after two punch failures).
        let prev_addr_hint = if manual_mode {
            manual_cached_addr
        } else {
            None
        };

        match run_attempt(cfg, &setup, ui, &mut telegram, reuse_addr, prev_addr_hint).await {
            Ok(report) => {
                let AttemptReport {
                    outcome,
                    tunnel_up_for,
                    peer_addr,
                } = report;
                stable_for = tunnel_up_for;

                // Manual mode: cache the peer address for the next attempt and
                // reset the punch streak when the operator re-entered it.
                if manual_mode {
                    if let Some(pa) = peer_addr {
                        manual_cached_addr = Some(pa);
                    }
                    if reuse_addr.is_none() && peer_addr.is_some() {
                        consecutive_punch_failures = 0;
                    }
                }

                match outcome {
                    AttemptOutcome::Retry(reason) => {
                        if ui.aborted() {
                            return Ok(());
                        }
                        if reason.contains("hole punching") || reason.contains("QUIC handshake") {
                            consecutive_punch_failures += 1;
                        } else {
                            consecutive_punch_failures = 0;
                        }
                        let delay = retry_delay(attempt, rand::random::<f64>());
                        let msg = format!("{reason} — retrying in ~{}s", delay.as_secs().max(1));
                        ui.emit(TuiEvent::Renegotiating(msg.clone()));
                        ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg.clone()));
                        if ui.is_disabled() {
                            // Non-TUI mode: keep the retry visible in plain text.
                            eprintln!("{msg}");
                        }
                        // Race the backoff against a user abort so q/Ctrl-C
                        // exits immediately instead of after the full delay.
                        tokio::select! {
                            _ = tokio::time::sleep(delay) => {}
                            _ = wait_aborted(ui) => return Ok(()),
                        }
                        if ui.aborted() {
                            return Ok(());
                        }
                    }
                    AttemptOutcome::Abort => return Ok(()),
                    AttemptOutcome::RoleConflict(their_role) => {
                        // v2: a conflict is a misconfiguration, not a transient
                        // failure. Stop the attempt, tell the operator, and force a
                        // fresh re-selection at the setup screen — a stale config
                        // selection must never silently survive a conflict.
                        let conflict = role::check_compatible(setup.role, their_role)
                            .expect_err("conflict outcome implies an incompatible peer role");
                        let msg = format!("{conflict} — re-select your role to continue");
                        ui.emit(TuiEvent::Log(tui::LogLevel::Error, msg.clone()));
                        eprintln!("{msg}");
                        match setup::setup_force_select_with(cfg, cli, &mut |prompt| {
                            ui.ask_line(prompt)
                        }) {
                            Ok(new_setup) => {
                                setup = new_setup;
                                attempt = 0; // fresh attempt, no backoff
                                emit_selected_role(ui, &setup);
                            }
                            Err(SetupBail::Aborted) => return Ok(()),
                            Err(SetupBail::Fatal(msg)) => return Err(anyhow::anyhow!(msg)),
                        }
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Emit the selected-role events once per setup into the TUI.
fn emit_selected_role(ui: &TuiHandle, setup: &Setup) {
    ui.emit(TuiEvent::SelectedRole(setup.role.as_str().to_string()));
    ui.emit(TuiEvent::Phase(Phase::Role, PhaseStatus::Done));
}

/// The full re-negotiation for one attempt.
async fn run_attempt(
    cfg: &Config,
    setup: &Setup,
    ui: &TuiHandle,
    telegram: &mut Option<Telegram>,
    reuse_addr: Option<SocketAddr>,
    prev_addr_hint: Option<SocketAddr>,
) -> anyhow::Result<AttemptReport> {
    // 1. Fresh UDP socket — NAT bindings and the peer process are stale per
    // attempt, so the socket (and its own public address) are re-created.
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .context("binding UDP socket")?;

    // 2. Address exchange — Telegram-first with the READY + role handshake,
    // manual fallback. The peer's declared role comes back for the cross-check.
    let (_public_addr, peer_addr, peer_role) = match resolve_addrs(
        cfg,
        setup,
        &socket,
        ui,
        telegram,
        reuse_addr,
        prev_addr_hint,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => {
            // STUN failure inside the Telegram path is structural: abort with
            // the error (the operator must fix the STUN server).
            if error_says_stun_fatal(&e) {
                return Err(e);
            }
            if ui.aborted() || error_says_aborted(&e) {
                return Ok(AttemptReport {
                    outcome: AttemptOutcome::Abort,
                    tunnel_up_for: Duration::ZERO,
                    peer_addr: None,
                });
            }
            if error_says_eof(&e) {
                // Non-interactive Eof: the operator must configure stdin or a
                // peer address is required — fatal, no retry.
                return Err(e);
            }
            return Ok(AttemptReport {
                outcome: AttemptOutcome::Retry(format!("address exchange failed: {e:#}")),
                tunnel_up_for: Duration::ZERO,
                peer_addr: None,
            });
        }
    };

    if ui.aborted() {
        return Ok(AttemptReport {
            outcome: AttemptOutcome::Abort,
            tunnel_up_for: Duration::ZERO,
            peer_addr: None,
        });
    }

    // 2b. Tell the TUI about the resolved peer address so the connection panel
    // shows it. Skipped on reuse (the same address was already shown).
    ui.emit(tui::TuiEvent::PeerAddr(peer_addr.to_string()));

    // 3. Role cross-check (Telegram mode only — a legacy peer or a manual
    //    exchange carries no declared role, so no cross-check is possible).
    if let Some(peer_role) = peer_role
        && role::check_compatible(setup.role, peer_role).is_err()
    {
        return Ok(AttemptReport {
            outcome: AttemptOutcome::RoleConflict(peer_role),
            tunnel_up_for: Duration::ZERO,
            peer_addr: Some(peer_addr),
        });
    }

    // 4. Hole punch. A punch failure is transient — the peer may be down or
    //    the binding expired; the supervisor retries.
    ui.emit(TuiEvent::Phase(Phase::Punch, PhaseStatus::Active));
    match punch(&socket, peer_addr, cfg)
        .instrument(tracing::info_span!("punch", %peer_addr))
        .await
    {
        Ok(()) => {
            ui.emit(TuiEvent::Phase(Phase::Punch, PhaseStatus::Done));
        }
        Err(e) => {
            if ui.aborted() || error_says_aborted(&e) {
                return Ok(AttemptReport {
                    outcome: AttemptOutcome::Abort,
                    tunnel_up_for: Duration::ZERO,
                    peer_addr: Some(peer_addr),
                });
            }
            return Ok(AttemptReport {
                outcome: AttemptOutcome::Retry(format!("hole punching failed: {e:#}")),
                tunnel_up_for: Duration::ZERO,
                peer_addr: Some(peer_addr),
            });
        }
    }

    // 5. Fresh self-signed certificate for the QUIC handshake.
    ui.emit(TuiEvent::Phase(Phase::Quic, PhaseStatus::Active));
    let (cert_chain, key) = quic::generate_self_signed_cert()?;
    let fingerprint = quic::fingerprint(&cert_chain[0]);
    ui.emit(TuiEvent::Fingerprint(fingerprint));

    // 6. QUIC endpoint on the punched socket.
    let keep_alive = (cfg.keep_alive_interval_secs > 0)
        .then(|| Duration::from_secs(cfg.keep_alive_interval_secs));
    let std_socket = socket
        .into_std()
        .context("converting the punched UDP socket for quinn")?;
    let server_config = match setup.role {
        Role::Server => Some(quic::build_server_config(cert_chain, key, keep_alive)?),
        Role::Client => None,
    };
    let mut endpoint = quic::create_endpoint(std_socket, server_config)?;
    if matches!(setup.role, Role::Client) {
        endpoint.set_default_client_config(quic::build_client_config(keep_alive)?);
    }
    info!(local = ?endpoint.local_addr(), "QUIC endpoint ready");

    // 7. Establish the connection.
    ui.emit(TuiEvent::Phase(Phase::Quic, PhaseStatus::Done));
    let conn = match setup.role {
        Role::Server => {
            let Setting::Server(target) = setup.setting else {
                unreachable!("server setup always carries a target");
            };
            ui.emit(TuiEvent::Target(target.to_string()));
            info!("waiting for the peer's QUIC connection…");
            quic::accept(&endpoint)
                .instrument(tracing::info_span!("quic_handshake"))
                .await
        }
        Role::Client => {
            let Setting::Client(port) = setup.setting else {
                unreachable!("client setup always carries a port");
            };
            ui.emit(TuiEvent::LocalPort(port));
            info!("initiating QUIC connection to peer…");
            quic::connect(&endpoint, peer_addr)
                .instrument(tracing::info_span!("quic_handshake"))
                .await
        }
    };

    let conn = match conn {
        Ok(conn) => conn,
        Err(e) => {
            if ui.aborted() || error_says_aborted(&e) {
                return Ok(AttemptReport {
                    outcome: AttemptOutcome::Abort,
                    tunnel_up_for: Duration::ZERO,
                    peer_addr: Some(peer_addr),
                });
            }
            return Ok(AttemptReport {
                outcome: AttemptOutcome::Retry(format!("QUIC handshake failed: {e:#}")),
                tunnel_up_for: Duration::ZERO,
                peer_addr: Some(peer_addr),
            });
        }
    };
    ui.emit(TuiEvent::Phase(Phase::Tunnel, PhaseStatus::Active));
    ui.emit(TuiEvent::Ready);

    // 8. Tunnel — raced against the user's abort; the tunnel runs until the
    //    connection closes (peer exit or network loss).
    let tunnel_future: std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>,
    > = match setup.setting {
        Setting::Client(port) => Box::pin(run_client_side(conn.clone(), port)),
        Setting::Server(addr) => Box::pin(run_server_side(conn.clone(), addr)),
    };
    let started = Instant::now();
    let outcome = tokio::select! {
        r = tunnel_future => match r {
            Ok(()) => {
                if ui.aborted() {
                    AttemptOutcome::Abort
                } else {
                    AttemptOutcome::Retry("tunnel closed (connection dropped)".to_string())
                }
            }
            Err(e) => {
                if ui.aborted() || error_says_aborted(&e) {
                    AttemptOutcome::Abort
                } else {
                    let chain = format!("{e:#}");
                    // Structural: the operator must fix the config/port —
                    // no point retrying forever.
                    if chain.contains("bind local TCP listener") {
                        return Err(e);
                    }
                    AttemptOutcome::Retry(format!("tunnel failed: {chain}"))
                }
            }
        },
        _ = wait_aborted(ui) => AttemptOutcome::Abort,
    };
    let tunnel_up_for = started.elapsed();

    // Drop the endpoint so the socket is released for the next attempt.
    drop(endpoint);
    Ok(AttemptReport {
        outcome,
        tunnel_up_for,
        peer_addr: Some(peer_addr),
    })
}

/// Poll `ui.aborted()` every 100ms until set.
async fn wait_aborted(ui: &TuiHandle) {
    loop {
        if ui.aborted() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Does the error message mark a user abort? (Prompt loops return a distinct
/// `anyhow!("aborted by the user")`; the render loop also flips `aborted`.)
fn error_says_aborted(e: &anyhow::Error) -> bool {
    format!("{e:#}").contains("aborted by the user")
}

/// Does the error message mark a non-interactive stdin EOF?
fn error_says_eof(e: &anyhow::Error) -> bool {
    format!("{e:#}").contains("stdin closed")
}

/// Does the error message mark STUN failure inside the Telegram path?
/// (Marked by `resolve_addrs_telegram` — an unreachable STUN server is not
/// Telegram's fault, so the run aborts with the error.)
fn error_says_stun_fatal(e: &anyhow::Error) -> bool {
    format!("{e:#}").contains("STUN discovery failed during the Telegram address exchange")
}

/// Resolve the peer's address for this attempt — Telegram-first (READY + role
/// handshake) or manual, per `setup.channel`. Returns the two addresses and
/// the peer's declared role (`None` on the manual path or with a legacy peer).
async fn resolve_addrs(
    cfg: &Config,
    setup: &Setup,
    socket: &tokio::net::UdpSocket,
    ui: &TuiHandle,
    telegram: &mut Option<Telegram>,
    reuse_addr: Option<SocketAddr>,
    prev_addr_hint: Option<SocketAddr>,
) -> anyhow::Result<(SocketAddr, SocketAddr, Option<Role>)> {
    match setup.channel {
        ExchangeMode::Manual => {
            let (public, peer) =
                resolve_addrs_manual(cfg, socket, ui, telegram, reuse_addr, prev_addr_hint).await?;
            Ok((public, peer, None))
        }
        ExchangeMode::Telegram => resolve_addrs_telegram(cfg, setup, socket, ui, telegram).await,
    }
}

/// Resolve the address pair via the Telegram exchange: READY + role handshake
/// (proves the peer is up), STUN, announce, wait for the peer's address.
/// On any Telegram failure, falls back to the manual prompt (STUN runs
/// first there, as in [`resolve_addrs_manual`]).
async fn resolve_addrs_telegram(
    cfg: &Config,
    setup: &Setup,
    socket: &tokio::net::UdpSocket,
    ui: &TuiHandle,
    telegram: &mut Option<Telegram>,
) -> anyhow::Result<(SocketAddr, SocketAddr, Option<Role>)> {
    let tg_cfg = cfg
        .telegram
        .as_ref()
        .context("[telegram] section is incomplete — complete it or pass --manual")?;
    ui.emit(TuiEvent::TelegramChannel(true));
    ui.set_exchange_mode(ExchangeMode::Telegram);

    // Lazily initialize the shared client (getMe). On init failure, degrade to
    // the manual prompt for THIS attempt — and leave the slot empty so the
    // NEXT attempt retries the init (a transient network error must not
    // permanently disable Telegram).
    if telegram.is_none() {
        match Telegram::init(tg_cfg).await {
            Ok(t) => {
                ui.emit(TuiEvent::Log(
                    tui::LogLevel::Info,
                    "exchanging readiness with the peer bot over Telegram…".into(),
                ));
                *telegram = Some(t);
            }
            Err(e) => {
                let msg = format!(
                    "Telegram signaling unavailable ({e:#}) — falling back to the manual address prompt."
                );
                eprintln!("{msg}");
                ui.emit(TuiEvent::TelegramChannel(false));
                ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
                ui.set_exchange_mode(ExchangeMode::Manual);
                let (public, peer) =
                    resolve_addrs_manual(cfg, socket, ui, telegram, None, None).await?;
                return Ok((public, peer, None));
            }
        }
    }

    // (1) Readiness + role handshake — sends our READY line + PTUN ROLE.
    //     Legacy peers ignore the ROLE line; the peer's declared role (if any)
    //     is captured for the cross-check. Any Telegram failure falls back to
    //     the manual prompt for this attempt.
    let peer_role = {
        let tg = telegram.as_mut().expect("initialized above");
        match tg
            .handshake_with_role(tg_cfg, Some(setup.role), || ui.aborted())
            .await
        {
            Ok(role) => role,
            Err(e) => {
                if ui.aborted() || error_says_aborted(&e) {
                    return Err(anyhow::anyhow!("aborted by the user"));
                }
                let msg = format!(
                    "Timed out / failed waiting for the peer bot's readiness confirmation ({e:#}) — switching to the manual address prompt."
                );
                eprintln!("{msg}");
                ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
                ui.set_exchange_mode(ExchangeMode::Manual);
                let (public, peer) =
                    resolve_addrs_manual(cfg, socket, ui, telegram, None, None).await?;
                return Ok((public, peer, None));
            }
        }
    };
    ui.emit(TuiEvent::Log(
        tui::LogLevel::Info,
        "peer bot confirmed it is up — discovering our address".into(),
    ));

    // (2) STUN — safe now: the peer is up and will be announcing soon. If STUN
    //     fails here, abort with the error — the root cause is an unreachable
    //     STUN server, not Telegram.
    ui.emit(TuiEvent::Phase(Phase::Stun, PhaseStatus::Active));
    let public_addr = discover_public_addr(socket, &cfg.stun_servers)
        .instrument(tracing::info_span!("stun"))
        .await
        .context("STUN discovery failed during the Telegram address exchange")?;
    info!(%public_addr, "discovered public address");
    ui.emit(TuiEvent::OwnAddr(public_addr.to_string()));
    ui.emit(TuiEvent::Phase(Phase::Stun, PhaseStatus::Done));

    // (3) Announce our address, wait for the peer's.
    let tg = telegram.as_mut().expect("initialized above");
    if let Err(e) = tg.send_own_addr(public_addr).await {
        if ui.aborted() || error_says_aborted(&e) {
            return Err(anyhow::anyhow!("aborted by the user"));
        }
        let msg = format!(
            "Telegram signaling failed ({e:#}) — falling back to the manual address prompt."
        );
        eprintln!("{msg}");
        ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
        ui.set_exchange_mode(ExchangeMode::Manual);
        let peer_addr = manual_peer_addr(cfg, Some(public_addr), ui, telegram, None).await?;
        return Ok((public_addr, peer_addr, None));
    }

    match tg.wait_peer_addr(tg_cfg, || ui.aborted()).await {
        Ok(addr) => {
            ui.emit(TuiEvent::Phase(Phase::Exchange, PhaseStatus::Done));
            Ok((public_addr, addr, peer_role))
        }
        Err(crate::telegram::TelegramError::Aborted) => Err(anyhow::anyhow!("aborted by the user")),
        Err(e) => {
            if ui.aborted() {
                return Err(anyhow::anyhow!("aborted by the user"));
            }
            let msg = format!(
                "Timed out / failed waiting for the peer bot's address ({e}) — switching to the manual address prompt."
            );
            eprintln!("{msg}");
            ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
            ui.set_exchange_mode(ExchangeMode::Manual);
            let peer_addr = manual_peer_addr(cfg, Some(public_addr), ui, telegram, None).await?;
            Ok((public_addr, peer_addr, None))
        }
    }
}

/// The manual path: STUN first (the human on the other end is the liveness
/// signal — no bot handshake needed), then the address prompt.
///
/// `reuse_addr`: a cached peer address from the previous attempt — when set,
/// the prompt is skipped entirely. `prev_addr_hint`: the previous address,
/// shown to the operator as a hint on a fresh prompt (empty line keeps it).
async fn resolve_addrs_manual(
    cfg: &Config,
    socket: &tokio::net::UdpSocket,
    ui: &TuiHandle,
    telegram: &mut Option<Telegram>,
    reuse_addr: Option<SocketAddr>,
    prev_addr_hint: Option<SocketAddr>,
) -> anyhow::Result<(SocketAddr, SocketAddr)> {
    ui.emit(TuiEvent::Phase(Phase::Stun, PhaseStatus::Active));
    let public_addr = discover_public_addr(socket, &cfg.stun_servers)
        .instrument(tracing::info_span!("stun"))
        .await?;
    info!(%public_addr, "discovered public address");
    ui.emit(TuiEvent::OwnAddr(public_addr.to_string()));
    ui.emit(TuiEvent::Phase(Phase::Stun, PhaseStatus::Done));

    // Display own public address and ask for the peer's. In TUI mode the
    // address is shown in the connection panel, so the plain-text prompt is
    // only printed in the non-TUI path.
    let tui_active = !ui.is_disabled();
    if !tui_active {
        println!();
        println!("Your public address is: {public_addr}");
        println!("Give it to the other party, then enter their public address below.");
    }

    ui.emit(TuiEvent::Phase(Phase::Exchange, PhaseStatus::Active));

    if let Some(reused) = reuse_addr {
        ui.emit(TuiEvent::Log(
            tui::LogLevel::Info,
            format!("reusing cached peer address {reused}"),
        ));
        ui.emit(TuiEvent::Phase(Phase::Exchange, PhaseStatus::Done));
        return Ok((public_addr, reused));
    }

    let peer_addr = manual_peer_addr(cfg, Some(public_addr), ui, telegram, prev_addr_hint).await?;
    ui.emit(TuiEvent::Phase(Phase::Exchange, PhaseStatus::Done));
    Ok((public_addr, peer_addr))
}

/// Read one line of user input through the active transport.
fn read_line(ui: &TuiHandle, prompt: &str) -> std::io::Result<PromptOutcome> {
    ui.ask_line(prompt)
}

/// Resolve the peer's public address, following the *current* exchange mode.
///
/// The mode is shared with the TUI: the `t` key toggles it at any time (when
/// Telegram is available), so this function loops — waiting on Telegram in
/// Telegram mode, showing the manual prompt in manual mode — until one of
/// them yields an address. A Telegram failure or a toggle falls through to
/// the manual prompt so a bot misconfiguration never blocks a working tunnel.
/// Aborts (q/Esc/Ctrl-C) stop the run.
///
/// `prev_addr_hint`: when the operator re-prompts after punch failures, the
/// previous address is shown in the prompt and an empty line keeps it.
async fn manual_peer_addr(
    cfg: &Config,
    own_addr: Option<SocketAddr>,
    ui: &TuiHandle,
    telegram: &mut Option<Telegram>,
    prev_addr_hint: Option<SocketAddr>,
) -> anyhow::Result<SocketAddr> {
    loop {
        if ui.aborted() {
            return Err(anyhow::anyhow!("aborted by the user"));
        }
        let mode = ui.exchange_mode();

        if mode == ExchangeMode::Telegram {
            // Lazily initialize the shared signaling client (getMe) on first
            // entry. On failure, degrade to the manual prompt for this
            // iteration — and leave the slot empty so the next call retries.
            if telegram.is_none() {
                let Some(tg_cfg) = &cfg.telegram else {
                    // No `[telegram]` table: degrade to the manual prompt.
                    ui.set_exchange_mode(ExchangeMode::Manual);
                    continue;
                };
                match Telegram::init(tg_cfg).await {
                    Ok(t) => {
                        ui.emit(TuiEvent::Log(
                            tui::LogLevel::Info,
                            "waiting for the peer bot's address over Telegram…".into(),
                        ));
                        *telegram = Some(t);
                    }
                    Err(e) => {
                        let msg = format!(
                            "Telegram signaling unavailable ({e:#}) — falling back to the manual address prompt."
                        );
                        eprintln!("{msg}");
                        ui.emit(TuiEvent::TelegramChannel(false));
                        ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
                        ui.set_exchange_mode(ExchangeMode::Manual);
                        continue;
                    }
                }
            }
            let Some(tg) = telegram.as_mut() else {
                continue;
            };
            let Some(tg_cfg) = &cfg.telegram else {
                continue;
            };

            // We are only here after the READY handshake (or in a manual→
            // Telegram toggle where the peer is trivially up), so an address
            // must be available to announce.
            let Some(own_addr) = own_addr else {
                // Should not happen: the handshake variant is not reachable
                // from here. Degrade to the prompt rather than panic.
                ui.set_exchange_mode(ExchangeMode::Manual);
                continue;
            };

            if let Err(e) = tg.send_own_addr(own_addr).await {
                if ui.aborted() || error_says_aborted(&e) {
                    return Err(anyhow::anyhow!("aborted by the user"));
                }
                let msg = format!(
                    "Telegram signaling failed ({e:#}) — falling back to the manual address prompt."
                );
                eprintln!("{msg}");
                ui.emit(TuiEvent::TelegramChannel(false));
                ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
                ui.set_exchange_mode(ExchangeMode::Manual);
                continue;
            }

            match tg.wait_peer_addr(tg_cfg, || ui.aborted()).await {
                Ok(addr) => return Ok(addr),
                Err(crate::telegram::TelegramError::Aborted) => {
                    return Err(anyhow::anyhow!("aborted by the user"));
                }
                Err(e) => {
                    if ui.aborted() {
                        return Err(anyhow::anyhow!("aborted by the user"));
                    }
                    let msg = format!(
                        "Timed out / failed waiting for the peer bot's address ({e}) — switching to the manual address prompt (press t to try Telegram again)."
                    );
                    eprintln!("{msg}");
                    ui.emit(TuiEvent::Log(tui::LogLevel::Warn, msg));
                    ui.set_exchange_mode(ExchangeMode::Manual);
                    continue;
                }
            }
        }

        // Manual mode — with an optional previous-address hint: an empty line
        // keeps the previous address (the prompt shows it).
        let prompt = match prev_addr_hint {
            Some(prev) => {
                format!("Enter peer's public address (ip:port) — press Enter to keep {prev}: ")
            }
            None => "Enter peer's public address (ip:port): ".to_string(),
        };
        let prev = prev_addr_hint;
        let mut read = || -> std::io::Result<PromptOutcome> {
            let outcome = read_line(ui, &prompt)?;
            match outcome {
                PromptOutcome::Line(line) if line.trim().is_empty() && prev.is_some() => {
                    Ok(PromptOutcome::Line(prev.unwrap().to_string()))
                }
                other => Ok(other),
            }
        };
        match cli::prompt_peer_addr(&mut read) {
            Ok(addr) => return Ok(addr),
            Err(cli::PromptBail::ModeToggled) => {
                // The user pressed `t` mid-prompt: loop back and wait on
                // Telegram (the render loop already flipped the shared flag).
                continue;
            }
            Err(cli::PromptBail::Aborted) => {
                return Err(anyhow::anyhow!("aborted by the user"));
            }
            Err(cli::PromptBail::Eof) => {
                return Err(anyhow::anyhow!(
                    "stdin closed before a peer address was entered"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded_and_exponential() {
        // Each attempt's cap: 2, 4, 8, 16, 30, 30, 30, 30 (capped at 30).
        let attempts = [1u32, 2, 3, 4, 5, 6, 7, 10];
        let expected_caps = [2u64, 4, 8, 16, 30, 30, 30, 30];
        for (i, &attempt) in attempts.iter().enumerate() {
            let delay = retry_delay(attempt, 0.999_999);
            assert!(
                delay.as_secs() <= expected_caps[i],
                "attempt {attempt}: delay {delay:?} exceeds cap {}",
                expected_caps[i]
            );
        }
    }

    #[test]
    fn backoff_is_full_jitter() {
        // Jitter is uniform across the [0, cap) range: 0 gives zero, 0.9
        // gives nearly the cap.
        assert_eq!(retry_delay(3, 0.0), Duration::ZERO);
        let d9 = retry_delay(3, 0.9);
        assert!(d9 > Duration::ZERO && d9 < Duration::from_secs(8));
    }

    #[test]
    fn backoff_clamps_out_of_range_jitter() {
        // Jitter outside [0,1) is clamped rather than trusted blindly.
        let _ = retry_delay(5, -1.0);
        let _ = retry_delay(5, 42.0);
    }

    #[test]
    fn stun_fatal_error_is_recognised() {
        let e = anyhow::anyhow!("STUN discovery failed during the Telegram address exchange");
        assert!(error_says_stun_fatal(&e));
        let e_other = anyhow::anyhow!("hole punching failed");
        assert!(!error_says_stun_fatal(&e_other));
    }

    #[test]
    fn abort_and_eof_errors_are_recognised() {
        let e = anyhow::anyhow!("aborted by the user");
        assert!(error_says_aborted(&e));
        let e_other = anyhow::anyhow!("stdin closed before a peer address was entered");
        assert!(error_says_eof(&e_other));
    }
}
