//! Live, cross-platform TUI that visualizes the tunnel lifecycle.
//!
//! The tunnel pipeline is unchanged; it reports progress by emitting
//! [`TuiEvent`]s over an [`mpsc::unbounded_channel`]. A dedicated render loop
//! owns the terminal (via ratatui + crossterm) and paints the current state.
//!
//! Rendering is *completely decoupled* from the network code: no pipeline
//! function calls a UI routine. They only hand the sender a message. That keeps
//! the async logic testable and the UI a pure function of the event stream.
//!
//! The TUI is opt-in (`--tui`) and also auto-enabled when stdout is a TTY and
//! `--no-tui` is not given. When the TUI is off, the plain `tracing` log path
//! runs exactly as before — there is no regression.
//!
//! **Interactive prompt (the address-exchange fallback).** The TUI owns the
//! terminal in raw mode, so a plain `read_line` from the pipeline would eat
//! raw bytes and the prompt would never appear. Instead the pipeline emits
//! [`TuiEvent::Prompt`]; the render loop switches to an inline line editor
//! (the UI keeps rendering, the user's input is visible at the bottom) and
//! replies with a [`PromptOutcome`]: the submitted line, a mode toggle (the
//! `t` key switches manual ⇄ Telegram), or an abort (`q`/Esc/Ctrl-C).
//!
//! **The S1 setup screen.** Startup setup is a real screen, not a prompt: the
//! pipeline emits [`TuiEvent::Setup`] carrying the [`SetupForm`], the render
//! loop switches to a dedicated screen (role picker → setting field → channel
//! badge), runs its own key loop, and replies with [`SetupOutcome`] — a
//! validated [`ValidatedSetup`] or an abort. The screen re-renders on every
//! keystroke; the pipeline is blocked on the reply, which is fine — no
//! network I/O happens while the operator is setting things up.
//!
//! **Keyboard.** Outside a prompt: `q`/Esc/Ctrl-C aborts the whole run (a
//! shared flag tells the pipeline to stop), and `t` switches the
//! address-exchange mode when a Telegram channel is configured.

use std::io::Write;
use std::sync::mpsc;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::{Frame, Terminal};

use crate::tui_state::{
    ExchangeMode, FormKey, Phase, PhaseStatus, SetupField, TuiState, ValidatedSetup,
};

/// A single progress message the pipeline reports to the TUI.
///
/// `Clone` + `Send` so it can cross the mpsc boundary from any pipeline task.
#[derive(Clone, Debug)]
pub enum TuiEvent {
    /// A phase transitioned: `Phase::Stun` is now `PhaseStatus::Active`, etc.
    Phase(Phase, PhaseStatus),
    /// A line for the event log (level affects color).
    Log(LogLevel, String),
    /// The own public address was discovered.
    OwnAddr(String),
    /// The peer public address was resolved.
    PeerAddr(String),
    /// The certificate fingerprint, for out-of-band comparison.
    Fingerprint(String),
    /// The local listen port (client role) the user should connect to.
    LocalPort(u16),
    /// The remote target being forwarded to (server role).
    Target(String),
    /// The tunnel is up and forwarding.
    Ready,
    /// The tunnel closed (normal exit).
    Done(String),
    /// A fatal error occurred.
    Error(String),
    /// The pipeline needs a line of text from the user. The render loop
    /// switches to the inline prompt editor and replies with the outcome on
    /// `reply_tx` (a submitted line, a mode toggle, or an abort).
    Prompt {
        prompt: String,
        reply_tx: mpsc::Sender<PromptOutcome>,
    },
    /// The pipeline needs the operator to set up the run — the render loop
    /// switches to the S1 setup screen and replies with the validated setup
    /// (or an abort) on `reply_tx`.
    Setup {
        form: crate::tui_state::SetupForm,
        reply_tx: mpsc::Sender<SetupOutcome>,
    },
    /// The peer declared its own role over the Telegram READY handshake.
    PeerRole(String),
    /// A working Telegram channel exists (or not) — the render loop shows or
    /// hides the `[t]` mode-toggle hint accordingly.
    TelegramChannel(bool),
    /// The supervisor started a new attempt: per-attempt state is reset and
    /// the event log records it (logs survive across attempts).
    RetryBegin { attempt: u32 },
    /// The tunnel dropped and the supervisor is waiting before the next
    /// attempt — the header shows a red re-negotiating banner with this
    /// (upcoming) attempt number, and the footer shows the message until
    /// [`TuiEvent::RetryBegin`].
    Renegotiating { attempt: u32, msg: String },
    /// The user-selected role from startup setup (shown in the header/diagram).
    SelectedRole(String),
}

/// The outcome of an interactive prompt, sent back to the pipeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromptOutcome {
    /// The user submitted a line (may be empty; the caller validates).
    Line(String),
    /// The user pressed `t` to switch the address-exchange mode.
    ModeToggled,
    /// The user aborted the prompt (`q` / Esc / Ctrl-C).
    Aborted,
    /// stdin was closed (EOF; the non-TUI path only).
    Eof,
}

/// The outcome of the S1 setup screen, sent back to the pipeline.
#[derive(Clone, Debug, PartialEq)]
pub enum SetupOutcome {
    /// The operator validated and submitted the form.
    Submit(ValidatedSetup),
    /// The operator aborted the screen (`q` / Esc / Ctrl-C).
    Abort,
}

/// Severity of a log line, mapping to a color in the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// A thread-safe handle the pipeline holds to report progress.
///
/// Wraps the mpsc sender plus two flags shared with the render loop:
/// the current exchange mode (flipped by the `t` key) and an abort flag
/// (set when the user quits outside a prompt). Cloning is cheap and the
/// sender can be dropped when the TUI is off (a `None` handle emits nothing).
#[derive(Clone)]
pub struct TuiHandle {
    tx: Option<mpsc::Sender<TuiEvent>>,
    mode: std::sync::Arc<std::sync::atomic::AtomicU8>,
    aborted: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl TuiHandle {
    /// A no-op handle used when the TUI is disabled. Stays in manual mode and
    /// is never aborted (there is no render loop to do either).
    pub fn disabled() -> Self {
        Self {
            tx: None,
            mode: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(ExchangeMode::MANUAL_BITS)),
            aborted: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn new(tx: mpsc::Sender<TuiEvent>) -> Self {
        Self {
            tx: Some(tx),
            mode: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(ExchangeMode::MANUAL_BITS)),
            aborted: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn emit(&self, ev: TuiEvent) {
        if let Some(tx) = &self.tx {
            // The receiver always owns the channel for the process lifetime,
            // so a closed sender is only a problem if the render loop exited
            // early (user pressed `q`); ignore that.
            let _ = tx.send(ev);
        }
    }

    /// True when the TUI is not running (events are silently dropped).
    pub fn is_disabled(&self) -> bool {
        self.tx.is_none()
    }

    /// The shared render-loop side of this handle's flags.
    pub fn render_side(
        &self,
    ) -> (
        std::sync::Arc<std::sync::atomic::AtomicU8>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        (self.mode.clone(), self.aborted.clone())
    }

    /// The current address-exchange mode (manual or Telegram).
    pub fn exchange_mode(&self) -> ExchangeMode {
        ExchangeMode::from_bits(self.mode.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Set the exchange mode (also used when the user presses `t`).
    pub fn set_exchange_mode(&self, mode: ExchangeMode) {
        self.mode
            .store(mode.to_bits(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the user has asked to abort (pressed `q`/Esc/Ctrl-C outside a
    /// prompt). The pipeline checks this between phases and at the end of
    /// every Telegram polling iteration so the run actually stops.
    pub fn aborted(&self) -> bool {
        self.aborted.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Ask the user for the startup setup (role + setting + channel) — the
    /// S1 setup screen. The render loop takes over the terminal, runs the form
    /// key loop, and replies with the outcome.
    ///
    /// Returns `None` when the TUI is disabled (callers fall back to the plain
    /// stdin path) or when the render loop dropped the reply channel.
    pub fn ask_setup(&self, form: crate::tui_state::SetupForm) -> Option<SetupOutcome> {
        let tx = self.tx.as_ref()?;
        let (reply_tx, reply_rx) = mpsc::channel();
        tx.send(TuiEvent::Setup { form, reply_tx }).ok()?;
        reply_rx.recv().ok()
    }

    /// Ask the user for a line of text and return the outcome.
    ///
    /// TUI active: hands the request to the render loop, which switches to
    /// the inline prompt editor and replies on the mpsc. Pipeline blocked
    /// meanwhile is fine — the pipeline is otherwise idle waiting for this
    /// input.
    ///
    /// TUI disabled: a plain blocking `read_line` on stdin, exactly as before.
    ///
    /// Returns [`PromptOutcome::Eof`] on EOF (stdin closed / Ctrl-D) and
    /// `Err` on I/O errors.
    pub fn ask_line(&self, prompt: &str) -> std::io::Result<PromptOutcome> {
        if let Some(tx) = &self.tx {
            let (reply_tx, reply_rx) = mpsc::channel();
            tx.send(TuiEvent::Prompt {
                prompt: prompt.to_string(),
                reply_tx,
            })
            .map_err(|_| std::io::Error::other("TUI render loop has exited"))?;
            match reply_rx.recv() {
                Ok(outcome) => Ok(outcome),
                Err(_) => Ok(PromptOutcome::Aborted),
            }
        } else {
            print!("{prompt}");
            std::io::stdout().flush()?;
            let mut line = String::new();
            let n = std::io::stdin().read_line(&mut line)?;
            if n == 0 {
                return Ok(PromptOutcome::Eof);
            }
            Ok(PromptOutcome::Line(line))
        }
    }
}

/// Construct the channel pair: the pipeline keeps `TuiHandle`, the render
/// loop receives from the `Receiver` plus the shared mode/abort flags.
pub fn channel() -> (
    TuiHandle,
    mpsc::Receiver<TuiEvent>,
    std::sync::Arc<std::sync::atomic::AtomicU8>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let (tx, rx) = mpsc::channel();
    let handle = TuiHandle::new(tx);
    let (mode, aborted) = handle.render_side();
    (handle, rx, mode, aborted)
}

// ── State application ────────────────────────────────────────────────────

/// Fold one event into the shared state (pure — no terminal I/O).
///
/// `TuiEvent::Prompt` is transport-only and carries no renderable state; it
/// is ignored here.
///
/// Splitting this out from the render loop makes it unit-testable.
pub fn apply_event(state: &mut TuiState, ev: TuiEvent) {
    match ev {
        TuiEvent::Phase(phase, status) => state.set_phase(phase, status),
        TuiEvent::Log(level, msg) => state.push_log(level, msg),
        TuiEvent::OwnAddr(a) => {
            state.push_log(LogLevel::Info, format!("own public address: {a}"));
            state.own_addr = Some(a);
        }
        TuiEvent::PeerAddr(a) => {
            state.push_log(LogLevel::Info, format!("peer address: {a}"));
            state.peer_addr = Some(a);
        }
        TuiEvent::Fingerprint(f) => {
            state.push_log(LogLevel::Info, format!("cert fingerprint: {f}"));
            state.fingerprint = Some(f);
        }
        TuiEvent::LocalPort(p) => {
            state.push_log(LogLevel::Info, format!("local port: {p}"));
            state.local_port = Some(p);
        }
        TuiEvent::Target(t) => {
            state.push_log(LogLevel::Info, format!("forwarding to: {t}"));
            state.target = Some(t);
        }
        TuiEvent::Ready => {
            state.ready = true;
            state.push_log(LogLevel::Info, "tunnel is up — traffic is flowing".into());
        }
        TuiEvent::Done(msg) => {
            state.done = true;
            state.error = false;
            state.push_log(LogLevel::Info, msg);
        }
        TuiEvent::Error(msg) => {
            state.done = true;
            state.error = true;
            state.push_log(LogLevel::Error, msg);
        }
        TuiEvent::RetryBegin { attempt } => {
            state.reset_for_attempt(attempt);
            // The operator's role selection survives the reset — keep the
            // selected-role line and the Setup phase stepper lit.
            if state.selected_role.is_some() {
                state.set_phase(Phase::Setup, PhaseStatus::Done);
            }
            state.push_log(
                LogLevel::Info,
                format!("attempt {attempt} — re-negotiating"),
            );
        }
        TuiEvent::Renegotiating { attempt, msg } => {
            state.renegotiating = true;
            state.renegotiating_msg = Some(msg.clone());
            state.attempt = Some(attempt);
            state.push_log(LogLevel::Warn, msg);
        }
        TuiEvent::SelectedRole(r) => {
            state.push_log(LogLevel::Info, format!("role selected: {r}"));
            state.selected_role = Some(r);
        }
        TuiEvent::TelegramChannel(available) => {
            state.telegram_available = available;
            if available {
                state.push_log(
                    LogLevel::Info,
                    "telegram channel ready — press [t] to switch address-exchange mode".into(),
                );
            }
        }
        TuiEvent::PeerRole(r) => {
            state.push_log(LogLevel::Info, format!("peer declared role: {r}"));
            state.peer_role = Some(r);
        }
        TuiEvent::Prompt { .. } => {}
        TuiEvent::Setup { .. } => {}
    }
}

/// The render loop. Owns the terminal until the pipeline signals `Done`/`Error`
/// or the user quits (`q`/Esc/Ctrl-C, which also sets `aborted` so the
/// pipeline stops).
///
/// `mode` is the shared exchange-mode flag (flipped by the `t` key); `aborted`
/// is set when the user quits outside a prompt.
pub fn run_render_loop(
    rx: mpsc::Receiver<TuiEvent>,
    mode: std::sync::Arc<std::sync::atomic::AtomicU8>,
    aborted: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<()> {
    // Terminal setup.
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut quit = false;
    loop {
        // Drain any pending events before drawing. A `Prompt` request is
        // handled inline (it blocks until the user submits/aborts); everything
        // else is folded into state.
        let mut state = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        state.tick = state.tick.wrapping_add(1);
        state.exchange_mode =
            ExchangeMode::from_bits(mode.load(std::sync::atomic::Ordering::Relaxed));
        while let Ok(ev) = rx.try_recv() {
            match ev {
                TuiEvent::Prompt { prompt, reply_tx } => {
                    drop(state); // release the lock while we touch the terminal
                    let available = terminal_state_telegram();
                    let outcome = prompt_editor(&mut terminal, &prompt, &mode, available);
                    let _ = reply_tx.send(outcome);
                    state = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
                }
                TuiEvent::Setup { form, reply_tx } => {
                    drop(state); // release the lock while we touch the terminal
                    let outcome = setup_screen(&mut terminal, form, &mode);
                    let _ = reply_tx.send(outcome);
                    state = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
                    // The screen is closed — the main rendering resumes.
                    state.setup_form = None;
                }
                other => apply_event(&mut state, other),
            }
        }
        drop(state);

        // Draw, then poll the terminal with a short timeout so we stay
        // responsive to keyboard input without busy-spinning.
        terminal.draw(draw)?;

        let key_event = match crossterm::event::poll(std::time::Duration::from_millis(60))? {
            true => event::read()?,
            false => continue,
        };
        if let Event::Key(key) = key_event {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            let quit_key = matches!(
                key.code,
                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc
            ) || ctrl_c(&key);
            if quit_key {
                // q / Esc / Ctrl-C: abort the run, not just the UI.
                if !terminal_state_done() {
                    aborted.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                quit = true;
            } else if matches!(key.code, KeyCode::Char('t') | KeyCode::Char('T'))
                && terminal_state_telegram()
                && !terminal_state_done()
            {
                let cur = ExchangeMode::from_bits(mode.load(std::sync::atomic::Ordering::Relaxed));
                let next = if cur == ExchangeMode::Telegram {
                    ExchangeMode::Manual
                } else {
                    ExchangeMode::Telegram
                };
                mode.store(next.to_bits(), std::sync::atomic::Ordering::Relaxed);
                let mut s = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
                s.exchange_mode = next;
                s.push_log(
                    LogLevel::Info,
                    format!("address exchange mode: {}", next.as_str()),
                );
            }
        }

        if quit || terminal_state_done() {
            break;
        }
    }

    // Restore the terminal even on the error path.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

/// Inline line editor used while a prompt is active. The UI keeps rendering
/// (the input is drawn at the bottom), so the user always sees what they are
/// typing. Keys: printable/space append, Backspace deletes, Enter submits,
/// `t` toggles the exchange mode (when Telegram is available), `q`/Esc/Ctrl-C
/// abort.
fn prompt_editor(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    prompt: &str,
    mode: &std::sync::Arc<std::sync::atomic::AtomicU8>,
    telegram_available: bool,
) -> PromptOutcome {
    let mut input = String::new();
    let outcome = loop {
        // Show the prompt + current input while we wait for the next key.
        {
            let mut s = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
            s.prompt = Some((prompt.to_string(), input.clone()));
        }
        if terminal.draw(draw).is_err() {
            break PromptOutcome::Aborted;
        }
        let key_event = match event::read() {
            Ok(e) => e,
            Err(_) => break PromptOutcome::Aborted,
        };
        let Event::Key(key) = key_event else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Enter => break PromptOutcome::Line(std::mem::take(&mut input)),
            KeyCode::Backspace => {
                input.pop();
            }
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                break PromptOutcome::Aborted;
            }
            KeyCode::Char('c') if ctrl_c(&key) => break PromptOutcome::Aborted,
            KeyCode::Char('t') | KeyCode::Char('T') if telegram_available => {
                let cur = ExchangeMode::from_bits(mode.load(std::sync::atomic::Ordering::Relaxed));
                let next = if cur == ExchangeMode::Telegram {
                    ExchangeMode::Manual
                } else {
                    ExchangeMode::Telegram
                };
                mode.store(next.to_bits(), std::sync::atomic::Ordering::Relaxed);
                break PromptOutcome::ModeToggled;
            }
            KeyCode::Char(c) if c.is_ascii_graphic() || c == ' ' => {
                input.push(c);
            }
            _ => {}
        }
    };
    // Clear the prompt line and reflect any mode change before the regular
    // render resumes.
    let mut s = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
    s.prompt = None;
    s.exchange_mode = ExchangeMode::from_bits(mode.load(std::sync::atomic::Ordering::Relaxed));
    outcome
}

// A process-lifetime state holder so the render loop and a (future) keyboard
// handler can share it. In this MVP the render loop is the only consumer, but
// keeping it behind a Mutex makes the design honest about ownership.
static STATE_GUARD: std::sync::LazyLock<std::sync::Mutex<TuiState>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(TuiState::default()));

fn terminal_state_done() -> bool {
    let s = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
    s.done
}

fn terminal_state_telegram() -> bool {
    let s = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
    s.telegram_available
}

/// True for a Ctrl-C key event (in raw mode the terminal does not translate
/// it to SIGINT; we handle it ourselves).
fn ctrl_c(key: &crossterm::event::KeyEvent) -> bool {
    key.code == crossterm::event::KeyCode::Char('c')
        && key
            .modifiers
            .contains(crossterm::event::KeyModifiers::CONTROL)
}

// ── Drawing ──────────────────────────────────────────────────────────────

fn draw(f: &mut Frame) {
    let state = STATE_GUARD
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let area = f.area();

    // The S1 setup screen is a full-area takeover while it is open.
    if let Some(form) = state.setup_form.as_ref() {
        draw_setup_screen(f, area, form, &state);
        return;
    }

    let prompt_active = state.prompt.is_some();

    // Four vertical regions: header, body (diagram + log), footer (the footer
    // grows by one line while a prompt is active, to host the input line).
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),                                 // header
            Constraint::Min(8),                                    // body
            Constraint::Min(1),                                    // footer hints
            Constraint::Length(if prompt_active { 1 } else { 0 }), // input line
        ])
        .split(area);

    draw_header(f, chunks[0], &state);
    draw_body(f, chunks[1], &state);
    draw_footer(f, chunks[2], &state);
    if prompt_active {
        draw_prompt_line(f, chunks[3], &state);
    }
}

// ── The S1 setup screen ──────────────────────────────────────────────────

/// Map a raw crossterm key event down to the form's plain [`FormKey`].
fn form_key(key: &crossterm::event::KeyEvent) -> FormKey {
    use crossterm::event::KeyCode;
    if ctrl_c(key) {
        return FormKey::CtrlC;
    }
    match key.code {
        KeyCode::Esc => FormKey::Esc,
        KeyCode::Left => FormKey::Left,
        KeyCode::Right => FormKey::Right,
        KeyCode::Up => FormKey::Up,
        KeyCode::Down => FormKey::Down,
        KeyCode::Tab => FormKey::Tab,
        KeyCode::Enter => FormKey::Enter,
        KeyCode::Backspace => FormKey::Backspace,
        KeyCode::Char(c) => FormKey::Char(c),
        _ => FormKey::Unhandled,
    }
}

/// The S1 setup screen's key loop. Blocks on keyboard input (like the prompt
/// editor), redraws on every keystroke, and returns the outcome.
fn setup_screen(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    mut form: crate::tui_state::SetupForm,
    _mode: &std::sync::Arc<std::sync::atomic::AtomicU8>,
) -> SetupOutcome {
    let outcome = loop {
        // Reflect the form in the shared state so the main draw (and the
        // footer) show it too.
        {
            let mut s = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
            s.setup_form = Some(form.clone());
        }
        if terminal.draw(draw).is_err() {
            break SetupOutcome::Abort;
        }
        let key_event = match event::read() {
            Ok(e) => e,
            Err(_) => break SetupOutcome::Abort,
        };
        let Event::Key(key) = key_event else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match form.apply(form_key(&key)) {
            crate::tui_state::FormKeyOutcome::Submit => match form.submit() {
                Ok(validated) => break SetupOutcome::Submit(validated),
                Err(err) => form.error = Some(err),
            },
            crate::tui_state::FormKeyOutcome::Abort => break SetupOutcome::Abort,
            _ => {}
        }
    };
    // Clear the form before the regular render resumes.
    {
        let mut s = STATE_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        s.setup_form = None;
    }
    outcome
}

/// Render the S1 setup screen. A focused, full-area screen — no stepper, no
/// diagram — the operator's job is to confirm the two settings.
fn draw_setup_screen(
    f: &mut Frame,
    area: Rect,
    form: &crate::tui_state::SetupForm,
    state: &TuiState,
) {
    let mut lines: Vec<Line> = Vec::new();

    // The role-conflict banner, if one is on the state.
    if let Some(conflict) = state.role_conflict.as_ref() {
        lines.push(Line::from(Span::styled(
            format!(" ⚠ {conflict} "),
            Style::default().yellow().bold(),
        )));
        lines.push(Line::from(""));
    }

    // The question.
    lines.push(Line::from(Span::styled(
        " which side are you?",
        Style::default().white().bold(),
    )));
    lines.push(Line::from(""));

    // The role picker.
    let role_focus = form.focused == SetupField::Role;
    let role_style = |selected: bool| {
        let mut s = if selected {
            Style::default().cyan().bold()
        } else {
            Style::default().dim()
        };
        if role_focus {
            s = s.add_modifier(ratatui::style::Modifier::UNDERLINED);
        }
        s
    };
    let client_sel = form.role == Some(crate::role::Role::Client);
    let server_sel = form.role == Some(crate::role::Role::Server);
    lines.push(Line::from(vec![
        Span::styled("  ◀ CLIENT ", role_style(client_sel)),
        Span::styled("    ", Style::default()),
        Span::styled("SERVER ▶  ", role_style(server_sel)),
        Span::styled(
            format!(
                "  (arrows, or {})",
                if role_focus { "c / s" } else { "Tab to field" }
            ),
            Style::default().dim(),
        ),
    ]));
    lines.push(Line::from(""));

    // The role-specific setting.
    let setting_focus = form.focused == SetupField::Setting;
    let setting_label = form.field_label();
    lines.push(Line::from(vec![Span::styled(
        format!("  {}", setting_label),
        if form.role.is_some() {
            if setting_focus {
                Style::default().white().bold()
            } else {
                Style::default().dim()
            }
        } else {
            Style::default().dim().italic()
        },
    )]));
    lines.push(Line::from(""));

    // The draft.
    let draft = form.focused_draft();
    let placeholder = form.draft_placeholder();
    let mut draft_spans = vec![Span::styled("  ▊ ", Style::default().cyan())];
    if draft.is_empty() && form.role.is_some() {
        draft_spans.push(Span::styled(
            placeholder.to_string(),
            Style::default().dim().italic(),
        ));
    } else if draft.is_empty() {
        draft_spans.push(Span::styled(
            "pick a role first",
            Style::default().dim().italic(),
        ));
    } else {
        draft_spans.push(Span::raw(draft.to_string()));
    }
    lines.push(Line::from(draft_spans));
    lines.push(Line::from(""));

    // The channel badge.
    let channel_badge = match form.channel {
        ExchangeMode::Telegram => "telegram (default)",
        ExchangeMode::Manual => "manual",
    };
    lines.push(Line::from(vec![
        Span::styled("  exchange  ", Style::default().dim()),
        Span::styled(channel_badge.to_string(), Style::default().bold()),
        if form.telegram_available {
            Span::styled("  [t] toggle", Style::default().dim())
        } else {
            Span::raw("  (no Telegram channel)")
        },
    ]));
    lines.push(Line::from(""));

    // The error line (the form's validation message).
    if let Some(err) = form.error.as_ref() {
        lines.push(Line::from(Span::styled(
            format!("  ✗ {err}"),
            Style::default().red().bold(),
        )));
        lines.push(Line::from(""));
    }

    // The hint bar.
    lines.push(Line::from(Span::styled(
        "  ←/→ or c/s role · Tab next field · Enter submit · q/Esc abort",
        Style::default().dark_gray().italic(),
    )));

    // Borders + padding included, so nothing is clipped.
    let content_h = lines.len() + 4;
    let height = content_h.min(area.height.saturating_sub(2) as usize).max(4);
    let centered = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(height as u16),
            Constraint::Fill(1),
        ])
        .split(area)[1];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(state))
        .title(" setup — this only runs once per run ")
        .padding(ratatui::widgets::Padding::new(1, 0, 1, 1));
    f.render_widget(Paragraph::new(lines).block(block), centered);
}

/// The prompt + live input line, drawn at the very bottom while a prompt is
/// active. The area is one line tall; the input follows the prompt text with
/// a blinking cursor. (ratatui clips overlong content at character
/// boundaries, so no manual truncation is needed.)
fn draw_prompt_line(f: &mut Frame, area: Rect, state: &TuiState) {
    let (prompt, input) = state.prompt.as_ref().expect("checked by draw");
    let cursor = if state.tick.is_multiple_of(2) {
        "▏"
    } else {
        " "
    };
    let line = Line::from(vec![
        Span::styled(" › ", Style::default().cyan().bold()),
        Span::styled(prompt.clone(), Style::default().bold()),
        Span::raw(input.clone()),
        Span::styled(cursor.to_string(), Style::default().cyan()),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_header(f: &mut Frame, area: Rect, state: &TuiState) {
    let attempt = state
        .attempt
        .filter(|&n| n >= 2)
        .map(|n| format!(" · attempt {n}"))
        .unwrap_or_default();
    let title = match (state.done, state.error) {
        (true, true) => Line::from(Span::styled(
            format!(" p2p-tunnel{attempt}  —  ERROR "),
            Style::default().red().bold(),
        )),
        (true, false) => Line::from(Span::styled(
            format!(" p2p-tunnel{attempt}  —  CLOSED "),
            Style::default().green().bold(),
        )),
        _ if state.ready => Line::from(Span::styled(
            format!(" p2p-tunnel{attempt}  —  CONNECTED "),
            Style::default().cyan().bold(),
        )),
        _ if state.renegotiating => {
            let n = state.attempt.unwrap_or(1);
            Line::from(Span::styled(
                format!(" p2p-tunnel  —  RE-NEGOTIATING (attempt {n}) "),
                Style::default().red().bold(),
            ))
        }
        _ => Line::from(Span::styled(
            format!(" p2p-tunnel{attempt} "),
            Style::default().cyan().bold(),
        )),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(state))
        .title(title);
    f.render_widget(block, area);
}

fn draw_body(f: &mut Frame, area: Rect, state: &TuiState) {
    let cols = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6), // phase stepper
            Constraint::Length(8), // connection diagram
            Constraint::Min(3),    // event log
        ])
        .split(area);

    draw_phase_stepper(f, cols[0], state);
    draw_diagram(f, cols[1], state);
    draw_log(f, cols[2], state);
}

fn draw_phase_stepper(f: &mut Frame, area: Rect, state: &TuiState) {
    let phases = [
        (Phase::Setup, "SETUP"),
        (Phase::Stun, "STUN"),
        (Phase::Exchange, "EXCHANGE"),
        (Phase::Punch, "PUNCH"),
        (Phase::RoleCheck, "ROLE CHECK"),
        (Phase::Quic, "QUIC"),
        (Phase::Tunnel, "TUNNEL"),
    ];
    let mut spans = Vec::new();
    for (i, (phase, label)) in phases.iter().enumerate() {
        let status = state.status(*phase);
        let (icon, style) = match status {
            PhaseStatus::Done => ("✓", Style::default().green()),
            PhaseStatus::Active => {
                let c = spinner_char(state.tick);
                (c, Style::default().yellow().bold())
            }
            PhaseStatus::Pending => ("·", Style::default().dim()),
            PhaseStatus::Error => ("✗", Style::default().red()),
            PhaseStatus::Skipped => ("—", Style::default().dim()),
        };
        if i > 0 {
            spans.push(Span::styled(" ── ", Style::default().dark_gray()));
        }
        spans.push(Span::styled(format!("{icon} {label}"), style));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(state))
        .title(" lifecycle ");
    f.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

fn draw_diagram(f: &mut Frame, area: Rect, state: &TuiState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(state))
        .title(" connection ");
    let lines = vec![
        Line::from(vec![
            Span::styled(" you  ", Style::default().cyan().bold()),
            Span::raw(
                state
                    .own_addr
                    .clone()
                    .unwrap_or_else(|| "discovering…".into()),
            ),
        ]),
        Line::from(vec![
            Span::styled(" peer ", Style::default().magenta().bold()),
            Span::raw(state.peer_addr.clone().unwrap_or_else(|| "—".into())),
        ]),
        Line::from(vec![
            Span::styled("roles ", Style::default().dim()),
            Span::styled(
                state.selected_role.as_deref().unwrap_or("—"),
                Style::default().cyan().bold(),
            ),
            Span::raw(" · "),
            Span::styled(
                state.peer_role.as_deref().unwrap_or("—"),
                Style::default().magenta().bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled("via  ", Style::default().dim()),
            Span::raw(state.exchange_mode.as_str()),
            if state.telegram_available {
                Span::styled("  [t]", Style::default().dim())
            } else {
                Span::raw("")
            },
        ]),
        Line::from(vec![
            Span::styled(port_label(state), Style::default().dim()),
            Span::raw(port_value(state)),
        ]),
        Line::from(vec![
            Span::styled(" cert ", Style::default().dim()),
            Span::raw(shorten(
                &state.fingerprint.clone().unwrap_or_default(),
                area.width as usize,
            )),
        ]),
    ];
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Label for the role-specific setting line: "port" for a client (the local
/// TCP listener), "serve" for a server (the exposed service address).
fn port_label(state: &TuiState) -> &'static str {
    match state.selected_role.as_deref() {
        Some("server") => " serve",
        _ => " port ",
    }
}

/// Value for the role-specific setting line.
fn port_value(state: &TuiState) -> String {
    match state.selected_role.as_deref() {
        Some("server") => state.target.clone().unwrap_or_else(|| "—".into()),
        _ => state
            .local_port
            .map(|p| format!("127.0.0.1:{p}"))
            .unwrap_or_else(|| "—".into()),
    }
}

fn draw_log(f: &mut Frame, area: Rect, state: &TuiState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style(state))
        .title(" events ");

    let items: Vec<ListItem> = state
        .logs
        .iter()
        .map(|(level, msg)| {
            let style = match level {
                LogLevel::Error => Style::default().red(),
                LogLevel::Warn => Style::default().yellow(),
                LogLevel::Debug => Style::default().dim(),
                LogLevel::Info => Style::default(),
            };
            ListItem::new(Line::from(Span::styled(msg.clone(), style)))
        })
        .collect();

    let list = List::new(items).block(block);
    let mut state_box = ListState::default();
    // Selecting the last item scrolls the list so the newest line is visible.
    state_box.select(if state.logs.is_empty() {
        None
    } else {
        Some(state.logs.len() - 1)
    });
    f.render_stateful_widget(list, area, &mut state_box);
}

fn draw_footer(f: &mut Frame, area: Rect, state: &TuiState) {
    let left = if state.renegotiating {
        format!(
            " re-negotiating — {} ",
            state.renegotiating_msg.as_deref().unwrap_or("tunnel down")
        )
    } else if state.done {
        String::from(" session ended ")
    } else if state.ready {
        String::from(" CONNECTED — traffic flowing ")
    } else if state.telegram_available {
        format!(
            " [{}: {}]",
            phase_label(state.active_phase()),
            state.exchange_mode.as_str()
        )
    } else {
        format!(" working on: {} ", phase_label(state.active_phase()))
    };
    let right = if state.renegotiating {
        String::from(" q to quit ")
    } else if state.done {
        String::from(" q to close ")
    } else if state.ready {
        String::from(" q to tear down ")
    } else {
        // Offer the mode toggle only while a working Telegram channel exists
        // and the address exchange is not over.
        if state.telegram_available && state.peer_addr.is_none() {
            String::from(" [t] toggle mode · q to abort ")
        } else {
            String::from(" q to abort ")
        }
    };
    let line = Line::from(vec![
        Span::styled(left, Style::default().dark_gray().italic()),
        Span::raw("   "),
        Span::styled(right, Style::default().dark_gray().italic()),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn border_style(state: &TuiState) -> Style {
    match (state.done, state.error) {
        (_, true) => Style::default().red(),
        (true, _) => Style::default().green(),
        _ if state.ready => Style::default().cyan(),
        _ => Style::default().dark_gray(),
    }
}

fn phase_label(phase: Phase) -> &'static str {
    match phase {
        Phase::Setup => "setup",
        Phase::Stun => "STUN discovery",
        Phase::Exchange => "address exchange",
        Phase::Punch => "hole punching",
        Phase::RoleCheck => "role cross-check",
        Phase::Quic => "QUIC handshake",
        Phase::Tunnel => "tunneling",
    }
}

/// Advance a 4-frame braille spinner based on a tick counter.
fn spinner_char(tick: u32) -> &'static str {
    match tick % 4 {
        0 => "⠋",
        1 => "⠙",
        2 => "⠹",
        3 => "⠸",
        _ => "⠋",
    }
}

/// Truncate a string to `max` chars (used for the fingerprint in narrow panes).
fn shorten(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.is_empty() {
        return "—".into();
    }
    if s.len() <= max {
        return s.to_string();
    }
    // Show a head…tail slice so both ends are visible.
    let keep = max.saturating_sub(1).max(8);
    let head = s.get(..(keep / 2).max(4)).unwrap_or(s);
    let tail = s
        .get(s.len().saturating_sub(keep / 2).max(4)..)
        .unwrap_or("");
    format!("{head}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renegotiating_event_sets_upcoming_attempt_and_renegotiating() {
        let mut s = TuiState::default();
        apply_event(
            &mut s,
            TuiEvent::Renegotiating {
                attempt: 3,
                msg: "boom".into(),
            },
        );
        assert!(s.renegotiating);
        assert_eq!(s.renegotiating_msg.as_deref(), Some("boom"));
        assert_eq!(s.attempt, Some(3));
    }
}
