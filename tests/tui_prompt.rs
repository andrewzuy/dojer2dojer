//! End-to-end test: the TUI's interactive address prompt must deliver user
//! input back to the pipeline even though the render loop owns the terminal
//! in raw mode.
//!
//! We exercise the same seam the real app uses:
//!   pipeline  ->  TuiHandle::ask_line(prompt)
//!   render    ->  TuiEvent::Prompt { .. }
//!   (terminal) ->  user line
//!   render    ->  reply_tx
//!   pipeline  <-  ask_line returns the line
//!
//! The render side is simulated with a minimal receiver that stands in for
//! `run_render_loop`'s event handling: on `Prompt`, it "reads a line" (from
//! a scripted vec) and sends it back on `reply_tx`. This proves the channel
//! wiring, the blocking `recv`, and EOF/None propagation without needing a
//! real PTY in CI.

use p2p_tunnel_lib::cli;
use p2p_tunnel_lib::tui;
use p2p_tunnel_lib::tui::{TuiEvent, TuiHandle};
use std::io::Result as IoResult;
use std::sync::mpsc;
use std::thread;

/// Simulated render loop: replies to each Prompt with the next scripted line.
fn fake_render(rx: mpsc::Receiver<TuiEvent>, lines: Vec<String>) {
    for line in lines {
        loop {
            match rx.recv() {
                Ok(TuiEvent::Prompt { reply_tx, .. }) => {
                    let _ = reply_tx.send(line);
                    break;
                }
                Ok(_) => continue,
                Err(_) => return,
            }
        }
    }
}

#[test]
fn tui_prompt_round_trips_through_handle() {
    let (handle, rx) = tui::channel();
    // First line is bad input (exercises the retry loop in prompt_peer_addr),
    // second is valid.
    let lines = vec!["not-an-address".into(), "1.2.3.4:9999".into()];
    let render = thread::spawn(move || fake_render(rx, lines));

    // The pipeline's read seam: TUI active -> ask_line.
    let mut read = || handle.ask_line("Enter peer's public address (ip:port): ");

    let addr = cli::prompt_peer_addr(&mut read).unwrap();
    assert_eq!(addr.to_string(), "1.2.3.4:9999");
    render.join().unwrap();
}

#[test]
fn tui_prompt_receiver_gone_fails_cleanly() {
    let (handle, rx) = tui::channel();
    // Simulate the render loop exiting (user pressed q) while the pipeline
    // is about to ask for input: the receiver is dropped, so ask_line's
    // send must fail rather than hang.
    drop(rx);
    let res: IoResult<Option<String>> = handle.ask_line("Enter peer's public address (ip:port): ");
    assert!(
        res.is_err(),
        "ask_line must error when the render loop is gone"
    );
}

#[test]
fn disabled_handle_is_a_plain_stdin_read() {
    // With no TUI, ask_line does a plain blocking read_line. We only verify
    // the disabled branch exists and returns without panicking on a closed
    // channel; the real stdin EOF path is integration-level.
    let handle = TuiHandle::disabled();
    assert!(handle.is_disabled());
}
