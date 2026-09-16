//! Lifecycle smoke tests over a real terminal.
//!
//! Everything else about the TUI is covered by unit tests and golden frames;
//! these two flows exist because only a real PTY can prove the parts that go
//! wrong silently: the first frame actually paints, a resize re-lays out, a
//! too-small terminal says so, and every exit path gives the terminal back.
//!
//! Unix only: the interrupt flow writes a raw Ctrl+C byte, and that is only the
//! interrupt key where the terminal is not translating it into a signal.

#![cfg(all(feature = "tui", unix))]

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, Child, CommandBuilder, PtySize};

/// Generous enough for a slow machine, short enough to fail rather than hang.
const TIMEOUT: Duration = Duration::from_secs(20);
/// How often the readers look for the text they are waiting on.
const POLL_INTERVAL: Duration = Duration::from_millis(20);
/// The alternate screen's enter and leave sequences, as drawn by Crossterm.
const ENTER_ALT_SCREEN: &str = "\u{1b}[?1049h";
const LEAVE_ALT_SCREEN: &str = "\u{1b}[?1049l";

/// A spawned TUI, killed if the test leaves it behind.
struct Session {
    child: Box<dyn Child + Send + Sync>,
    writer: Box<dyn Write + Send>,
    output: Arc<Mutex<Vec<u8>>>,
    master: Box<dyn portable_pty::MasterPty + Send>,
}

impl Session {
    fn start(columns: u16, rows: u16) -> Self {
        let pty = native_pty_system();
        let pair = pty
            .openpty(PtySize {
                rows,
                cols: columns,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("a pty opens");

        let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_flx"));
        command.args(["grab", "--tui", "--offline", "--no-config"]);
        // Crossterm needs a terminfo entry to emit the right sequences.
        command.env("TERM", "xterm-256color");
        // Pin the locale so the glyph set is deterministic, and keep the run
        // away from any version check or user cache.
        command.env("LANG", "en_US.UTF-8");
        command.env("LC_ALL", "en_US.UTF-8");
        command.env("NO_COLOR", "1");

        let child = pair
            .slave
            .spawn_command(command)
            .expect("the flx binary spawns");
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().expect("the pty is readable");
        let writer = pair.master.take_writer().expect("the pty is writable");
        let output = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&output);
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                sink.lock()
                    .expect("the sink is not poisoned")
                    .extend_from_slice(&buffer[..read]);
            }
        });

        Self {
            child,
            writer,
            output,
            master: pair.master,
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).expect("the pty accepts input");
        self.writer.flush().expect("the pty flushes");
    }

    fn resize(&mut self, columns: u16, rows: u16) {
        self.master
            .resize(PtySize {
                rows,
                cols: columns,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("the pty resizes");
    }

    /// Everything the child has written so far, as lossy UTF-8.
    fn seen(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().expect("the sink is not poisoned")).into_owned()
    }

    /// The end of the output, for failure messages that stay readable.
    ///
    /// The raw stream is cursor-positioned and style-delimited, so matching a
    /// whole phrase is not possible; every assertion here looks for a single
    /// run-free token, and prints this tail when it is missing.
    fn tail(&self) -> String {
        let seen = self.seen();
        let start = seen.len().saturating_sub(400);
        seen[start..].to_owned()
    }

    /// Waits for `needle`, returning whether it arrived before the deadline.
    fn wait_for(&self, needle: &str) -> bool {
        let deadline = Instant::now() + TIMEOUT;
        while Instant::now() < deadline {
            if self.seen().contains(needle) {
                return true;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        self.seen().contains(needle)
    }

    /// Waits until the child has emitted more output than before a resize.
    fn wait_for_output_after(&self, previous_length: usize) -> bool {
        let deadline = Instant::now() + TIMEOUT;
        while Instant::now() < deadline {
            if self.seen().len() > previous_length {
                return true;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        self.seen().len() > previous_length
    }

    /// Waits for the child to exit, returning its code.
    fn exit_code(&mut self) -> Option<u32> {
        let deadline = Instant::now() + TIMEOUT;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status.exit_code());
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        None
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Never leave a killed-but-unreaped TUI behind on a failed assertion.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_run_paints_immediately_survives_a_resize_and_quits_cleanly() {
    let mut session = Session::start(80, 24);

    assert!(
        session.wait_for("grab"),
        "the first frame must paint without waiting for an event; tail: {:?}",
        session.tail()
    );
    assert!(
        session.seen().contains(ENTER_ALT_SCREEN),
        "a full-screen session takes the alternate screen"
    );

    // A resize must re-lay out rather than corrupt or blank the screen.
    let before_resize = session.seen().len();
    session.resize(140, 30);
    assert!(
        session.wait_for_output_after(before_resize),
        "the single-pane table redraws after resize; tail: {:?}",
        session.tail()
    );

    session.send(b"\x03");
    std::thread::sleep(Duration::from_millis(200));
    session.send(b"\x03");
    assert_eq!(
        session.exit_code(),
        Some(0),
        "quitting is a clean exit; tail: {:?}",
        session.tail()
    );
    let seen = session.seen();
    assert!(
        seen.contains(LEAVE_ALT_SCREEN),
        "the alternate screen must be given back"
    );
    assert!(
        !seen.contains("panicked"),
        "the run must not panic; tail: {:?}",
        session.tail()
    );
}

#[test]
fn a_small_terminal_says_so_and_ctrl_c_still_leaves_cleanly() {
    // Below the supported 60x12 minimum.
    let mut session = Session::start(40, 10);

    // The message is "terminal too small — need 60×12"; the spaces between the
    // words never reach the stream, so the tokens are checked on their own.
    assert!(
        session.wait_for("terminal"),
        "the minimum is enforced with a message; tail: {:?}",
        session.tail()
    );
    assert!(
        session.seen().contains("60\u{d7}12"),
        "the message names the minimum it needs; tail: {:?}",
        session.tail()
    );

    // Ctrl+C stops the run; a second press leaves.
    session.send(b"\x03");
    std::thread::sleep(Duration::from_millis(200));
    session.send(b"\x03");

    assert_eq!(
        session.exit_code(),
        Some(0),
        "an interrupted run still exits cleanly; tail: {:?}",
        session.tail()
    );
    let seen = session.seen();
    assert!(
        seen.contains(LEAVE_ALT_SCREEN),
        "the alternate screen must be given back after an interrupt"
    );
    assert!(
        !seen.contains("panicked"),
        "the interrupt path must not panic; tail: {:?}",
        session.tail()
    );
}
