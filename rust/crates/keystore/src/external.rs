//! External approver — an approval gate that asks another program.
//!
//! A headless agent (a CI job, a cron task, a server process) has no screen
//! for Touch ID, Windows Hello or polkit. Instead of failing every payment,
//! the account owner can name a program that decides: it might page a phone,
//! post to a chat, or check a dashboard. pay writes the request to the
//! program's stdin as JSON and reads one answer: exit status `0` approves,
//! anything else denies.
//!
//! The gate fails closed. A program that cannot start, exits non-zero, is
//! killed by a signal or does not answer within the timeout is a denial. The
//! timeout covers delivering the request as well as the answer, and a
//! timed-out program is killed and reaped, along with any helpers it started
//! on Unix, so it cannot keep a request open.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::{AuthGate, AuthIntent, Error, Result};

/// How long an approver may take when the account does not say.
pub const DEFAULT_APPROVER_TIMEOUT: Duration = Duration::from_secs(120);

/// Version of the JSON request written to the approver's stdin.
pub const APPROVER_REQUEST_VERSION: u32 = 1;

const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// An [`AuthGate`] that delegates the decision to an external program.
#[derive(Debug, Clone)]
pub struct ExternalApprover {
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
}

impl ExternalApprover {
    pub fn new(program: impl Into<PathBuf>, args: Vec<String>, timeout: Duration) -> Self {
        Self {
            program: program.into(),
            args,
            timeout,
        }
    }

    /// The JSON document the approver receives on stdin.
    pub fn request_json(intent: &AuthIntent) -> String {
        serde_json::json!({
            "version": APPROVER_REQUEST_VERSION,
            "kind": intent_kind(intent),
            "message": intent.message(),
            "amount_minor_units": intent.amount_minor_units(),
            "moves_money": intent.moves_money(),
            "recurring": intent.is_recurring(),
        })
        .to_string()
    }

    fn name(&self) -> String {
        self.program.display().to_string()
    }

    /// Run the approver on `request` and decide from its exit status.
    fn run(&self, request: Vec<u8>) -> Result<()> {
        // Checked before spawning, so a timeout too large to represent never
        // starts a program it could not bound.
        let deadline = Instant::now().checked_add(self.timeout).ok_or_else(|| {
            Error::AuthDenied(format!(
                "approver `{}` timeout of {}s is too large",
                self.name(),
                self.timeout.as_secs()
            ))
        })?;

        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        // Its own process group, so a timeout can kill helpers it started too.
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let mut child = command.spawn().map_err(|e| {
            Error::AuthDenied(format!("approver `{}` could not start: {e}", self.name()))
        })?;

        if let Some(mut stdin) = child.stdin.take() {
            // Written on its own thread so the deadline also covers delivery:
            // an approver that holds stdin open without reading cannot stall
            // us on a full pipe. Killing it closes the pipe and ends the
            // thread. An approver may decide without reading the request; a
            // closed pipe is not an error, its exit status still decides.
            let writer = std::thread::Builder::new()
                .name("pay-approver-stdin".into())
                .spawn(move || {
                    let _ = stdin.write_all(&request);
                });
            if let Err(e) = writer {
                kill_tree(&mut child);
                return Err(Error::AuthDenied(format!(
                    "approver `{}` could not be sent the request: {e}",
                    self.name()
                )));
            }
        }

        let status = self.wait_until(&mut child, deadline)?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::AuthDenied(format!(
                "approver `{}` declined ({status})",
                self.name()
            )))
        }
    }

    fn wait_until(&self, child: &mut Child, deadline: Instant) -> Result<ExitStatus> {
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                kill_tree(child);
                return Err(Error::AuthDenied(format!(
                    "approver `{}` did not answer within {}s",
                    self.name(),
                    self.timeout.as_secs()
                )));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

/// Kill the approver and every process in its group, then reap it.
fn kill_tree(child: &mut Child) {
    #[cfg(unix)]
    if let Ok(pid) = libc::pid_t::try_from(child.id()) {
        // SAFETY: kill(2) takes no pointers. The child is not reaped yet, so
        // its pid, and the process group it leads, cannot have been reused.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

impl AuthGate for ExternalApprover {
    fn authenticate(&self, intent: &AuthIntent) -> Result<()> {
        self.run(Self::request_json(intent).into_bytes())
    }

    fn is_available(&self) -> bool {
        resolve_program(&self.program).is_some()
    }
}

fn intent_kind(intent: &AuthIntent) -> &'static str {
    match intent {
        AuthIntent::AuthorizePayment { .. } => "authorize_payment",
        AuthIntent::AuthorizeBatch { .. } => "authorize_batch",
        AuthIntent::CreateAccount(_) => "create_account",
        AuthIntent::ImportAccount(_) => "import_account",
        AuthIntent::ExportAccount(_) => "export_account",
        AuthIntent::DeleteAccount(_) => "delete_account",
        AuthIntent::OpenSession(_) => "open_session",
        AuthIntent::UseGatewayFeePayer(_) => "use_gateway_fee_payer",
        AuthIntent::UseAccount(_) => "use_account",
    }
}

/// The program as it would be run: a path with a separator is taken as is,
/// a bare name is looked up on `PATH`.
fn resolve_program(program: &Path) -> Option<PathBuf> {
    if program.components().count() > 1 {
        return program.is_file().then(|| program.to_path_buf());
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &tempfile::TempDir, name: &str, body: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn payment() -> AuthIntent {
        AuthIntent::authorize_payment_details("$0.05", "accessing API", "api.example.com")
    }

    fn gate(program: PathBuf, timeout: Duration) -> ExternalApprover {
        ExternalApprover::new(program, Vec::new(), timeout)
    }

    #[test]
    fn exit_zero_approves() {
        let dir = tempfile::tempdir().unwrap();
        let approver = gate(
            script(&dir, "yes.sh", "cat >/dev/null; exit 0"),
            DEFAULT_APPROVER_TIMEOUT,
        );
        assert!(approver.authenticate(&payment()).is_ok());
    }

    #[test]
    fn non_zero_exit_denies() {
        let dir = tempfile::tempdir().unwrap();
        let approver = gate(script(&dir, "no.sh", "exit 1"), DEFAULT_APPROVER_TIMEOUT);
        let err = approver.authenticate(&payment()).unwrap_err();
        assert!(matches!(err, Error::AuthDenied(m) if m.contains("declined")));
    }

    #[test]
    fn killed_approver_denies() {
        let dir = tempfile::tempdir().unwrap();
        let approver = gate(
            script(&dir, "crash.sh", "kill -9 $$"),
            DEFAULT_APPROVER_TIMEOUT,
        );
        assert!(matches!(
            approver.authenticate(&payment()),
            Err(Error::AuthDenied(_))
        ));
    }

    #[test]
    fn timeout_denies_and_kills_the_child() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let body = format!("echo $$ > {}; exec sleep 30", pid_file.display());
        let approver = gate(script(&dir, "slow.sh", &body), Duration::from_millis(300));

        let started = Instant::now();
        let err = approver.authenticate(&payment()).unwrap_err();
        assert!(matches!(err, Error::AuthDenied(m) if m.contains("did not answer")));
        assert!(started.elapsed() < Duration::from_secs(5));

        let pid = std::fs::read_to_string(&pid_file).unwrap();
        assert!(gone(pid.trim()), "timed-out approver must be killed");
    }

    #[test]
    fn timeout_kills_helpers_the_approver_started() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("helper-pid");
        // No `exec`: the shell waits on a separate helper process.
        let body = format!("sleep 30 & echo $! > {}; wait", pid_file.display());
        let approver = gate(script(&dir, "helper.sh", &body), Duration::from_millis(300));

        let err = approver.authenticate(&payment()).unwrap_err();
        assert!(matches!(err, Error::AuthDenied(m) if m.contains("did not answer")));

        let pid = std::fs::read_to_string(&pid_file).unwrap();
        assert!(
            gone(pid.trim()),
            "helper of a timed-out approver must be killed"
        );
    }

    #[test]
    fn timeout_covers_a_request_the_approver_never_reads() {
        let dir = tempfile::tempdir().unwrap();
        // Holds stdin open and never reads it, so a large request fills the pipe.
        let approver = gate(
            script(&dir, "deaf.sh", "exec sleep 30"),
            Duration::from_millis(300),
        );

        let started = Instant::now();
        let err = approver.run(vec![b'x'; 4 << 20]).unwrap_err();
        assert!(matches!(err, Error::AuthDenied(m) if m.contains("did not answer")));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn oversized_timeout_denies_without_starting_the_approver() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let body = format!("touch {}; exit 0", marker.display());
        let approver = gate(script(&dir, "never.sh", &body), Duration::MAX);

        let err = approver.authenticate(&payment()).unwrap_err();
        assert!(matches!(err, Error::AuthDenied(m) if m.contains("too large")));
        assert!(!marker.exists(), "approver must not start");
    }

    /// Whether `pid` is gone within a couple of seconds. A killed helper is
    /// reparented and reaped by init, which is not instant.
    fn gone(pid: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let alive = Command::new("kill")
                .args(["-0", pid])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success();
            if !alive {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn missing_program_denies_and_is_unavailable() {
        let approver = gate(
            PathBuf::from("/nonexistent/pay-approver"),
            DEFAULT_APPROVER_TIMEOUT,
        );
        assert!(!approver.is_available());
        let err = approver.authenticate(&payment()).unwrap_err();
        assert!(matches!(err, Error::AuthDenied(m) if m.contains("could not start")));
    }

    #[test]
    fn existing_program_is_available() {
        let dir = tempfile::tempdir().unwrap();
        let approver = gate(script(&dir, "ok.sh", "exit 0"), DEFAULT_APPROVER_TIMEOUT);
        assert!(approver.is_available());
    }

    #[test]
    fn approver_receives_the_request_on_stdin() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("request.json");
        let body = format!("cat > {}; exit 0", out.display());
        let approver = gate(script(&dir, "record.sh", &body), DEFAULT_APPROVER_TIMEOUT);
        approver.authenticate(&payment()).unwrap();

        let request: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(request["version"], APPROVER_REQUEST_VERSION);
        assert_eq!(request["kind"], "authorize_payment");
        assert_eq!(request["amount_minor_units"], 500);
        assert_eq!(request["moves_money"], true);
        assert_eq!(request["recurring"], false);
        assert!(
            request["message"]
                .as_str()
                .unwrap()
                .contains("api.example.com")
        );
    }

    #[test]
    fn non_payment_intents_carry_no_amount() {
        let request: serde_json::Value = serde_json::from_str(&ExternalApprover::request_json(
            &AuthIntent::export_account("main"),
        ))
        .unwrap();
        assert_eq!(request["kind"], "export_account");
        assert!(request["amount_minor_units"].is_null());
        assert_eq!(request["moves_money"], false);
    }
}
