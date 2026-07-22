//! Killable, resource-limited artifact compilation in a child process.
//!
//! Fuel, epoch interruption, and Store limits bound *guest execution*, but
//! they do not bound Cranelift compilation, JIT code allocation, or embedder
//! memory (RFC 0002 §"Invocation and Cache TOCTOU Rules" and the compilation
//! threat surface). A hostile module can therefore try to exhaust the parent
//! purely by being compiled. This moves `Module::from_binary` — the compile —
//! into a short-lived worker process the parent can cap and kill:
//!
//! - the parent sends the module bytes together with their expected digest;
//!   the worker rehashes before compiling, so a byte substitution in transit
//!   is detected as substitution, not treated as a cache miss;
//! - on Unix the worker runs under an address-space rlimit, so a
//!   compile-time memory blow-up kills the worker, not the parent;
//! - the parent enforces a wall-clock deadline and kills the worker if it is
//!   exceeded; a crashed, killed, non-zero, or malformed worker fails closed.
//!
//! The worker returns the wasmtime-serialized module; the parent deserializes
//! it with its own engine. The bytes come from the parent's own trusted
//! worker this run — the untrusted on-disk compiled cache (which needs a
//! signed cache record before `deserialize`) is a separate, later boundary.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use wasmtime::{Engine, Module};

use sovereign_artifact::Digest;

use crate::SandboxError;

/// How the parent launches its compilation worker: a program plus arguments
/// that re-enter this crate's [`run_compile_worker`] (for the single-binary
/// CLI, its own path plus a hidden subcommand).
#[derive(Debug, Clone)]
pub struct CompileWorker {
    program: PathBuf,
    args: Vec<String>,
    /// Address-space ceiling for the worker (Unix `RLIMIT_AS`).
    address_space_limit_bytes: u64,
    /// Wall-clock deadline before the worker is killed.
    timeout: Duration,
}

impl CompileWorker {
    /// A worker launched as `program args...`. The invoked program must read a
    /// compile request on stdin and write the serialized module to stdout via
    /// [`run_compile_worker`].
    pub fn new(program: impl Into<PathBuf>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            address_space_limit_bytes: 1024 * 1024 * 1024,
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_address_space_limit_bytes(mut self, bytes: u64) -> Self {
        self.address_space_limit_bytes = bytes;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Compile `bytes` in the worker and deserialize the result with `engine`.
    /// Fails closed on digest mismatch, worker crash/non-zero exit, timeout, or
    /// malformed output.
    pub(crate) fn compile(&self, engine: &Engine, bytes: &[u8]) -> Result<Module, SandboxError> {
        let expected = Digest::of_bytes(bytes);
        let serialized = self.run(bytes, &expected)?;
        // SAFETY: `serialized` is produced this run by the parent's own trusted
        // worker from digest-verified source bytes and never read from an
        // untrusted on-disk cache; deserializing it is equivalent to the
        // in-process `Module::from_binary` it replaces.
        unsafe { Module::deserialize(engine, &serialized) }
            .map_err(|error| SandboxError::CompileWorkerFailed(error.to_string()))
    }

    fn run(&self, bytes: &[u8], expected: &Digest) -> Result<Vec<u8>, SandboxError> {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        self.apply_rlimit(&mut command);

        let mut child = command
            .spawn()
            .map_err(|error| SandboxError::CompileWorkerFailed(format!("spawn: {error}")))?;

        // Frame the request as digest(32) || module bytes. Write from a thread
        // and drain stdout from another so a large module cannot deadlock on a
        // full pipe while the parent waits.
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| SandboxError::CompileWorkerFailed("no worker stdin".into()))?;
        let request: Vec<u8> = expected
            .as_bytes()
            .iter()
            .copied()
            .chain(bytes.iter().copied())
            .collect();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&request);
            // stdin drops here, signalling EOF to the worker.
        });

        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| SandboxError::CompileWorkerFailed("no worker stdout".into()))?;
        let (tx, rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let outcome = stdout.read_to_end(&mut buffer).map(move |_| buffer);
            let _ = tx.send(outcome);
        });

        // Enforce the deadline: poll for exit, kill on timeout.
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = writer.join();
                        let _ = reader.join();
                        return Err(SandboxError::CompileWorkerTimeout);
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => {
                    let _ = child.kill();
                    return Err(SandboxError::CompileWorkerFailed(format!("wait: {error}")));
                }
            }
        };

        let _ = writer.join();
        let _ = reader.join();
        let serialized = rx
            .recv()
            .map_err(|_| SandboxError::CompileWorkerFailed("reader thread dropped".into()))?
            .map_err(|error| SandboxError::CompileWorkerFailed(format!("read: {error}")))?;

        if !status.success() {
            return Err(SandboxError::CompileWorkerFailed(format!(
                "worker exited with {status}"
            )));
        }
        if serialized.is_empty() {
            return Err(SandboxError::CompileWorkerFailed(
                "empty worker output".into(),
            ));
        }
        Ok(serialized)
    }

    #[cfg(unix)]
    fn apply_rlimit(&self, command: &mut Command) {
        use std::os::unix::process::CommandExt;
        let limit = self.address_space_limit_bytes;
        // SAFETY: pre_exec runs in the forked child before exec; setrlimit is
        // async-signal-safe and touches only the child's own limits.
        unsafe {
            command.pre_exec(move || {
                let rlim = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                if libc::setrlimit(libc::RLIMIT_AS, &rlim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    #[cfg(not(unix))]
    fn apply_rlimit(&self, _command: &mut Command) {
        // No portable address-space rlimit off Unix; the wall-clock deadline
        // and kill still bound the worker.
    }
}

/// Worker entry point: read one compile request from `reader`, write the
/// serialized module to `writer`, and return the process exit code. The
/// embedder wires this to a hidden subcommand of its own binary. Any failure
/// — short read, digest mismatch, invalid module — is a non-zero exit and no
/// output, which the parent treats as fail-closed.
pub fn run_compile_worker(mut reader: impl Read, mut writer: impl Write) -> u8 {
    let mut input = Vec::new();
    if reader.read_to_end(&mut input).is_err() || input.len() < 32 {
        return 2;
    }
    let (digest_bytes, module_bytes) = input.split_at(32);
    let mut expected = [0u8; 32];
    expected.copy_from_slice(digest_bytes);
    if Digest::of_bytes(module_bytes) != Digest::from_bytes(expected) {
        // Byte substitution in transit — refuse rather than compile it.
        return 3;
    }

    let engine = match Engine::new(&crate::wasm::compile_engine_config()) {
        Ok(engine) => engine,
        Err(_) => return 4,
    };
    let module = match Module::from_binary(&engine, module_bytes) {
        Ok(module) => module,
        Err(_) => return 5,
    };
    let serialized = match module.serialize() {
        Ok(bytes) => bytes,
        Err(_) => return 6,
    };
    if writer.write_all(&serialized).is_err() || writer.flush().is_err() {
        return 7;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::compile_engine_config;
    use std::io::Cursor;

    fn valid_module() -> Vec<u8> {
        wat::parse_str(r#"(module (func (export "sovereign_run") (result i32) i32.const 7))"#)
            .unwrap()
    }

    fn request_bytes(digest: &Digest, module: &[u8]) -> Vec<u8> {
        digest
            .as_bytes()
            .iter()
            .copied()
            .chain(module.iter().copied())
            .collect()
    }

    #[test]
    fn worker_compiles_a_valid_module_into_a_deserializable_artifact() {
        let module = valid_module();
        let input = request_bytes(&Digest::of_bytes(&module), &module);
        let mut out = Vec::new();
        assert_eq!(run_compile_worker(Cursor::new(input), &mut out), 0);
        assert!(!out.is_empty());
        // The parent's engine deserializes what the worker produced.
        let engine = Engine::new(&compile_engine_config()).unwrap();
        // SAFETY: bytes produced by our own worker this run from a valid module.
        assert!(unsafe { Module::deserialize(&engine, &out) }.is_ok());
    }

    #[test]
    fn worker_refuses_a_digest_mismatch_and_emits_nothing() {
        let module = valid_module();
        let wrong = request_bytes(&Digest::of_bytes(b"other"), &module);
        let mut out = Vec::new();
        assert_eq!(run_compile_worker(Cursor::new(wrong), &mut out), 3);
        assert!(out.is_empty());
    }

    #[test]
    fn worker_rejects_short_input_and_invalid_modules() {
        let mut out = Vec::new();
        assert_eq!(
            run_compile_worker(Cursor::new(b"short".to_vec()), &mut out),
            2
        );

        let garbage = b"\0asm\x01\0\0\0\x7f\xff\xff\xff\xff\x0f".to_vec();
        let input = request_bytes(&Digest::of_bytes(&garbage), &garbage);
        let mut out2 = Vec::new();
        assert_eq!(run_compile_worker(Cursor::new(input), &mut out2), 5);
        assert!(out2.is_empty());
    }

    // Parent-side fail-closed plumbing, using stand-in programs so no real
    // worker binary is needed (the happy subprocess path is exercised at
    // runtime by the Security Center gauntlet against the real binary).
    #[cfg(unix)]
    #[test]
    fn parent_fails_closed_on_timeout_nonzero_and_garbage_output() {
        let engine = Engine::new(&compile_engine_config()).unwrap();
        let module = valid_module();

        // A worker that never exits is killed at the deadline.
        let hang = CompileWorker::new("/bin/sleep", vec!["30".into()])
            .with_timeout(Duration::from_millis(150));
        assert!(matches!(
            hang.compile(&engine, &module),
            Err(SandboxError::CompileWorkerTimeout)
        ));

        // A worker that exits non-zero fails closed.
        let nonzero = CompileWorker::new("/bin/false", vec![]);
        assert!(matches!(
            nonzero.compile(&engine, &module),
            Err(SandboxError::CompileWorkerFailed(_))
        ));

        // A worker that echoes non-module bytes fails at deserialize.
        let echo = CompileWorker::new("/bin/cat", vec![]);
        assert!(matches!(
            echo.compile(&engine, &module),
            Err(SandboxError::CompileWorkerFailed(_))
        ));
    }
}
