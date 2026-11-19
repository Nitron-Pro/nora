pub mod guard;
pub mod audit;
pub mod pty;
pub mod exec;

/// Tear down every terminal, running exec and pooled SSH session; flush the audit log.
/// Call from the app exit handler.
pub fn cleanup_all() {
    pty::cleanup_terminals();
    exec::cleanup_execs();
    audit::flush();
}
