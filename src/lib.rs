//! bynh-status-agent: an open-source uptime monitoring agent for bynh.
//!
//! The binary lives in `main.rs`; the library exists so the pieces can be
//! tested on their own and driven end to end from integration tests.

pub mod agent;
pub mod backoff;
pub mod buffer;
pub mod config;
pub mod details;
pub mod net;
pub mod netguard;
pub mod platform;
pub mod probe;
pub mod protocol;
pub mod proxy;
pub mod redact;
pub mod scheduler;
