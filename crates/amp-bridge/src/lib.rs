//! `remora-amp-bridge` — codex app-server facade over `amp --stream-json`.

pub mod bridge;
pub mod command_exec;
pub mod index;
pub mod process;
pub mod state;

pub use bridge::{AmpBridge, AmpBridgeBuilder};
pub use index::AmpSessionRef;
