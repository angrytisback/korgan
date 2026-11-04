//! Background job dispatcher and periodic cleanup tasks (e-mail delivery,
//! audit writes, expired-session and pending-deletion sweeps).

pub mod events;
pub mod worker;

pub use events::{AppEvent, EventBus};
pub use worker::{EventWorker, RetentionGcWorker, SessionPurgeWorker};
