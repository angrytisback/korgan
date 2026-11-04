//! Adapters (infrastructure & delivery). Dependencies flow
//! `adapters -> application -> domain`, never the other way around.

pub mod inbound;
pub mod outbound;
