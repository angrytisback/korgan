//! k-anonymity Have I Been Pwned range-API client.

pub mod client;

pub use client::{NoopHibpClient, ReqwestHibpClient};
