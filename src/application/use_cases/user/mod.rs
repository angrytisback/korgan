//! User use cases: get profile, update profile, change e-mail, deactivate and
//! delete.

pub mod profile;

pub use profile::{GetProfileUseCase, UpdateProfileUseCase};
