pub mod oneshot;
pub mod rwlock;

pub use oneshot::{local_channel, Receiver, Sender};
pub use rwlock::{RwLock, RwLockReadGuard, RwLockWriteGuard};
