//! Pool of reusable sessions to one server address.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

/// Session operations needed by the pool.
pub(crate) trait PoolSession: Send + Sync + 'static {
    /// Whether the session has failed or was closed.
    fn is_dead(&self) -> bool;
    /// Closes the session.
    fn terminate(&self);
}

/// Placement limit of a reusing session policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cap {
    /// At most this many sessions.
    Sessions(usize),
    /// At most this many streams per session.
    Streams(usize),
}

/// State of a pool entry, observed by callers waiting for a handshake.
pub(crate) enum EntryState<S> {
    /// TLS handshake or the first stream are in progress.
    Handshaking,
    /// Session is established and accepts further streams.
    Ready(Arc<S>),
    /// Session failed or was closed.
    Dead,
}

impl<S> Clone for EntryState<S> {
    fn clone(&self) -> Self {
        match self {
            Self::Handshaking => Self::Handshaking,
            Self::Ready(session) => Self::Ready(session.clone()),
            Self::Dead => Self::Dead,
        }
    }
}

struct Entry<S> {
    state: watch::Sender<EntryState<S>>,
    /// Streams in use plus reserved stream slots.
    streams: usize,
    next_stream_id: u32,
    idle_since: Option<Instant>,
}

impl<S: PoolSession> Entry<S> {
    fn is_live(&self) -> bool {
        match &*self.state.borrow() {
            EntryState::Handshaking => true,
            EntryState::Ready(session) => !session.is_dead(),
            EntryState::Dead => false,
        }
    }

    fn session(&self) -> Option<Arc<S>> {
        match &*self.state.borrow() {
            EntryState::Ready(session) => Some(session.clone()),
            _ => None,
        }
    }
}

/// Sessions to one server address, keyed by a sequence number increasing from 1.
pub(crate) struct Pool<S: PoolSession> {
    inner: Mutex<Inner<S>>,
}

struct Inner<S> {
    next_seq: u64,
    entries: BTreeMap<u64, Entry<S>>,
}

impl<S: PoolSession> Inner<S> {
    /// Removes dead entries; this drops their state senders so waiters fail.
    fn reap(&mut self) {
        self.entries.retain(|_, entry| {
            let live = entry.is_live();
            if !live {
                entry.state.send_replace(EntryState::Dead);
            }
            live
        });
    }

    /// Entry with the fewest streams among those matching `pred`; ties go to the lowest sequence number.
    fn least_loaded(&self, pred: impl Fn(&Entry<S>) -> bool) -> Option<u64> {
        self.entries
            .iter()
            .filter(|(_, entry)| pred(entry))
            .min_by_key(|(_, entry)| entry.streams)
            .map(|(seq, _)| *seq)
    }
}

/// A reserved stream slot. Dropping it releases the slot.
pub(crate) struct Reservation<S: PoolSession> {
    pool: Weak<Pool<S>>,
    seq: u64,
}

impl<S: PoolSession> Drop for Reservation<S> {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            pool.release(self.seq);
        }
    }
}

/// Outcome handle of dialing a new session.
///
/// Dropping it without calling [`established`](Self::established) marks the session as failed,
/// so callers waiting for the handshake are released even if dialing was cancelled.
pub(crate) struct DialHandle<S: PoolSession> {
    pool: Weak<Pool<S>>,
    seq: u64,
    done: bool,
}

impl<S: PoolSession> DialHandle<S> {
    /// Marks the session as established after its first stream was opened.
    pub(crate) fn established(mut self, session: Arc<S>) {
        self.done = true;
        match self.pool.upgrade() {
            Some(pool) => pool.established(self.seq, session),
            None => session.terminate(),
        }
    }
}

impl<S: PoolSession> Drop for DialHandle<S> {
    fn drop(&mut self) {
        if !self.done
            && let Some(pool) = self.pool.upgrade()
        {
            pool.failed(self.seq);
        }
    }
}

/// Where to open a new stream.
pub(crate) enum Placement<S: PoolSession> {
    /// Dial a new session; its first stream has id 1.
    Dial { dial: DialHandle<S>, reservation: Reservation<S> },
    /// Wait for a session that is still handshaking, then open `stream_id` on it.
    Wait { stream_id: u32, state: watch::Receiver<EntryState<S>>, reservation: Reservation<S> },
    /// Open `stream_id` on an established session.
    Open { stream_id: u32, session: Arc<S>, reservation: Reservation<S> },
}

impl<S: PoolSession> Pool<S> {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self { inner: Mutex::new(Inner { next_seq: 1, entries: BTreeMap::new() }) })
    }

    /// Reserves a stream slot according to `cap`.
    ///
    /// Stream ids are assigned here, in reservation order.
    pub(crate) fn place(self: &Arc<Self>, cap: Cap) -> Placement<S> {
        let mut inner = self.inner.lock().unwrap();
        inner.reap();

        let chosen = match cap {
            Cap::Sessions(max) if inner.entries.len() < max => None,
            Cap::Sessions(_) => inner.least_loaded(|_| true),
            Cap::Streams(max) => inner.least_loaded(|entry| entry.streams < max),
        };

        match chosen {
            None => {
                let seq = inner.next_seq;
                inner.next_seq += 1;
                let (state, _) = watch::channel(EntryState::Handshaking);
                inner.entries.insert(seq, Entry { state, streams: 1, next_stream_id: 2, idle_since: None });
                Placement::Dial {
                    dial: DialHandle { pool: Arc::downgrade(self), seq, done: false },
                    reservation: Reservation { pool: Arc::downgrade(self), seq },
                }
            }
            Some(seq) => {
                let entry = inner.entries.get_mut(&seq).unwrap();
                entry.streams += 1;
                entry.idle_since = None;
                let stream_id = entry.next_stream_id;
                entry.next_stream_id += 1;
                let reservation = Reservation { pool: Arc::downgrade(self), seq };
                match entry.session() {
                    Some(session) => Placement::Open { stream_id, session, reservation },
                    None => Placement::Wait { stream_id, state: entry.state.subscribe(), reservation },
                }
            }
        }
    }

    fn established(&self, seq: u64, session: Arc<S>) {
        let mut inner = self.inner.lock().unwrap();
        match inner.entries.get_mut(&seq) {
            Some(entry) => {
                entry.state.send_replace(EntryState::Ready(session));
                if entry.streams == 0 {
                    entry.idle_since = Some(Instant::now());
                }
            }
            None => session.terminate(),
        }
    }

    fn failed(&self, seq: u64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.remove(&seq) {
            entry.state.send_replace(EntryState::Dead);
        }
    }

    fn release(&self, seq: u64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get_mut(&seq) {
            entry.streams = entry.streams.saturating_sub(1);
            if entry.streams == 0 && entry.session().is_some() {
                entry.idle_since = Some(Instant::now());
            }
        }
    }

    /// Removes sessions idle for longer than `idle_timeout` and returns them for closing.
    ///
    /// Walks from the newest to the oldest session and keeps up to `min_idle`
    /// idle sessions, counting those that have not timed out yet.
    pub(crate) fn scan(&self, idle_timeout: Duration, min_idle: usize) -> Vec<Arc<S>> {
        let now = Instant::now();
        let expired_before = now.checked_sub(idle_timeout);

        let mut inner = self.inner.lock().unwrap();
        inner.reap();

        let mut active = 0;
        let mut expired = Vec::new();
        for (&seq, entry) in inner.entries.iter_mut().rev() {
            let Some(idle_since) = entry.idle_since else { continue };
            if entry.streams != 0 || entry.session().is_none() {
                entry.idle_since = None;
                continue;
            }
            if expired_before.is_none_or(|expired_before| idle_since >= expired_before) {
                active += 1;
                continue;
            }
            if active < min_idle {
                entry.idle_since = Some(now);
                active += 1;
                continue;
            }
            expired.push(seq);
        }

        let mut victims = Vec::new();
        for seq in expired {
            let entry = inner.entries.remove(&seq).unwrap();
            victims.extend(entry.session());
            entry.state.send_replace(EntryState::Dead);
        }
        victims
    }

    #[cfg(test)]
    pub(crate) fn stream_counts(&self) -> Vec<(u64, usize)> {
        self.inner.lock().unwrap().entries.iter().map(|(seq, entry)| (*seq, entry.streams)).collect()
    }
}

impl<S: PoolSession> Drop for Pool<S> {
    fn drop(&mut self) {
        let inner = self.inner.get_mut().unwrap();
        for entry in inner.entries.values() {
            if let Some(session) = entry.session() {
                session.terminate();
            }
        }
    }
}

#[cfg(test)]
mod tests;
