use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::advance;

#[derive(Default)]
struct Fake {
    dead: AtomicBool,
}

impl PoolSession for Fake {
    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    fn terminate(&self) {
        self.dead.store(true, Ordering::SeqCst);
    }
}

type FakePool = Arc<Pool<Fake>>;

fn dial(placement: Placement<Fake>) -> (DialHandle<Fake>, Reservation<Fake>) {
    match placement {
        Placement::Dial { dial, reservation } => (dial, reservation),
        _ => panic!("expected dial"),
    }
}

fn wait(placement: Placement<Fake>) -> (u32, watch::Receiver<EntryState<Fake>>, Reservation<Fake>) {
    match placement {
        Placement::Wait { stream_id, state, reservation } => (stream_id, state, reservation),
        _ => panic!("expected wait"),
    }
}

fn open(placement: Placement<Fake>) -> (u32, Arc<Fake>, Reservation<Fake>) {
    match placement {
        Placement::Open { stream_id, session, reservation } => (stream_id, session, reservation),
        _ => panic!("expected open"),
    }
}

/// Dials and establishes a session, returning it with the reservation of its first stream.
fn established(pool: &FakePool, cap: Cap) -> (Arc<Fake>, Reservation<Fake>) {
    let (dial_handle, reservation) = dial(pool.place(cap));
    let session = Arc::new(Fake::default());
    dial_handle.established(session.clone());
    (session, reservation)
}

#[test]
fn session_cap_dials_until_limit() {
    let pool = Pool::new();
    let cap = Cap::Sessions(2);

    let (_dial1, _res1) = dial(pool.place(cap));
    let (_dial2, _res2) = dial(pool.place(cap));
    let (stream_id, _, _res3) = wait(pool.place(cap));
    assert_eq!(stream_id, 2);
    assert_eq!(pool.stream_counts(), [(1, 2), (2, 1)]);
}

#[test]
fn session_cap_places_on_least_loaded() {
    let pool = Pool::new();
    let cap = Cap::Sessions(2);

    let (first, _res1) = established(&pool, cap);
    let (second, _res2) = established(&pool, cap);
    let (stream_id, session, _res3) = open(pool.place(cap));
    assert!(Arc::ptr_eq(&session, &first));
    assert_eq!(stream_id, 2);

    let (stream_id, session, _res4) = open(pool.place(cap));
    assert!(Arc::ptr_eq(&session, &second));
    assert_eq!(stream_id, 2);

    let (stream_id, session, _res5) = open(pool.place(cap));
    assert!(Arc::ptr_eq(&session, &first));
    assert_eq!(stream_id, 3);
}

#[test]
fn stream_cap_dials_when_all_full() {
    let pool = Pool::new();
    let cap = Cap::Streams(2);

    let (_dial1, _res1) = dial(pool.place(cap));
    let (stream_id, _, _res2) = wait(pool.place(cap));
    assert_eq!(stream_id, 2);
    let (_dial3, _res3) = dial(pool.place(cap));
    assert_eq!(pool.stream_counts(), [(1, 2), (2, 1)]);
}

#[test]
fn stream_cap_prefers_less_loaded_established_session() {
    let pool = Pool::new();
    let cap = Cap::Streams(2);

    let (_dial1, _res1) = dial(pool.place(cap));
    let (_, _, res2) = wait(pool.place(cap));
    let (session, res3) = established(&pool, cap);
    drop(res3);
    drop(res2);
    assert_eq!(pool.stream_counts(), [(1, 1), (2, 0)]);

    let (_, chosen, _res4) = open(pool.place(cap));
    assert!(Arc::ptr_eq(&chosen, &session));
}

#[test]
fn stream_cap_one_is_not_exclusive() {
    let pool = Pool::new();
    let cap = Cap::Streams(1);

    let (session, res1) = established(&pool, cap);
    drop(res1);
    let (stream_id, chosen, _res2) = open(pool.place(cap));
    assert!(Arc::ptr_eq(&chosen, &session));
    assert_eq!(stream_id, 2);
}

#[tokio::test]
async fn waiter_sees_established_session() {
    let pool = Pool::new();
    let cap = Cap::Streams(4);

    let (dial_handle, _res1) = dial(pool.place(cap));
    let (_, mut state, _res2) = wait(pool.place(cap));
    let session = Arc::new(Fake::default());
    dial_handle.established(session.clone());

    let state = state.wait_for(|state| !matches!(state, EntryState::Handshaking)).await.unwrap().clone();
    assert!(matches!(state, EntryState::Ready(ready) if Arc::ptr_eq(&ready, &session)));
}

#[tokio::test]
async fn waiter_fails_when_dial_is_dropped() {
    let pool = Pool::new();
    let cap = Cap::Streams(4);

    let (dial_handle, res1) = dial(pool.place(cap));
    let (_, mut state, res2) = wait(pool.place(cap));
    drop(dial_handle);

    if let Ok(state) = state.wait_for(|state| !matches!(state, EntryState::Handshaking)).await {
        assert!(matches!(*state, EntryState::Dead));
    }
    assert!(pool.stream_counts().is_empty());

    drop(res1);
    drop(res2);
    let (_dial, _res) = dial(pool.place(cap));
    assert_eq!(pool.stream_counts(), [(2, 1)]);
}

#[test]
fn reservation_releases_once() {
    let pool = Pool::new();
    let cap = Cap::Sessions(1);

    let (_session, res1) = established(&pool, cap);
    let (_, _, res2) = open(pool.place(cap));
    assert_eq!(pool.stream_counts(), [(1, 2)]);
    drop(res1);
    assert_eq!(pool.stream_counts(), [(1, 1)]);
    drop(res2);
    assert_eq!(pool.stream_counts(), [(1, 0)]);
}

#[test]
fn dead_session_is_not_selected() {
    let pool = Pool::new();
    let cap = Cap::Sessions(1);

    let (session, _res1) = established(&pool, cap);
    session.terminate();
    let (_dial, _res2) = dial(pool.place(cap));
    assert_eq!(pool.stream_counts(), [(2, 1)]);
}

#[tokio::test(start_paused = true)]
async fn idle_timeout_boundary() {
    let pool = Pool::new();
    let cap = Cap::Sessions(2);

    let (session, res) = established(&pool, cap);
    drop(res);

    advance(Duration::from_secs(30)).await;
    assert!(pool.scan(Duration::from_secs(30), 0).is_empty());

    advance(Duration::from_millis(1)).await;
    let victims = pool.scan(Duration::from_secs(30), 0);
    assert_eq!(victims.len(), 1);
    assert!(Arc::ptr_eq(&victims[0], &session));
    assert!(pool.stream_counts().is_empty());
}

#[tokio::test(start_paused = true)]
async fn idle_scan_skips_sessions_with_streams() {
    let pool = Pool::new();
    let cap = Cap::Sessions(1);

    let (_session, _res) = established(&pool, cap);
    advance(Duration::from_secs(3600)).await;
    assert!(pool.scan(Duration::from_secs(30), 0).is_empty());
    assert_eq!(pool.stream_counts(), [(1, 1)]);
}

/// Sessions 3 and 4 idle since 31 s, sessions 1 and 2 since now.
async fn mixed_idle_pool() -> FakePool {
    let pool = Pool::new();
    let cap = Cap::Sessions(4);
    let reservations: Vec<_> = (0..4).map(|_| established(&pool, cap).1).collect();
    let mut reservations = reservations.into_iter();
    let (res1, res2, res3, res4) = (
        reservations.next().unwrap(),
        reservations.next().unwrap(),
        reservations.next().unwrap(),
        reservations.next().unwrap(),
    );
    drop(res3);
    drop(res4);
    advance(Duration::from_secs(31)).await;
    drop(res1);
    drop(res2);
    pool
}

#[tokio::test(start_paused = true)]
async fn idle_scan_keeps_newest_for_min_idle() {
    let pool = mixed_idle_pool().await;
    assert!(pool.scan(Duration::from_secs(30), 2).is_empty());

    // The kept sessions restarted their idle time.
    advance(Duration::from_secs(29)).await;
    assert!(pool.scan(Duration::from_secs(30), 0).is_empty());
}

#[tokio::test(start_paused = true)]
async fn idle_scan_closes_expired_without_min_idle() {
    let pool = mixed_idle_pool().await;
    let victims = pool.scan(Duration::from_secs(30), 0);
    assert_eq!(victims.len(), 2);
    assert_eq!(pool.stream_counts(), [(1, 0), (2, 0)]);
}

#[tokio::test(start_paused = true)]
async fn closed_idle_session_is_not_placed() {
    let pool = Pool::new();
    let cap = Cap::Sessions(1);

    let (_session, res) = established(&pool, cap);
    drop(res);
    advance(Duration::from_secs(31)).await;
    assert_eq!(pool.scan(Duration::from_secs(30), 0).len(), 1);

    let (_dial, _res) = dial(pool.place(cap));
    assert_eq!(pool.stream_counts(), [(2, 1)]);
}

#[test]
fn dropping_pool_terminates_sessions() {
    let pool = Pool::new();
    let (session, res) = established(&pool, Cap::Sessions(1));
    drop(res);
    drop(pool);
    assert!(session.is_dead());
}
