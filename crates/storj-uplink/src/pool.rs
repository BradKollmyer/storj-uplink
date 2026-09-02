//! Storage-node connection pool.
//!
//! One in-flight RPC per connection (same as Go). During a remote segment
//! upload the client talks to `n` storage nodes at once, so the cap **must**
//! be at least the RS scheme `n` (production default 110).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use storj_rpc::NodeId;
use tokio::sync::Notify;

use crate::{Error, Result};

/// Satellite `releaseDefault` total pieces (`n`). Pool cap must be ≥ this
/// when using that scheme.
pub const DEFAULT_SCHEME_N: usize = 110;

/// Pool sizing. [`Self::for_redundancy_n`] guarantees `max_connections >= n`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolConfig {
    /// Maximum concurrent SN connections (idle + in-use). Always ≥ scheme `n`.
    pub max_connections: usize,
    /// Unused by the map today; reserved for idle eviction (PR 16).
    pub idle_timeout: Duration,
}

impl PoolConfig {
    /// Cap the pool at least at RS total pieces `n`.
    #[must_use]
    pub fn for_redundancy_n(n: usize) -> Self {
        Self {
            max_connections: n.max(1),
            idle_timeout: Duration::from_secs(5 * 60),
        }
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self::for_redundancy_n(DEFAULT_SCHEME_N)
    }
}

struct Inner<T> {
    idle: HashMap<NodeId, VecDeque<T>>,
    idle_count: usize,
    in_use: usize,
}

impl<T> Inner<T> {
    fn pop_idle(&mut self, node: NodeId) -> Option<T> {
        let slot = self.idle.get_mut(&node)?;
        let conn = slot.pop_front()?;
        if slot.is_empty() {
            self.idle.remove(&node);
        }
        self.idle_count = self.idle_count.saturating_sub(1);
        Some(conn)
    }

    fn push_idle(&mut self, node: NodeId, conn: T) {
        self.idle.entry(node).or_default().push_back(conn);
        self.idle_count += 1;
    }

    fn evict_one_idle(&mut self) -> Option<T> {
        let key = self.idle.keys().next().copied()?;
        self.pop_idle(key)
    }
}

struct PoolInner<T> {
    max: usize,
    inner: Mutex<Inner<T>>,
    notify: Notify,
}

impl<T> PoolInner<T> {
    fn guard(&self) -> std::sync::MutexGuard<'_, Inner<T>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Decrements `in_use` on drop unless converted into a [`Pooled`] (dial cancel).
struct Slot<T> {
    pool: Arc<PoolInner<T>>,
    node: NodeId,
    armed: bool,
}

impl<T> Slot<T> {
    fn new(pool: Arc<PoolInner<T>>, node: NodeId) -> Self {
        Self {
            pool,
            node,
            armed: true,
        }
    }

    fn into_pooled(mut self, conn: T) -> Pooled<T> {
        self.armed = false;
        Pooled {
            conn: Some(conn),
            node: self.node,
            pool: Arc::clone(&self.pool),
            recycle: true,
        }
    }
}

impl<T> Drop for Slot<T> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        {
            let mut g = self.pool.guard();
            g.in_use = g.in_use.saturating_sub(1);
        }
        self.pool.notify.notify_one();
    }
}

/// LRU-ish SN pool keyed by [`NodeId`]. Checkout waits when `in_use == max`.
pub struct ConnectionPool<T> {
    inner: Arc<PoolInner<T>>,
}

impl<T> Clone for ConnectionPool<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T: Send + 'static> ConnectionPool<T> {
    /// Build a pool with `config.max_connections` concurrent slots.
    #[must_use]
    pub fn new(config: PoolConfig) -> Self {
        Self {
            inner: Arc::new(PoolInner {
                max: config.max_connections.max(1),
                inner: Mutex::new(Inner {
                    idle: HashMap::new(),
                    idle_count: 0,
                    in_use: 0,
                }),
                notify: Notify::new(),
            }),
        }
    }

    /// Maximum concurrent connections (always ≥ the `n` passed to the config).
    #[must_use]
    pub fn max_connections(&self) -> usize {
        self.inner.max
    }

    /// Idle connections currently cached.
    #[must_use]
    pub fn idle_count(&self) -> usize {
        self.inner.guard().idle_count
    }

    /// Connections checked out (not yet dropped).
    #[must_use]
    pub fn in_use(&self) -> usize {
        self.inner.guard().in_use
    }

    /// Take an idle conn for `node`, or dial a new one. Waits when at cap and
    /// every slot is in use.
    pub async fn checkout<F, Fut, E>(&self, node: NodeId, dial: F) -> Result<Pooled<T>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = std::result::Result<T, E>>,
        E: Into<Error>,
    {
        loop {
            let action = {
                let mut g = self.inner.guard();
                if let Some(conn) = g.pop_idle(node) {
                    g.in_use += 1;
                    Checkout::Reuse(conn)
                } else if g.in_use < self.inner.max {
                    if g.in_use + g.idle_count >= self.inner.max {
                        let _ = g.evict_one_idle();
                    }
                    g.in_use += 1;
                    Checkout::Dial
                } else {
                    Checkout::Wait
                }
            };
            match action {
                Checkout::Reuse(conn) => {
                    return Ok(Slot::new(Arc::clone(&self.inner), node).into_pooled(conn));
                }
                Checkout::Dial => {
                    let slot = Slot::new(Arc::clone(&self.inner), node);
                    return match dial().await {
                        Ok(conn) => Ok(slot.into_pooled(conn)),
                        Err(e) => Err(e.into()),
                    };
                }
                Checkout::Wait => {
                    self.inner.notify.notified().await;
                }
            }
        }
    }
}

enum Checkout<T> {
    Reuse(T),
    Dial,
    Wait,
}

/// Guard that returns the connection to the pool on drop.
pub struct Pooled<T> {
    conn: Option<T>,
    node: NodeId,
    pool: Arc<PoolInner<T>>,
    recycle: bool,
}

impl<T> Pooled<T> {
    /// Peer this connection was checked out for.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.node
    }

    /// Borrow the transport. `None` after the conn has been taken (drop).
    #[must_use]
    pub fn get(&self) -> Option<&T> {
        self.conn.as_ref()
    }

    /// Borrow the transport mutably. `None` after the conn has been taken (drop).
    pub fn get_mut(&mut self) -> Option<&mut T> {
        self.conn.as_mut()
    }

    /// Do not return this connection to the idle pool (mid-RPC cancel / poison).
    pub fn skip_recycle(&mut self) {
        self.recycle = false;
    }
}

impl<T> Drop for Pooled<T> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            {
                let mut g = self.pool.guard();
                g.in_use = g.in_use.saturating_sub(1);
                if self.recycle {
                    g.push_idle(self.node, conn);
                }
            }
            self.pool.notify.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn nid(n: u8) -> NodeId {
        NodeId::from_bytes([n; 32])
    }

    #[test]
    fn cap_at_least_scheme_n() {
        assert!(PoolConfig::default().max_connections >= DEFAULT_SCHEME_N);
        assert!(PoolConfig::for_redundancy_n(110).max_connections >= 110);
        assert!(PoolConfig::for_redundancy_n(4).max_connections >= 4);
        assert_eq!(PoolConfig::for_redundancy_n(0).max_connections, 1);
        let pool = ConnectionPool::<u32>::new(PoolConfig::for_redundancy_n(110));
        assert!(pool.max_connections() >= 110);
    }

    #[tokio::test]
    async fn checkout_reuses_idle_and_caps_concurrent() {
        let n = 4;
        let pool = ConnectionPool::new(PoolConfig::for_redundancy_n(n));
        assert!(pool.max_connections() >= n);
        let dials = Arc::new(AtomicUsize::new(0));

        let mut held = Vec::new();
        for i in 0..n {
            let dials = Arc::clone(&dials);
            let node = nid(i as u8);
            let c = pool
                .checkout(node, || {
                    let dials = Arc::clone(&dials);
                    async move {
                        dials.fetch_add(1, Ordering::SeqCst);
                        Ok::<u32, Error>(u32::from(i as u8))
                    }
                })
                .await
                .unwrap();
            held.push(c);
        }
        assert_eq!(dials.load(Ordering::SeqCst), n);
        assert_eq!(pool.in_use(), n);

        let extra = tokio::time::timeout(
            Duration::from_millis(40),
            pool.checkout(nid(99), || async { Ok::<u32, Error>(99) }),
        )
        .await;
        assert!(extra.is_err(), "checkout beyond n must wait");

        held.pop();
        let got = tokio::time::timeout(
            Duration::from_millis(500),
            pool.checkout(nid(99), || {
                let dials = Arc::clone(&dials);
                async move {
                    dials.fetch_add(1, Ordering::SeqCst);
                    Ok::<u32, Error>(99)
                }
            }),
        )
        .await
        .expect("slot freed")
        .unwrap();
        assert_eq!(*got.get().expect("conn"), 99);
        drop(got);
        drop(held);

        // Same node reuses the idle conn (no extra dial).
        let before = dials.load(Ordering::SeqCst);
        let reused = pool
            .checkout(nid(99), || async {
                Err(Error::protocol("should reuse idle"))
            })
            .await
            .unwrap();
        assert_eq!(*reused.get().expect("conn"), 99);
        assert_eq!(dials.load(Ordering::SeqCst), before);
    }

    #[tokio::test]
    async fn cancelled_dial_releases_slot() {
        let pool = ConnectionPool::new(PoolConfig::for_redundancy_n(1));
        let hang = tokio::spawn({
            let pool = pool.clone();
            async move {
                pool.checkout(nid(1), std::future::pending::<Result<u32, Error>>)
                    .await
            }
        });
        tokio::time::timeout(Duration::from_millis(500), async {
            while pool.in_use() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dial never started");
        hang.abort();
        let _ = hang.await;
        assert_eq!(pool.in_use(), 0, "cancelled dial must not leak in_use");

        let got = tokio::time::timeout(
            Duration::from_millis(500),
            pool.checkout(nid(1), || async { Ok::<u32, Error>(7) }),
        )
        .await
        .expect("leaked slot")
        .unwrap();
        assert_eq!(*got.get().expect("conn"), 7);
    }

    #[tokio::test]
    async fn skip_recycle_does_not_reuse() {
        let pool = ConnectionPool::new(PoolConfig::for_redundancy_n(1));
        let node = nid(1);
        let dials = Arc::new(AtomicUsize::new(0));
        {
            let dials = Arc::clone(&dials);
            let mut poisoned = pool
                .checkout(node, || async move {
                    dials.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, Error>(1u32)
                })
                .await
                .unwrap();
            poisoned.skip_recycle();
        }
        assert_eq!(pool.idle_count(), 0);
        let dials2 = Arc::clone(&dials);
        let _again = pool
            .checkout(node, || async move {
                dials2.fetch_add(1, Ordering::SeqCst);
                Ok::<_, Error>(2u32)
            })
            .await
            .unwrap();
        assert_eq!(dials.load(Ordering::SeqCst), 2, "skipped conn must redial");
    }
}
