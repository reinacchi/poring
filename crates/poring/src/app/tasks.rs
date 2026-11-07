//! Owned, supervised task sets for the server.
//!
//! [`TaskTracker`] spawns Tokio tasks whose lifetime the server owns: every task is
//! registered by an abort handle that is removed **the moment the task ends** (completed,
//! panicked or cancelled), so finished tasks never accumulate, with no reaper task and no
//! polling. A `watch` channel carries the live count, so shutdown can wait for the set to
//! drain and then abort what is left. Panics are caught at the task boundary and reported
//! through an optional hook instead of being lost in a dropped `JoinHandle`.
//!
//! Used for TCP/TLS connection tasks, for the HTTP/2 stream tasks of each connection, and
//! for WebSocket sessions.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

/// A set of owned tasks (cheap to clone; clones share the set).
#[derive(Clone)]
pub(crate) struct TaskTracker {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<State>,
    live: tokio::sync::watch::Sender<usize>,
    on_panic: Option<Box<dyn Fn() + Send + Sync>>,
}

struct State {
    /// New work is accepted by [`TaskTracker::spawn`].
    accepting: bool,
    /// [`TaskTracker::abort_all`] ran: nothing is spawned any more.
    aborted: bool,
    next: u64,
    tasks: HashMap<u64, tokio::task::AbortHandle>,
}

/// Removes its task from the set when the task's future is dropped, however it ends.
struct Entry {
    inner: Arc<Inner>,
    id: u64,
}

impl Drop for Entry {
    fn drop(&mut self) {
        lock(&self.inner.state).tasks.remove(&self.id);
        self.inner.live.send_modify(|n| *n -= 1);
    }
}

fn lock(m: &Mutex<State>) -> MutexGuard<'_, State> {
    // No user code runs under this lock, so the state is consistent even after a panic.
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl TaskTracker {
    pub(crate) fn new() -> Self {
        Self::build(None)
    }

    /// A tracker that calls `hook` whenever one of its tasks panics.
    #[cfg_attr(not(feature = "websocket"), allow(dead_code))]
    pub(crate) fn with_panic_hook(hook: impl Fn() + Send + Sync + 'static) -> Self {
        Self::build(Some(Box::new(hook)))
    }

    fn build(on_panic: Option<Box<dyn Fn() + Send + Sync>>) -> Self {
        TaskTracker {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    accepting: true,
                    aborted: false,
                    next: 0,
                    tasks: HashMap::new(),
                }),
                live: tokio::sync::watch::Sender::new(0),
                on_panic,
            }),
        }
    }

    /// Spawns `fut` unless the tracker was [closed](Self::close) or aborted.
    pub(crate) fn spawn(&self, fut: impl Future<Output = ()> + Send + 'static) -> bool {
        self.spawn_inner(fut, true)
    }

    /// Spawns `fut` unless the tracker was aborted — also while it drains after
    /// [`close`](Self::close) (work that belongs to an already admitted connection).
    #[cfg_attr(not(feature = "http2"), allow(dead_code))]
    pub(crate) fn spawn_draining(&self, fut: impl Future<Output = ()> + Send + 'static) -> bool {
        self.spawn_inner(fut, false)
    }

    fn spawn_inner(&self, fut: impl Future<Output = ()> + Send + 'static, admit: bool) -> bool {
        let mut st = lock(&self.inner.state);
        if st.aborted || (admit && !st.accepting) {
            return false;
        }
        let id = st.next;
        st.next += 1;
        self.inner.live.send_modify(|n| *n += 1);
        let entry = Entry {
            inner: self.inner.clone(),
            id,
        };
        let task = async move {
            // Dropped with the future: on completion, on panic and on abort (even before
            // the first poll, since an unresumed async block drops its captures).
            let entry = entry;
            if CatchUnwind(Box::pin(fut)).await.is_err()
                && let Some(hook) = &entry.inner.on_panic
            {
                hook();
            }
        };
        // Registered before the lock is released, so the entry's removal (which needs the
        // lock) can never precede its insertion.
        let handle = tokio::spawn(task);
        st.tasks.insert(id, handle.abort_handle());
        true
    }

    /// Stops [`spawn`](Self::spawn) from accepting work; running tasks continue.
    pub(crate) fn close(&self) {
        lock(&self.inner.state).accepting = false;
    }

    /// Number of tasks that have not ended yet.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn len(&self) -> usize {
        *self.inner.live.borrow()
    }

    /// Number of tasks still registered in the set (equals [`len`](Self::len) except
    /// transiently); finished tasks never linger here.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn registered(&self) -> usize {
        lock(&self.inner.state).tasks.len()
    }

    /// Waits until every task has ended.
    pub(crate) async fn wait_idle(&self) {
        let mut rx = self.inner.live.subscribe();
        let _ = rx.wait_for(|n| *n == 0).await;
    }

    /// Aborts every task and refuses all further spawns. Aborted tasks are dropped at their
    /// next await point; use [`wait_idle`](Self::wait_idle) to wait for that.
    pub(crate) fn abort_all(&self) -> usize {
        let handles: Vec<_> = {
            let mut st = lock(&self.inner.state);
            st.aborted = true;
            st.accepting = false;
            st.tasks.drain().map(|(_, h)| h).collect()
        };
        for h in &handles {
            h.abort();
        }
        handles.len()
    }
}

/// Owns a [`TaskTracker`]: dropping it aborts whatever is still running, so tasks cannot
/// outlive the scope (a connection task, a `serve` future) that spawned them.
pub(crate) struct TaskScope(pub(crate) TaskTracker);

impl Drop for TaskScope {
    fn drop(&mut self) {
        self.0.abort_all();
    }
}

/// Polls a future, turning a panic into `Err(())`.
pub(crate) struct CatchUnwind<F>(pub(crate) Pin<Box<F>>);

impl<F: Future> Future for CatchUnwind<F> {
    type Output = Result<F::Output, ()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let fut = self.0.as_mut();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fut.poll(cx))) {
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(Err(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn finished_tasks_are_reclaimed_without_further_spawns() {
        let t = TaskTracker::new();
        for _ in 0..2_000 {
            assert!(t.spawn(async { tokio::task::yield_now().await }));
        }
        tokio::time::timeout(Duration::from_secs(5), t.wait_idle())
            .await
            .expect("drains");
        // Nothing else is spawned: the completed entries are already gone.
        assert_eq!(t.len(), 0);
        assert_eq!(t.registered(), 0);
    }

    #[tokio::test]
    async fn panics_are_caught_and_reported() {
        let n = Arc::new(AtomicUsize::new(0));
        let t = TaskTracker::with_panic_hook({
            let n = n.clone();
            move || {
                n.fetch_add(1, Ordering::SeqCst);
            }
        });
        t.spawn(async { panic!("boom") });
        t.spawn(async {});
        tokio::time::timeout(Duration::from_secs(5), t.wait_idle())
            .await
            .expect("drains");
        assert_eq!(n.load(Ordering::SeqCst), 1);
        assert_eq!(t.registered(), 0);
    }

    #[tokio::test]
    async fn close_and_abort() {
        let t = TaskTracker::new();
        let dropped = Arc::new(AtomicUsize::new(0));
        struct D(Arc<AtomicUsize>);
        impl Drop for D {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        for _ in 0..10 {
            let d = D(dropped.clone());
            t.spawn(async move {
                let _d = d;
                std::future::pending::<()>().await
            });
        }
        t.close();
        assert!(!t.spawn(async {}), "closed: no new work");
        assert!(
            t.spawn_draining(async {}),
            "draining work is still accepted"
        );
        // The ten pending tasks, plus the draining one if it has not finished yet.
        let aborted = t.abort_all();
        assert!(aborted == 10 || aborted == 11, "{aborted}");
        tokio::time::timeout(Duration::from_secs(5), t.wait_idle())
            .await
            .expect("aborted tasks are dropped");
        assert_eq!(dropped.load(Ordering::SeqCst), 10);
        assert!(!t.spawn_draining(async {}), "aborted: nothing is spawned");
    }

    #[tokio::test]
    async fn dropping_the_scope_aborts() {
        let t = TaskTracker::new();
        let scope = TaskScope(t.clone());
        t.spawn(std::future::pending());
        drop(scope);
        tokio::time::timeout(Duration::from_secs(5), t.wait_idle())
            .await
            .expect("scope drop aborts");
    }
}
