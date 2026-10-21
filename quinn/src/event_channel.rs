use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SendError, TryRecvError},
    },
    task::{Context, Poll, Waker},
};

pub(crate) fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = mpsc::channel();
    let shared = Arc::new(Shared::default());
    (
        Sender {
            inner: sender,
            shared: shared.clone(),
        },
        Receiver {
            inner: receiver,
            shared,
        },
    )
}

struct Shared {
    has_waker: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            has_waker: AtomicBool::new(false),
            waker: Mutex::new(None),
        }
    }
}

pub(crate) struct Sender<T> {
    inner: mpsc::Sender<T>,
    shared: Arc<Shared>,
}

impl<T> Sender<T> {
    pub(crate) fn send(&self, value: T) -> Result<(), SendError<T>> {
        let result = self.inner.send(value);
        if result.is_ok() {
            self.shared.wake();
        }
        result
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            shared: self.shared.clone(),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        self.shared.wake();
    }
}

impl<T> fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sender").finish_non_exhaustive()
    }
}

pub(crate) struct Receiver<T> {
    inner: mpsc::Receiver<T>,
    shared: Arc<Shared>,
}

impl<T> Receiver<T> {
    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        match self.inner.try_recv() {
            Ok(value) => return Poll::Ready(Some(value)),
            Err(TryRecvError::Disconnected) => return Poll::Ready(None),
            Err(TryRecvError::Empty) => {}
        }

        let mut waker = self.shared.waker.lock().unwrap();
        match &*waker {
            Some(current) if current.will_wake(cx.waker()) => {}
            _ => *waker = Some(cx.waker().clone()),
        }
        self.shared.has_waker.store(true, Ordering::Release);

        match self.inner.try_recv() {
            Ok(value) => {
                *waker = None;
                self.shared.has_waker.store(false, Ordering::Release);
                Poll::Ready(Some(value))
            }
            Err(TryRecvError::Disconnected) => {
                *waker = None;
                self.shared.has_waker.store(false, Ordering::Release);
                Poll::Ready(None)
            }
            Err(TryRecvError::Empty) => Poll::Pending,
        }
    }
}

impl<T> fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Receiver").finish_non_exhaustive()
    }
}

impl Shared {
    fn wake(&self) {
        if !self.has_waker.swap(false, Ordering::AcqRel) {
            return;
        }

        let waker = self.waker.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    use crate::event_channel::channel;

    #[test]
    fn receives_ready_value() {
        let (sender, mut receiver) = channel();
        sender.send(7).unwrap();

        let (waker, _) = waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(receiver.poll_recv(&mut cx), Poll::Ready(Some(7)));
    }

    #[test]
    fn wakes_receiver_on_send() {
        let (sender, mut receiver) = channel();
        let (waker, wakes) = waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(receiver.poll_recv(&mut cx), Poll::Pending);
        assert_eq!(wakes.load(Ordering::Relaxed), 0);

        sender.send(7).unwrap();
        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        assert_eq!(receiver.poll_recv(&mut cx), Poll::Ready(Some(7)));
    }

    #[test]
    fn wakes_receiver_on_disconnect() {
        let (sender, mut receiver) = channel::<()>();
        let (waker, wakes) = waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(receiver.poll_recv(&mut cx), Poll::Pending);
        drop(sender);

        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        assert_eq!(receiver.poll_recv(&mut cx), Poll::Ready(None));
    }

    #[test]
    fn uses_most_recent_waker() {
        let (sender, mut receiver) = channel();
        let (first_waker, first_wakes) = waker();
        let (second_waker, second_wakes) = waker();
        let mut first_cx = Context::from_waker(&first_waker);
        let mut second_cx = Context::from_waker(&second_waker);

        assert_eq!(receiver.poll_recv(&mut first_cx), Poll::Pending);
        assert_eq!(receiver.poll_recv(&mut second_cx), Poll::Pending);

        sender.send(7).unwrap();
        assert_eq!(first_wakes.load(Ordering::Relaxed), 0);
        assert_eq!(second_wakes.load(Ordering::Relaxed), 1);
        assert_eq!(receiver.poll_recv(&mut second_cx), Poll::Ready(Some(7)));
    }

    #[test]
    fn reports_send_after_receiver_drop() {
        let (sender, receiver) = channel();
        drop(receiver);

        let error = sender.send(7).unwrap_err();
        assert_eq!(error.0, 7);
    }

    fn waker() -> (Waker, Arc<AtomicUsize>) {
        let wakes = Arc::new(AtomicUsize::new(0));
        (
            Waker::from(Arc::new(WakeCounter {
                wakes: wakes.clone(),
            })),
            wakes,
        )
    }

    struct WakeCounter {
        wakes: Arc<AtomicUsize>,
    }

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }
    }
}
