use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use thread_handles::{spawn_compute_bound, OsThreadGroup, ThreadHandleGroup};

mod thread_handle_group {
    use super::*;

    #[tokio::test]
    async fn thread_handle_group_join_all_succeeds() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut group = ThreadHandleGroup::new();

        for _ in 0..5 {
            let c = counter.clone();
            group.add(tokio::spawn(async move {
                c.fetch_add(1, Ordering::Relaxed);
            }));
        }

        group.join_all().await.unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn thread_handle_group_join_all_reports_panic() {
        let mut group = ThreadHandleGroup::new();
        group.add(tokio::spawn(async {
            panic!("oh noes");
        }));

        let err = group.join_all().await.unwrap_err();
        assert!(
            err.to_string().contains("panic"),
            "expected panic mention, got: {err}"
        );
    }

    #[tokio::test]
    async fn thread_handle_group_blocking_join_succeeds() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut group = ThreadHandleGroup::new();

        for _ in 0..3 {
            let c = counter.clone();
            group.add(tokio::spawn(async move {
                c.fetch_add(1, Ordering::Relaxed);
            }));
        }

        // Give the tasks a moment to finish so the blocking join doesn't have to
        // spin for long.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        group.join_all_blocking().unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn thread_handle_group_blocking_join_reports_panic() {
        let mut group = ThreadHandleGroup::new();
        group.add(tokio::spawn(async {
            panic!("blocking panic");
        }));

        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let err = group.join_all_blocking().unwrap_err();
        assert!(
            err.to_string().contains("blocking panic"),
            "expected panic mention, got: {err}"
        );
    }
}

mod os_thread_group {
    use super::*;
    #[test]
    fn join_all_succeeds() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut group: OsThreadGroup<()> = OsThreadGroup::new();

        for _ in 0..5 {
            let c = counter.clone();
            group.add(std::thread::spawn(move || {
                c.fetch_add(1, Ordering::Relaxed);
            }));
        }

        group.join_all().unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn join_all_reports_panic() {
        let mut group: OsThreadGroup<()> = OsThreadGroup::new();
        group.add(std::thread::spawn(|| {
            panic!("os thread panics");
        }));

        let err = group.join_all().unwrap_err();
        eprintln!("err: {}", err);
        assert!(
            err.to_string().contains("os thread panic"),
            "expected panic mention, got: {err}"
        );
    }

    #[test]
    fn join_all_with_results() {
        let mut group = OsThreadGroup::new();

        for i in 0..4 {
            group.add(std::thread::spawn(move || i * 10));
        }

        let mut results = group.join_all_with_results().unwrap();
        results.sort();
        assert_eq!(results, vec![0, 10, 20, 30]);
    }

    #[test]
    fn join_all_with_results_reports_panic() {
        let mut group = OsThreadGroup::new();
        group.add(std::thread::spawn(|| -> i32 {
            panic!("os thread result panic");
        }));

        let err = group.join_all_with_results().unwrap_err();

        assert!(
            err.to_string().contains("os thread result panic"),
            "expected panic mention, got: {err}"
        );
    }
}

mod spawn_compute_bound {
    use super::*;
    #[tokio::test]
    async fn spawn_compute_bound_returns_value() {
        let result = spawn_compute_bound(|| 2 + 2).await.unwrap();
        assert_eq!(result, 4);
    }

    #[tokio::test]
    async fn spawn_compute_bound_runs_off_tokio_thread() {
        // The closure runs on a rayon worker, which is a different thread from the
        // tokio runtime thread.
        let tokio_thread = std::thread::current().id();
        let rayon_thread = spawn_compute_bound(move || std::thread::current().id())
            .await
            .unwrap();
        assert_ne!(tokio_thread, rayon_thread);
    }

    #[tokio::test]
    async fn spawn_compute_bound_multiple_tasks() {
        let mut handles = Vec::new();
        for i in 0..10 {
            handles.push(tokio::spawn(async move {
                spawn_compute_bound(move || i * i).await.unwrap()
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            results.push(h.await.unwrap());
        }
        results.sort();
        assert_eq!(results, vec![0, 1, 4, 9, 16, 25, 36, 49, 64, 81]);
    }

    #[tokio::test]
    async fn spawn_compute_bound_propagates_result_types() {
        let result: anyhow::Result<String> =
            spawn_compute_bound(|| "hello from rayon".to_string()).await;
        assert_eq!(result.unwrap(), "hello from rayon");
    }
}
