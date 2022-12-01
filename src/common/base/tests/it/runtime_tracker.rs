// Copyright 2022 Datafuse Labs.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use common_base::base::AsyncThreadTracker;
use common_base::base::MemoryTracker;
use common_base::base::Runtime;
use common_base::base::ThreadTracker;
use common_base::base::TrySpawn;
use common_exception::Result;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_async_thread_tracker() -> Result<()> {
    let (out_tx, out_rx) = async_channel::bounded(10);
    let (inner_tx, inner_rx) = async_channel::bounded(10);

    let outer_runtime = Runtime::with_worker_threads(2, Some(String::from("Outer")))?;
    let inner_runtime = Runtime::with_worker_threads(2, Some(String::from("Inner")))?;

    let memory_tracker = MemoryTracker::create();
    let inner_join_handler = inner_runtime.spawn(AsyncThreadTracker::create(
        ThreadTracker::create(Some(memory_tracker.clone())),
        async move {
            let memory = vec![0_u8; 3 * 1024 * 1024];
            out_tx.send(()).await.unwrap();
            inner_rx.recv().await.unwrap();
            drop(memory);

            let memory1 = vec![0_u8; 3 * 1024 * 1024];
            out_tx.send(()).await.unwrap();
            inner_rx.recv().await.unwrap();

            let memory2 = vec![0_u8; 2 * 1024 * 1024];
            out_tx.send(()).await.unwrap();
            inner_rx.recv().await.unwrap();

            drop(memory1);
            out_tx.send(()).await.unwrap();
            inner_rx.recv().await.unwrap();

            drop(memory2);
            out_tx.send(()).await.unwrap();
            inner_rx.recv().await.unwrap();
        },
    ));

    // let memory_tracker2 = memory_tracker.clone();
    let outer_join_handler = outer_runtime.spawn(async move {
        for (min_memory_usage, max_memory_usage) in [
            (0, 1),
            (0, 1),
            (4 * 1024 * 1024, 6 * 1024 * 1024),
            (4 * 1024 * 1024, 6 * 1024 * 1024),
            (0, 1024 * 1024),
        ] {
            out_rx.recv().await.unwrap();
            assert!(min_memory_usage <= memory_tracker.get_memory_usage());
            assert!(max_memory_usage > memory_tracker.get_memory_usage());
            inner_tx.send(()).await.unwrap();
        }
    });

    inner_join_handler.await.unwrap();
    outer_join_handler.await.unwrap();

    drop(inner_runtime);
    drop(outer_runtime);

    // println!("{}", memory_tracker2.get_memory_usage());
    // XXX: maybe memory tracker leak
    // assert_eq!(memory_tracker2.get_memory_usage(), 0);
    Ok(())
}
