## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — priority selection, cancellation, ownership│
└──────────────────────────────────────────────┘
```

# Multi-level feedback queue (MLFQ)

## 1. Role

`t_mlfq<T, BINDER_T>` is a synchronized priority queue for work items. It is not an event source and does not schedule socket readiness; it decides which queued item a consumer retrieves next. The consumer decides what the item's priority means for application work.

## 2. Data Model

- `_mfq`: `std::map<int, std::queue<T*>>`, one FIFO queue per integer priority.
- `_workingset`: a set of pointers that are still considered active; cancellation marks an item inactive here.
- `_semaphore`: counts posted work so a consumer can wait.
- `_lock`: protects queue, working-set and size updates.
- `_size`: number of queued entries, including an entry whose pointer may have been canceled but has not yet been popped.
- `_mode[mlfq_block]`: posting can be blocked with `set(mlfq_mode_t::mlfq_block, 0)`.

The binder controls pointer lifetime/reference counting. The default `mlfq_shared_binder<T>` calls `addref()` on post and `release()` when an item is canceled or cleared. `mlfq_nonshared_binder<T>` does nothing, so the caller owns allocation and release. The optional `param` is passed to binder operations; it is not the queue item's payload.

## 3. Behavior Model

### Which item is returned first?

`get()` scans the priority map in reverse order: **a greater integer means a higher priority**. Within one priority, the underlying queue is FIFO. A consumer therefore receives the oldest active item from the highest non-empty priority, not necessarily the globally oldest posted item.

### What does post/get return?

- `post(pri, source, param)` rejects a null pointer, checks the blocked mode, applies the binder's reference-increment operation, appends the pointer to its priority queue, adds it to the working set, and signals the semaphore.
- `get(&pri, &source, timeout)` waits on the semaphore. A timeout is reported as `not_ready`; if a semaphore signal is received but no active queued item can be returned, the code can report a cancellation status.
- `push()` aliases `post()`; `operator<<` posts at priority zero with no parameter.
- `size()` reports queued-entry count, not the number of unique active pointers.
- `clear(param)` drains queued entries and applies the binder's decrement operation to items still in the working set.

### Cancellation is a two-stage operation

`cancel(source, param)` removes the pointer from `_workingset` and applies the binder's decrement operation, but it does not search and remove the pointer from its priority queue. When the consumer later reaches that queue entry, `get()` pops it, sees that the pointer is no longer active, and reports cancellation rather than returning it as work. This distinction explains why queue size can temporarily include canceled entries and why the consumer must handle cancellation results.

Do not use `mlfq_nonshared_binder` as if it were automatic memory management: in that mode the queue does not delete items for you. The testcase explicitly allocates integers and deletes them after successful retrieval.

### Source-level example

`test/testcase/io/system/testcase_mlfq.cpp` creates producer and consumer threads. The producer posts 100 heap-allocated integers at random priorities in the range 0–9; the consumer retrieves an item, logs the priority/value and deletes the returned integer. A non-shared binder is used. This demonstrates concurrent queue use and priority ordering, but this document update did not execute the testcase.

## 4. Relationships
- [Event multiplexer](multiplexer.md) — event notification, distinct from work scheduling.
- `sdk/net/server/` — related asynchronous producer/consumer architecture.
- `sdk/base/system/critical_section.hpp`, `semaphore.hpp` — synchronization primitives used by the queue.
- `test/testcase/io/system/testcase_mlfq.cpp` — source-level usage example.

### Implementation source navigation

- `sdk/io/system/mlfq.hpp`

## 6. Developer Notes
The type is described as a multi-level *feedback* queue, but this implementation's visible selection policy is priority-map ordering plus FIFO per priority. The class does not itself calculate priority changes from service time; priority assignment and any feedback policy belong to the caller.
