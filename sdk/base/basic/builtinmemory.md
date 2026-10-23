## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Builtin Memory

## 1. Role

### Introduction

`builtinmemory` provides a memory-pool implementation centered on `builtinpool`.

The pool can operate with a fixed memory region or expand by allocating additional segments. The default expansion unit is `BUILTINMEMORY_EXPANSION_SIZE` (1 MiB).

## 2. Data Model

### Pool state and block representation

`builtinpool` keeps its operational state in `buitinmemory_context`:

- `_base`, `_top`, and `_limit` describe the active initial memory range.
- `_policy` selects `fixed` (no growth on exhaustion) or `expandable` (add a segment when necessary).
- `_expansion_size` controls the default segment growth unit; the default is `BUILTINMEMORY_EXPANSION_SIZE` (1 MiB).
- `_hint` is the sentinel for the linked chain of reusable free blocks; its `_size` tracks the free capacity represented by that chain.
- `_segments` links separately allocated backing segments owned by the pool when it allocates storage itself or expands.

Each block starts with a `buitinmemory_block_descriptor`. A free block uses the `chain` view (`_signature`, `_size`, `_prev`, `_next`); an allocated block uses the `entry` view (`_signature`, `_size`, `_lock`, `_parent`). The returned user pointer follows the descriptor, and `_parent` lets `deallocate()` reject blocks that do not belong to this pool.

`total_size()`, `allocated_size()`, and `available_size()` describe different quantities; available capacity does not imply that a single adjacent region can satisfy a reallocation in place.

### Allocator adapters and ownership

`builtinpool_allocator<T>` adapts a pool to standard-container allocation conventions. The source also provides aliases such as `builtinpool_vector`, `builtinpool_deque`, `builtinpool_list`, `builtinpool_map`, and related containers. Copies of the allocator share the same pool handle. A default allocator creates an expandable pool; an allocator constructed from an external `builtinpool*` uses a non-owning shared-pointer wrapper, so the external pool must outlive all containers and allocations using it.

A `scope` helper can bind a pool to the current thread, and `pooled_allocator` can obtain that pool implicitly.

## 3. Behavior Model

### Reallocation flow

`reallocate()` first tries to resize the existing allocation when the surrounding free space permits it. If that is not possible, the implementation allocates another region and moves the existing data.

This makes reallocation useful both for ordinary pool users and for containers using the allocator adapter.

```text
reallocate(ptr, new_size)
  ├─ adjacent capacity available ─► resize in place
  └─ otherwise ──────────────────► allocate new region
                                      ├─ copy old contents
                                      ├─ release old region
                                      └─ return new address
```

### Allocation and deallocation flow

`allocate(size)` aligns the requested size, includes descriptor overhead, then searches the reusable free-block chain. A fitting block is either consumed whole or split; the descriptor is changed from the free-chain view to the allocated-entry view. If no block fits, `fixed` returns failure, while `expandable` attempts to add a segment and retries.

`deallocate(ptr)` recovers the descriptor immediately before the user pointer, checks its allocation signature and owning context, and inserts the block into the address-ordered free chain. Invalid or foreign pointers are ignored by the implementation's validation path.

### Lifetime and allocator adapters

For a pool constructed over external memory, the backing buffer must outlive all pool operations. For expandable pools, the pool manages additional segments according to its implementation policy. `builtinpool_allocator<T>` makes the pool usable through container allocation interfaces, so the pool must also outlive containers and allocations that use that allocator.

The allocation and reallocation paths above are the core state transitions. The testcase creates a one-megabyte backing buffer, checks `total_size()`, allocates two blocks, writes patterns to the returned regions, and exercises release/reallocation paths. See `test/testcase/base/basic/testcase_builtinmemory.cpp` for the source-level sequence. The pool's backing storage and any containers using `builtinpool_allocator<T>` must remain alive for the duration of their allocations.

## 4. Relationships

- `builtinpool_allocator<T>` adapts the pool to standard-container allocation conventions.
- The fixed-buffer constructor ties pool validity to the supplied backing buffer's lifetime.
- `variant` and `basic_stream` are separate utilities; neither is a required part of pool allocation.
- The allocator implementation is in `builtinmemory.hpp/.cpp`; `testcase_builtinmemory.cpp` exercises the pool and allocator-facing behavior. These links help check the adapter contract.
