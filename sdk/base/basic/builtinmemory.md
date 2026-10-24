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

### Practical use: STL allocator and scoped pool selection

The allocator adapter is easiest to understand at its consumer boundary. The testcase constructs a fixed pool over caller-owned storage, passes that pool to a standard container's allocator, and checks both the container values and the pool's capacity after the container is destroyed.

```cpp
constexpr std::size_t BUFFER_SIZE = 1 << 20;
std::vector<char> raw_buffer(BUFFER_SIZE);
builtinpool pool(raw_buffer.data(), BUFFER_SIZE);

{
    std::vector<int, builtinpool_allocator<int> > values{
        builtinpool_allocator<int>(&pool)
    };

    for (int i = 0; i < 100; ++i) {
        values.push_back(i);
    }

    _test_case.assert(values.size() == 100, __FUNCTION__, "container size");
    _test_case.assert(values[99] == 99, __FUNCTION__, "last value");
}

_test_case.assert(pool.total_size() == pool.available_size(),
                  __FUNCTION__, "pool capacity restored");
```

The braces are significant: the container releases its storage before the pool-capacity check. The backing `raw_buffer` is declared before the pool and remains alive throughout, because the pool does not own that externally supplied buffer. This example demonstrates allocator compatibility and release behavior; it is not a performance comparison with the default allocator.

The `pooled::scope` adapter offers a different composition: pooled containers created inside the active scope pick up its pool without receiving an allocator argument.

```cpp
builtinpool local_pool(nullptr, 64 * 1024, builtinpool_policy::expandable);

{
    pooled::scope scope(&local_pool);
    pooled::vector<int> values;
    values.push_back(100);
    // Allocations made by this container use local_pool.
}

// The previous thread-local pool binding is restored when scope is destroyed.
pooled::vector<int> fallback;
fallback.push_back(200);
```

The scope is an RAII binding of a thread-local pool pointer, not an ownership wrapper for `local_pool`. The pool must outlive containers using it, and the scope restores the previous binding on exit. The testcase exercises this selection path and logs the in-scope allocation count, but it does not assert an exact allocation count or explicitly assert restoration of the previous pointer.

## 5. Relationships

- `builtinpool_allocator<T>` adapts the pool to standard-container allocation conventions.
- The fixed-buffer constructor ties pool validity to the supplied backing buffer's lifetime.
- `variant` and `basic_stream` are separate utilities; neither is a required part of pool allocation.
- The allocator implementation is in `builtinmemory.hpp/.cpp`; `testcase_builtinmemory.cpp` exercises the pool and allocator-facing behavior. These links help check the adapter contract.

## 6. References

No external references are listed.
