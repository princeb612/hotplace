## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
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

### Main capabilities

- allocation and deallocation
- in-place or moving reallocation
- fixed and expandable pool policies
- multiple memory segments for expandable pools
- total, allocated, and available size tracking
- address-range validation
- STL-compatible allocator adapters

`builtinpool_allocator<T>` adapts a pool to standard containers. The source also provides aliases such as `builtinpool_vector`, `builtinpool_deque`, `builtinpool_list`, `builtinpool_map`, and related containers.

A `scope` helper can bind a pool to the current thread, and `pooled_allocator` can obtain that pool implicitly.

### Reallocation

`reallocate()` first tries to resize the existing allocation when the surrounding free space permits it. If that is not possible, the implementation allocates another region and moves the existing data.

This makes reallocation useful both for ordinary pool users and for containers using the allocator adapter.

## 3. Behavior Model

### Allocation and segment behavior

A pool can be backed by a fixed caller-provided memory region or use an expandable policy that adds segments. Allocation success, free-list reuse, and total/available size are related but distinct observations: a pool can have free capacity that is not necessarily contiguous enough for an in-place growth operation.

`reallocate()` attempts to retain the existing allocation when adjacent capacity permits it. Otherwise it may allocate a new region and move the existing contents. Callers must use the returned pointer after reallocation; they must not assume the old address remains valid.

### Lifetime and allocator adapters

For a pool constructed over external memory, the backing buffer must outlive all pool operations. For expandable pools, the pool manages additional segments according to its implementation policy. `builtinpool_allocator<T>` makes the pool usable through container allocation interfaces, so the pool must also outlive containers and allocations that use that allocator.

### Source testcase

The testcase creates a one-megabyte backing buffer, verifies `total_size()`, allocates two blocks, writes patterns to the returned regions, and exercises release/reallocation paths. See `test/testcase/base/basic/testcase_builtinmemory.cpp` for the allocation/reallocation sequence.

## 4. Relationships

- `builtinpool_allocator<T>` adapts the pool to standard-container allocation conventions.
- The fixed-buffer constructor ties pool validity to the supplied backing buffer's lifetime.
- `variant` and `basic_stream` are separate utilities; neither is a required part of pool allocation.
- The allocator implementation is in `builtinmemory.hpp/.cpp`; `testcase_builtinmemory.cpp` exercises the pool and allocator-facing behavior. These links help check the adapter contract.
