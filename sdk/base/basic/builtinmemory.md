## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Builtin Memory

## 1. Role

### Introduction

`builtinmemory` provides a memory-pool implementation centered on `builtinpool`.

The pool can operate with a fixed memory region or expand by allocating additional segments. The default expansion unit is `BUILTINMEMORY_EXPANSION_SIZE` (1 MiB).

## 2. Model

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

## 3. Important behavior and lifetime

### Allocation and segment behavior

A pool can be backed by a fixed caller-provided memory region or use an expandable policy that adds segments. Allocation success, free-list reuse, and total/available size are related but distinct observations: a pool can have free capacity that is not necessarily contiguous enough for an in-place growth operation.

`reallocate()` attempts to retain the existing allocation when adjacent capacity permits it. Otherwise it may allocate a new region and move the existing contents. Callers must use the returned pointer after reallocation; they must not assume the old address remains valid.

### Lifetime and allocator adapters

For a pool constructed over external memory, the backing buffer must outlive all pool operations. For expandable pools, the pool manages additional segments according to its implementation policy. `builtinpool_allocator<T>` makes the pool usable through container allocation interfaces, so the pool must also outlive containers and allocations that use that allocator.

### Source testcase

The testcase creates a one-megabyte backing buffer, verifies `total_size()`, allocates two blocks, writes patterns to the returned regions, and exercises release/reallocation paths. See the example below for the sequence.

## 4. Example from the source tests

### Allocation and reallocation flow

`test/testcase/base/basic/testcase_builtinmemory.cpp` creates a one-megabyte backing buffer and constructs a fixed-region `builtinpool` over it. The test allocates two blocks, writes distinct byte patterns into them, and then checks deallocation and reallocation behavior. This makes the backing-store boundary explicit: the pool is operating over memory supplied by the testcase rather than obtaining every byte from the operating system.

```text
testcase_builtinmemory.cpp
    └── raw_buffer
          └── builtinpool(raw_buffer.data(), BUFFER_SIZE)
                ├── allocate(...)
                ├── write to returned regions
                ├── deallocate(...)
                └── reallocate(...) cases
```

When investigating a failure, follow the exact testcase branch first, then inspect the free-list/segment logic in `builtinmemory.cpp`. The test's expected sizes and data patterns are more informative than the existence of a pool object alone.

## 5. Relationships

- `builtinpool_allocator<T>` adapts the pool to standard-container allocation conventions.
- The fixed-buffer constructor ties pool validity to the supplied backing buffer's lifetime.
- `variant` and `basic_stream` are separate utilities; neither is a required part of pool allocation.

## 6. References

### Related source and test

- Implementation: `sdk/base/basic/builtinmemory.hpp`, `sdk/base/basic/builtinmemory.cpp`
- Test: `test/testcase/base/basic/testcase_builtinmemory.cpp`

The allocator adapters are the bridge from `builtinpool` to container-like use. Keep pool lifetime, backing-buffer lifetime, and any allocator/container lifetime aligned.

