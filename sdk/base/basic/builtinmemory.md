# Builtin Memory

`builtinmemory` provides a memory-pool implementation centered on `builtinpool`.

The pool can operate with a fixed memory region or expand by allocating additional segments. The default expansion unit is `BUILTINMEMORY_EXPANSION_SIZE` (1 MiB).

## Main capabilities

- allocation and deallocation
- in-place or moving reallocation
- fixed and expandable pool policies
- multiple memory segments for expandable pools
- total, allocated, and available size tracking
- address-range validation
- STL-compatible allocator adapters

`builtinpool_allocator<T>` adapts a pool to standard containers. The source also provides aliases such as `builtinpool_vector`, `builtinpool_deque`, `builtinpool_list`, `builtinpool_map`, and related containers.

A `scope` helper can bind a pool to the current thread, and `pooled_allocator` can obtain that pool implicitly.

## Reallocation

`reallocate()` first tries to resize the existing allocation when the surrounding free space permits it. If that is not possible, the implementation allocates another region and moves the existing data.

This makes reallocation useful both for ordinary pool users and for containers using the allocator adapter.

## Tests

`test/testcase/base/basic/testcase_builtinmemory.cpp`

The testcase covers allocation/deallocation, reallocation, shrinking and expanding allocations, and free-list/segment behavior.

## Related source

- `sdk/base/basic/builtinmemory.hpp`
- `sdk/base/basic/builtinmemory.cpp`
- `test/testcase/base/basic/testcase_builtinmemory.cpp`
