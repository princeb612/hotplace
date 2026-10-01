# String Split

`split.hpp/.cpp` provides a reusable split context for delimiter-based string decomposition.

A `split_context_t` stores the original source and a list of `{begin,length}` ranges. The API is:

1. `split_begin()` creates and initializes the context.
2. `split_count()` reports the number of fragments.
3. `split_get()` returns an individual fragment as `binary_t` or `std::string`.
4. `split_foreach()` iterates fragments through a callback.
5. `split_chained_foreach()` allows callback-driven early termination.
6. `split_end()` releases the context.

The range-based representation avoids storing a separate string object for every fragment until a caller asks for one.

## Test

- `test/testcase/base/string/testcase_string.cpp`
