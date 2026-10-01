# nostd Key/Value and Exception Utilities

`keyvalue.hpp` provides a lightweight key/value container used by protocol and text-processing code. It is distinct from the graph/container structures because its primary role is representing decoded or parsed name/value pairs.

`exception.hpp` / `exception.cpp` provide the project's exception abstraction and compatibility layer.

`string_set.hpp` / `string_set.cpp` provide a string-keyed set-oriented helper used where textual membership is needed.

## Related tests

- `testcase_exception.cpp`
- `testcase_findlte.cpp`
- `testcase_set.cpp`
