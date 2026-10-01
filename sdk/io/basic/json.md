# JSON Helper

## Role

`sdk/io/basic/json.hpp` contains small inline helpers for opening JSON text or a JSON file through the project's Jansson dependency.

The helpers are intentionally thin:

```text
JSON text / file
      |
      v
json_open_stream / json_open_file
      |
      v
    json_t*
```

## APIs

`json_open_stream()` calls Jansson's `json_loads()`.

`json_open_file()` calls Jansson's `json_load_file()`.

Both functions:

- validate the output pointer and input
- return hotplace `return_t` status values
- return the parsed `json_t*` through the output parameter
- optionally suppress detailed parse-error tracing

The caller remains responsible for the Jansson reference lifetime, including `json_decref()`.

## Scope

This is not a JSON object model implemented by hotplace. It is a compatibility/convenience boundary around the existing Jansson API.

The module should therefore remain small unless the project later develops a project-specific JSON abstraction.

## Related source

- `sdk/io/basic/json.hpp`
- Jansson (`jansson.h`)
- `sdk/base/system/trace.hpp`

## Current test coverage

No dedicated JSON testcase was found under `test/testcase/io/basic` in the rev1095 source tree inspected for this document.
