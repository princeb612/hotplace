## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — key/value APIs, callback data, deletion    │
└──────────────────────────────────────────────┘
```

# Windows Registry wrapper

## 1. Role

`windows_registry` wraps Windows Registry operations for code that needs to create/open keys, enumerate subkeys and values, read/write values, and delete keys. It is a Windows-specific utility, not a portable configuration-storage abstraction.

## 2. Data Model

The API has ANSI and wide-character overloads. The build's MBCS/Unicode setting selects the implementation signatures and `ENUM_VALUE_CONTEXT` alias.

A value-enumeration callback receives the value name plus an `ENUM_VALUE_CONTEXT` containing the name buffer, registry type (`dwType`), data pointer (`pData`) and data size (`dwDataSize`). The bytes must be interpreted according to the returned registry type; not every value is a NUL-terminated string.

The main operations are:

- `create_key` / `open_key` — return an `HKEY` owned by the caller;
- `close_key` — calls `RegCloseKey`;
- `enumerate_subkeys` / `enumerate_values` — iterate and invoke the supplied callback;
- `set_string` / `set_value`, `query_value`, `delete_value`;
- `delete_key` and `delete_sub_nodes` — key deletion, with optional recursive subkey deletion.

## 3. Behavior Model

### Access rights and key lifetime

The caller chooses `REGSAM` rights when opening/creating a key. Enumeration or querying can fail if the opened handle lacks the relevant access rights. Every successfully opened/created handle must be closed with `close_key`, including early-return/error paths.

### Enumeration callback contract

The wrapper checks that the callback is non-null, then enumerates names and invokes the callback with the caller parameter. Value enumeration passes a context with type and data bytes. The implementation uses fixed-size buffers for names and value data; callers should not assume that arbitrarily large registry values are fully represented by these buffers. The callback should inspect the reported type/size rather than assume string encoding.

### Recursive deletion

`delete_key(..., registry_option_t::delete_sub_keys)` delegates to `delete_sub_nodes`. The helper attempts direct deletion first, then opens the key, enumerates child keys, recursively deletes them and retries deletion. It uses a bounded retry count for cases where deletion fails. This is destructive Windows Registry behavior; callers should validate the root and subkey path before requesting recursive deletion.

### Source-level example

The header's example opens a key under `HKEY_LOCAL_MACHINE` with enumeration/query rights, enumerates subkeys through a callback, and closes the handle. This documents the API shape, not a runtime test result. No dedicated testcase for this wrapper was identified in the reviewed source paths.

## 4. Relationships
- [Platform-specific I/O support](platform.md) — Windows-only boundary.
- `sdk/io/system/windows/windows_registry_charset.cpp` — character-set-dependent Win32 calls.
- `sdk/io/system/windows_registry.hpp` — public wrapper declaration.

### Implementation source navigation

- `sdk/io/system/windows/windows_registry.hpp`
- `sdk/io/system/windows/windows_registry.cpp`
- `sdk/io/system/windows/windows_registry_charset.cpp`

## 5. References
- [Microsoft Learn: Registry functions](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-functions) — Win32 registry APIs including RegCreateKeyEx, RegOpenKeyEx, RegEnumKeyEx, RegEnumValue, RegQueryValueEx, and RegDeleteKey.
