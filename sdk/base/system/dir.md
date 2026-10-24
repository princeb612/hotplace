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

# Directory creation helpers

## 1. Role

`dir.hpp` provides small inline helpers for creating a directory on Linux and Windows. It does not provide directory enumeration, recursive deletion, or a filesystem abstraction.

## 2. Data Model

The header exposes two functions:

- `makedir(path)` — create one directory.
- `makedirp(path)` — walk a path and create intermediate directories before creating the final directory.

Both return `bool` and use platform-specific system calls underneath.

## 3. Behavior Model

**`makedir(path)`**

Rejects an empty path. It calls `mkdir(path, 0755)` on Linux or `_mkdir(path)` on Windows. If creation reports failure, it checks whether the path already exists and is a directory; an existing directory is treated as success, while other failures return false.

**`makedirp(path)`**

Scans the supplied path for slash or backslash separators and attempts to create each accumulated prefix, then creates the final path. It avoids treating a two-character drive prefix such as `C:` as a directory. This is a simple path-prefix strategy, not a canonicalization or symlink-safe filesystem traversal algorithm.

The helper accepts both separator characters when splitting prefixes, but the underlying path and permission semantics remain platform-specific.

### Prefix-creation flow

```text
makedir(path)
  ├─ empty path ──────────────► false
  ├─ platform mkdir succeeds ─► true
  └─ mkdir fails ─────────────► check existing path
                                  ├─ already a directory ─► true
                                  └─ otherwise ────────────► false

makedirp(path)
  └─ scan slash/backslash separators
       └─ create each accumulated prefix
            └─ skip treating drive prefix such as C: as a directory
                 └─ create final path
```

`makedirp()` is a prefix-creation helper, not a path canonicalizer. It does not establish symlink safety or normalize all platform-specific path semantics.

## 4. Relationships

- `sdk/base/system/process.hpp` — accepts a working-directory string for child-process launch; it does not call `makedirp()` automatically.
- `sdk/base/system/linux/types.hpp` and `sdk/base/system/windows/types.hpp` — platform headers.
- `sdk/base/system/` — low-level OS helpers; this file is limited to directory creation.

## 5. References

- [Linux man-pages: mkdir(2)](https://man7.org/linux/man-pages/man2/mkdir.2.html) — POSIX directory creation.
- [Microsoft Learn: _mkdir, _wmkdir](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/mkdir-wmkdir?view=msvc-170) — Microsoft CRT directory creation functions.