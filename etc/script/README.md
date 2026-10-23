## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1108
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: environment-specific shell helper functions
```

# Environment scripts

## 1. Role

`etc/script/` provides shell functions that help prepare supported development environments for building and running hotplace. These files are environment-specific helpers; they are not standalone applications, a platform-independent package manager, or a replacement for the root `make.sh` and CMake build.

## 2. Data Model

```text
script/
├─ env.mingw64
├─ env.rockylinux
└─ env.ubuntu
```

Each file defines functions intended to be loaded into the current shell with `source`.

| Function | MinGW64 | Rocky Linux | Ubuntu |
|---|---|---|---|
| `install_packages()` | Yes | Yes | Yes |
| `export_path()` | Yes | Yes | Yes |
| `copy_dir_files()` | Yes | — | — |
| `redist()` | Yes | — | — |

The helper names are similar across environments, but their implementations and package commands differ. The current files use `PATH` for the MinGW64 shared-build path and `LD_LIBRARY_PATH` for Linux shared-build paths.

## 3. Behavior Model

```text
select environment file
        │
        ▼
source etc/script/env.<environment>
        │
        ├─ install_packages()
        │    └─ invokes environment package manager
        │
        ├─ export_path()
        │    └─ adds repository lib/ to PATH or LD_LIBRARY_PATH
        │
        └─ MinGW64-only helpers
             ├─ copy_dir_files()
             └─ redist() ──► redist/ DLL copies (MSYS/Cygwin)
```

- `install_packages()` invokes the platform's package-management commands for compiler/build tools and selected dependencies. Review the script before running it because it can change the environment and requires elevated privileges on Linux.
- `export_path()` uses the current working directory as `HOTPLACE_HOME` and adds its `lib` directory to the relevant search path if it is not already detected there. Run it from the intended repository root.
- `copy_dir_files()` copies named files from a source directory to a destination directory; it is defined only in `env.mingw64`.
- `redist()` copies a selected set of runtime DLLs from the MSYS/Cygwin prefix into the repository's `redist/` directory when the shell's `OSTYPE` matches `msys` or `cygwin`. It is not a general Windows dependency scanner.

These are source-level descriptions of the current functions. No package installation, environment mutation, or DLL redistribution was performed as part of this documentation update.

## 4. Relationships

- [Repository resource map](../README.md) — how environment helpers fit into `etc/`.
- Root `make.sh` and `CMakeLists.txt` — primary project build orchestration.
- `lib/` — target of the shared-build search-path helper.
- `redist/` — destination used by the MinGW64 runtime DLL helper.
