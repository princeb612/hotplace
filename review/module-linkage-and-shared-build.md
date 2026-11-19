# Module Linkage and Shared-Build Boundary

## Source Baseline

- Source revision: 1132
- Source base : Revision 1132

## 1. Review Perspective

The important change in revisions 1112–1113 is not simply that hotplace can be built as a shared library. It makes the module boundary explicit in a second dimension: the boundary must hold both when modules are linked statically and when each module is consumed through a shared-library interface.

This is a cross-cutting review topic because the contract spans root build selection, per-module build definitions, public declarations, dependency relationships, and platform-specific symbol handling. No single module README can explain the whole contract.

## 2. The Architectural Relationship

```text
             root build configuration
                       |
                       v
              static / shared choice
                       |
                       v
            module dependency graph
                       |
                       v
            per-module build identity
                       |
                       v
           public symbol boundary
                       |
                       v
        consumer sees the intended API
```

For a static build, the modules' symbols are resolved through the static link arrangement. For a shared build, each module must also express which declarations it exports and which declarations it consumes from another module. The build configuration and the public API declarations therefore form one contract rather than two independent implementation details.

At Revision 1132, the root defaults are `SUPPORT_STATIC=1` and `SUPPORT_SHARED=0`. The root `MODULE_LIB_TYPE` selection checks `SUPPORT_STATIC` first; selecting the shared-only dependency path therefore requires `SUPPORT_STATIC=0` together with `SUPPORT_SHARED=1`. If both are enabled, both library targets can be generated, but the root dependency selector still chooses the static type for its shared dependency variable.

The central relationship is:

> A module boundary is only reliable when the dependency graph, library type, and symbol visibility agree.

## 3. Why the API Boundary Is Cross-Cutting

The project has distinct base, I/O, crypto, and network libraries, with ODBC optional. These are separate build units, but they are not independent: higher-level modules consume lower-level interfaces, and the same public header can be seen from either side of a shared-library boundary.

```text
base
  ^
  |
 io
  ^
  |
crypto / net
  |
  +--- optional ODBC integration
```

This is a conceptual dependency sketch, not a complete link-order diagram. The review concern is that a declaration may need different treatment depending on whether its module is currently being built or consumed by another module. Per-module API annotations encode that distinction.

The implementation details live in the source tree. The architecture-level observation is that **symbol visibility is part of the module interface**, not merely a compiler decoration.

## 4. Platform Differences Are Part of the Same Contract

The export/import mechanism differs by toolchain. Windows and MinGW use platform-specific export/import annotations; GCC shared builds use symbol visibility; static builds do not need the same shared-library annotations.

```text
                   module API
                       |
             +---------+---------+
             |                   |
       shared build         static build
             |                   |
      visibility policy     ordinary static link
             |
      toolchain-specific form
```

These are different mechanisms serving the same architectural purpose: preserve the public boundary while allowing implementation symbols to remain appropriately scoped. This is why a shared-build change must be considered across module declarations and build definitions, rather than as a single linker flag.

At Revision 1132, `sdk/base/types.hpp` implements this split: Windows/MinGW use `__declspec(dllexport/dllimport)` selected by `HOTPLACE_*_SHARED`; GCC uses `visibility("default")` for the public API macros under `SUPPORT_SHARED`. Each module's shared target defines its own `HOTPLACE_BASE_SHARED`, `HOTPLACE_IO_SHARED`, `HOTPLACE_CRYPTO_SHARED`, or `HOTPLACE_NET_SHARED` marker. The GNU link path also uses `sdk/version.script` to export the `hotplace::*` namespace and selected type metadata while keeping other symbols local.

## 5. Revision Evidence and Its Limits

- **Revision 1112:** the project recorded a successful MinGW64 shared-build test and introduced per-module API export/import handling.
- **Revision 1113:** the root CMake configuration and Windows test-runtime setup were adjusted, and an MSVC concurrency-header compile conflict was corrected.

The evidence supports a specific conclusion: hotplace has an explicit shared-build API boundary, and the MinGW64 shared-build path was exercised. It does **not** establish that every compiler, operating system, optional dependency, or static/shared combination has been tested.

The MSVC concurrency correction belongs to the same portability checkpoint, but it is not itself evidence about symbol export correctness. Keeping those claims separate prevents unrelated platform fixes from being treated as one broad portability guarantee.

## 6. What This Adds to the Existing Architecture Review

The existing review topics focus on parser/runtime relationships, reusable data abstractions, protocol/session boundaries, and crypto/protocol identity. The shared-build work adds another kind of cross-cutting boundary:

```text
logical module architecture
          |
          v
build-time module graph
          |
          v
link-time public interface
          |
          v
runtime library composition
```

This relationship matters because a module architecture that works only when everything is linked in one static arrangement is not automatically equivalent to the same architecture exposed as separately loadable libraries. Shared builds make the public interface boundary visible to the toolchain and to downstream consumers.

The review should therefore track shared-build support as a set of evidenced configurations, not as a binary claim that the project either supports shared libraries or does not.

## 7. Related Source

Implementation details and the authoritative local descriptions remain in the source tree:

- Root build configuration and make.sh
- sdk/base/types.hpp and module-specific CMake definitions
- sdk/version.script
- Platform-specific Windows type definitions

These paths are included to anchor the review to the implementation; this document intentionally does not duplicate their API-macro definitions or line-by-line CMake behavior.

## 8. Current Assessment

Revisions 1112–1113 establish the historical architecture checkpoint: module symbol visibility became an explicit part of the shared-build arrangement, and MinGW64 has a recorded shared-build test. A Revision 1132 source recheck confirms that the same per-module export/import contract remains in place; the root default is still static-only, and no additional shared-build execution is claimed here.

The next useful evidence would be additional build results from other supported compiler/platform combinations, especially where their symbol-export conventions differ. Until then, the accurate statement is that the shared-build boundary has been implemented and tested in a specific configuration—not that all shared builds are universally verified.

---

**GPT Review**

Reviewed against the hotplace source/documentation state through **revision 1132**; the recorded MinGW64 execution evidence remains Revision 1112.
