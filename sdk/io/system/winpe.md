## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — PE checksum algorithm and scope            │
└──────────────────────────────────────────────┘
```

# Windows PE helpers

## 1. Role

`winpe` currently exposes a small PE-format utility: `winpe_checksum`. It should not be mistaken for a full PE parser, a signature verifier, or the Authenticode image-digest implementation.

## 2. Data Model

`winpe_checksum` maintains two pieces of state:

- `_checksum`: accumulated 16-bit words with carry folding;
- `_size`: total number of bytes passed to `update()`.

The header uses native Windows PE definitions on Windows and the project's compatibility declarations in `linux/winnt.hpp` on Linux.

## 3. Behavior Model

### Checksum lifecycle

```text
init()
  |
  v
update(data, size)  (one or more chunks)
  |
  v
finalize(checksum)
```

`init()` resets the accumulated checksum and byte count. Each `update()` folds input words into the checksum state and tracks the supplied byte count; `finalize()` produces the checksum result. This is the PE checksum calculation, not certificate-chain or Authenticode signature verification.


### What checksum does it calculate?

`update()` sums 16-bit words and folds carry bits back into the low 16 bits. `finalize()` folds the remaining carry and adds the accumulated byte count. The API is incremental, so a caller can feed a buffer in chunks after calling `init()`.

The implementation iterates over `bytelen >> 1` words; an odd trailing byte is not added as a word, although the full byte count is included in `_size`. The input pointer must be non-null. Initialize a new calculation before processing another image so state is not carried over.

A PE checksum is not an Authenticode digest. Authenticode hashing has format-specific exclusions and is part of signature verification; a checksum match alone does not authenticate a file.

### Source-level evidence

No dedicated testcase for `winpe_checksum` was identified in the reviewed source paths. `sdk/crypto/authenticode/` is a related consumer of PE/certificate structures, but its verification flow is not evidence that each checksum API path is independently tested.

## 5. Relationships

- [Platform-specific I/O support](platform.md) — OS-specific PE declarations.
- `sdk/crypto/authenticode/` — separate image-digest and certificate/signature verification path.

### Implementation source navigation

- `sdk/io/system/winpe.hpp`
- `sdk/io/system/winpe.cpp`
- `sdk/io/system/linux/winnt.hpp`
- `sdk/crypto/authenticode/`

## 6. References

- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — PE image layout and checksum field.
- [Microsoft Learn: Authenticode](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode) — signature digest and verification, distinct from the PE checksum.
