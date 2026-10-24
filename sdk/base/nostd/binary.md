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

# Binary utilities and tagged byte accumulation

## 1. Role

The binary utility headers provide two different facilities:

- `binary.hpp` appends values and byte ranges to a `binary_t` buffer.
- `binaries.hpp` defines `t_binaries<T, TAG>`, a thread-protected map of tagged byte entries that can be assembled from sequential or offset writes and consumed after enough data has arrived.

The first builds a byte sequence. The second tracks multiple named byte sequences and their assembly state.

## 2. Data Model

`binary_t` is the contiguous byte-sequence representation used by the append helpers. `t_binaries<T, TAG>` is a separate tagged accumulator whose entry layout is described below.

### `t_binaries<T, TAG>` entries

Each map entry contains:

- `tag` — caller-supplied metadata.
- `bin` — accumulated byte buffer.
- `part` — a range set tracking written intervals.
- `flags` — entry behavior flags.
- `finsize` — expected final size when `bin_set_fin` is supplied.
- `pos` — progress position used by callback-based consumption.

The map is protected by a `critical_section`. The template key `T` identifies each entry; `TAG` carries a caller-defined type of metadata.

## 3. Behavior Model

`binary_t` byte storage and `t_binaries<T, TAG>` accumulation are separate responsibilities. The former represents bytes and supports append operations; the latter tracks tagged values, fragment accumulation, and whether a complete value has been assembled. For TLS-secret-style accumulation, the lifecycle is assign complete value, append fragments, retrieve the accumulated value, then erase the entry when it is no longer needed.

### `binary_push()` and `binary_append()`

Append one byte or a value/range to the end of a `binary_t`. The no-transformer integral overload preserves the host representation of the converted integer value; protocol callers should pass an explicit transformer when the wire byte order must be fixed. Floating-point overloads first use `binary32_from_fp32()` or `binary64_from_fp64()`.

### `binary_append_n()`

Reserves the requested number of bytes and writes a width-constrained representation. When the requested width is narrower than the source type, the implementation selects the corresponding portion of the transformed value; when wider, it adds padding. Verify the intended width and sign representation at the call site, especially for protocol fields.

### `assign(id, ...)`

Replaces the entry's current byte content, resets its tracked ranges, and records the supplied bytes as one written interval. If `bin_set_fin` is set, it records the final size.

### `append(id, ...)`

Adds bytes to the current end and extends the interval map. This is appropriate for sequential fragments.

### `write(id, offset, ...)`

Writes at a specified offset, expands the buffer when needed, and records the written interval. This permits fragments to arrive out of order; a buffer may exist before all its ranges are present.

### `produce()`

Selects the appropriate operation based on the overload and flags: `bin_trunc` chooses replacement for sequential input, otherwise bytes are appended; offset-based forms delegate to `write()`.

### `is_fragmented(id)`

Merges the recorded ranges and checks whether the entry covers one continuous interval from offset zero to the buffer end. If a final size was set, the assembled size must also match it. This distinguishes “some bytes are buffered” from “the full byte sequence is available.”

### `peek()` and `get()`

`peek()` copies an existing entry to caller-owned storage and returns `not_found` for an absent ID. `get()` returns a reference to the map entry's internal buffer and uses map indexing; it is not a non-mutating checked lookup. Callers needing explicit missing-entry handling should use `peek()`.

### `consume()`

The overload returning a whole `binary_t` moves the buffer out and then clears or removes the entry depending on `bin_keep_entry`. The size overload removes a prefix and reports `out_of_range` if the requested size exceeds the current buffer. The callback overload refuses fragmented entries with `more_data`, invokes the consumer with the buffer and saved position, and removes or clears the entry after successful full consumption.

### `clear()` and concurrency

`clear()` removes all entries. Unlike most per-entry mutation methods, the current implementation does not acquire `_lock` around `_map.clear()`, so callers should avoid concurrent use with other operations unless external synchronization is provided.

### `reserve()`, tags, and enumeration

`reserve()` creates a persistent entry with a tag and the keep-entry flag. `set_tag()` / `get_tag()` update or retrieve metadata, while `for_each()` enumerates entries under the internal lock. The callback therefore runs while the lock is held; avoid re-entering the same `t_binaries` object from that callback.

## 5. Relationships
- [Shared types](../types.md) — defines `binary_t`.
- [Endian and wire integers](../system/endian-and-wire-integers.md) — provides the byte-order transformers and custom-width helpers.
- [IEEE-754](../system/ieee754.md) — converts native floating-point values to their bit representation.
- [Range set](range_set.md) — `t_binaries` uses a range set to track received/written spans.
- `sdk/base/system/critical_section.hpp` — protects entry mutations and metadata access.
- `sdk/base/encoding/` — encoders can consume the byte buffers produced by these helpers. The implementation is split between `binary.hpp` and `binaries.hpp`; `testcase_binary.cpp` provides source-level examples.

## 6. References

No external references are listed.
