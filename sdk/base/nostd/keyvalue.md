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

# Key/value utility

## 1. Role

`keyvalue.hpp` provides a lightweight key/value representation for name/value-oriented data. It is distinct from the general-purpose container family: its purpose is to carry a pair-like value rather than to provide a collection algorithm.

## 2. Data Model

The main type is `t_stringkey_value<TYPE>`. It stores values by string key, protects access with a `critical_section`, and maintains separate ordering maps alongside the value map. The default value type is `std::string`; `operator[]` uses string-specific conversion, so callers should not assume every `TYPE` behaves as a fully generic mapped value.

## 3. Behavior Model

### Lookup and mutation flow

```text
set(name, value, mode) ─► value map + ordering metadata
          │
          ├─ exist() / query() / get() / operator[] ─► lookup result
          └─ remove() / clear() ─► update or reset stored state
```

Duplicate-key behavior depends on the selected mode; see the operation rules below.

### Lookup and mutation

- set(name, value, mode) inserts a new key or applies the selected duplicate-key policy. kv_update replaces an existing value; kv_keep and kv_move are copy/merge modes and do not overwrite an existing value through set().
- update() is shorthand for set(..., kv_update).
- exist(), query(), get(), and operator[] provide lookup paths. query() returns not_found when the key is absent; get() returns a default-constructed value if lookup fails.
- remove() removes a key, and clear() resets values and ordering state.
- copy(), copyfrom(), and copyto() transfer entries between maps. kv_move clears the destination before copying, kv_update overwrites duplicate keys, and kv_keep preserves existing destination values.
- key_value_case_sensitive controls whether lookup keys are normalized to lowercase. The default constructor enables case-sensitive keys.

## 5. Relationships
- `keyvalue.hpp` implements the value map and ordering indexes; it uses `critical_section.hpp` to serialize access.

## 6. References

No external references are listed.
