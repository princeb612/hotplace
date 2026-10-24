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

### Concrete caller path: HTTP query parameters in OAuth 2.0

The HTTP URI layer parses query text into a `skey_value`; the OAuth 2.0 authorization handler then reads named parameters from that map:

```cpp
skey_value& kv = request->get_http_uri().get_query_keyvalue();

std::string client_id = kv.get("client_id");
std::string redirect_uri = kv.get("redirect_uri");
std::string state = kv.get("state");
```

This is the useful application-level role of the string-key map: the URI parser handles the `key=value&...` text, while the handler asks for semantic parameter names. In this implementation, `get()` returns a default-constructed value if a key is missing; it does not itself distinguish “missing” from “present with an empty value.” Callers that require that distinction must check key presence or use the query API with explicit status handling.

Sources: `sdk/net/http/http_uri.cpp`, `http_uri::to_keyvalue()`; `sdk/net/http/auth/oauth2.cpp`, `oauth2_authorization_code_grant_provider::authorization_handler()`.

## 5. Relationships
- `keyvalue.hpp` implements the value map and ordering indexes; it uses `critical_section.hpp` to serialize access.

## 6. References

No external references are listed.
