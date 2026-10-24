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

# Shared instance and reference counting

## 1. Role

### Introduction

The system layer contains two closely related ownership helpers: `reference_counter` and the templated `t_shared_reference` / `t_shared_instance` classes.

## 2. Data Model

### Reference counter

`reference_counter` is the smallest building block. It stores an integer count and provides:

- `addref()`
- `delref()`
- `getref()`

The increment/decrement operations use the project's platform atomic helpers.

It does not own an object and therefore does not perform deletion itself. The containing object decides what to do when `delref()` reaches zero.

### Object relationship

```text
object
  |
  +-- t_shared_reference<T>
        counter
        object pointer
```


`t_shared_reference<T>` couples an object pointer with an embedded reference count. `t_shared_instance<T>` keeps the counter separately allocated from the managed object.

### Ownership caveat

These classes are reference-counting primitives, not a complete replacement for every smart-pointer ownership model. Copy operations are intentionally disabled; ownership transfer is represented by move operations or explicit `addref`/`delref` calls.

## 3. Behavior Model

### `t_shared_reference`

`make_share()` attaches the object and establishes the first reference. `delref()` deletes the object when the count reaches zero.

The class was written to provide a smart-pointer-like ownership pattern without requiring the project to depend on `std::shared_ptr` for its older compatibility targets.

### `t_shared_instance`

`t_shared_instance<T>` keeps the counter separately allocated from the managed object. It supports move construction/assignment and `operator->`, `operator*`, and conversion to `T*` for convenient use.

It is used in hotplace where an owning, reference-counted object needs to be shared through project-specific infrastructure.

### Composite ownership: CBOR map example

The reference-counting primitive itself does **not** automatically discover or release an object's children. A composite type must explicitly propagate ownership operations to its members. `cbor_map` does this: `addref()` calls `addref()` on every stored `cbor_pair` before incrementing the map's own counter, and `release()` calls `release()` on every stored pair before decrementing the map counter. Nested pairs, maps, arrays, and data objects participate through their own implementations.

```cpp
cbor_map* root = new cbor_map(cbor_flag_t::cbor_indef);
(*root)
    .add("a", new cbor_data(1))
    .add("b", [](cbor_array* obj) -> void {
        *obj << new cbor_data(2) << new cbor_data(3);
    }, cbor_flag_t::cbor_indef);
do_cbor_test(root, "bf61610161629f0203ffff");
root->release();
```

In this pattern, the root map owns the composed CBOR object graph through its pairs. Calling `root->release()` releases the references held through the map and, when the root's reference count reaches zero, deletes the root object; member releases propagate through the nested structure so owned members can be deleted when their own counts reach zero. A call to `addref()` on the map likewise increments the references of all stored pairs as well as the map's own reference count. Each retained root reference must be balanced by a corresponding `release()`.

This recursive behavior is specific to composite types such as `cbor_map` that implement propagation. Do not assume every class using `t_shared_reference` automatically manages child objects.

## 4. Relationships

- `sdk/base/nostd/set.hpp` — `t_set_runtime` uses a shared-instance handle for its concrete set object.
- `sdk/base/nostd/value.hpp` — a separate deferred-value abstraction; it uses future/promise state rather than this ownership counter.
- `sdk/io/cbor/cbor_map.hpp/.cpp` — concrete composite ownership: map-level `addref()` / `release()` propagate to stored pairs and nested members.
- `test/testcase/base/system/testcase_shared.cpp` — explicit reference release and move/ownership lifetime checks, including single destruction at the end of ownership.
- `sdk/io/cbor/cbor_map.hpp` — includes the nested-map ownership example; `cbor_map.cpp` implements member-wise reference propagation.
- This utility is distinct from `std::shared_ptr`; callers must follow its own attach/release contract.

## 5. References

No external references are listed.
