## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Shared instance and reference counting

## 1. Role

### Introduction

The system layer contains two closely related ownership helpers: `reference_counter` and the templated `t_shared_reference` / `t_shared_instance` classes.

## 2. Model

### Reference counter

`reference_counter` is the smallest building block. It stores an integer count and provides:

- `addref()`
- `delref()`
- `getref()`

The increment/decrement operations use the project's platform atomic helpers.

It does not own an object and therefore does not perform deletion itself. The containing object decides what to do when `delref()` reaches zero.

### Ownership caveat

These classes are reference-counting primitives, not a complete replacement for every smart-pointer ownership model. Copy operations are intentionally disabled; ownership transfer is represented by move operations or explicit `addref`/`delref` calls.

## 3. Important behavior and lifetime

### `t_shared_reference`

`t_shared_reference<T>` couples an object pointer with an embedded reference count.

```text
object
  |
  +-- t_shared_reference<T>
        counter
        object pointer
```

`make_share()` attaches the object and establishes the first reference. `delref()` deletes the object when the count reaches zero.

The class was written to provide a smart-pointer-like ownership pattern without requiring the project to depend on `std::shared_ptr` for its older compatibility targets.

### `t_shared_instance`

`t_shared_instance<T>` keeps the counter separately allocated from the managed object. It supports move construction/assignment and `operator->`, `operator*`, and conversion to `T*` for convenient use.

It is used in hotplace where an owning, reference-counted object needs to be shared through project-specific infrastructure.

## 4. Example from the source tests

### Test

`test/testcase/base/system/testcase_shared.cpp` covers both forms:

- an object containing `t_shared_reference<T>` and explicitly releasing references;
- a `t_shared_instance<T>` moved between two owners, verifying that destruction occurs once at the end of the ownership lifetime.

## 5. Relationships

Related components and cross-module links are listed in References where available.

## 6. References

Implementation and test paths are retained in the sections above or the source tree.
