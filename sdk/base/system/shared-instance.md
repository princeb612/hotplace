# Shared instance and reference counting

The system layer contains two closely related ownership helpers: `reference_counter` and the templated `t_shared_reference` / `t_shared_instance` classes.

## Reference counter

`reference_counter` is the smallest building block. It stores an integer count and provides:

- `addref()`
- `delref()`
- `getref()`

The increment/decrement operations use the project's platform atomic helpers.

It does not own an object and therefore does not perform deletion itself. The containing object decides what to do when `delref()` reaches zero.

## `t_shared_reference`

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

## `t_shared_instance`

`t_shared_instance<T>` keeps the counter separately allocated from the managed object. It supports move construction/assignment and `operator->`, `operator*`, and conversion to `T*` for convenient use.

It is used in hotplace where an owning, reference-counted object needs to be shared through project-specific infrastructure.

## Ownership caveat

These classes are reference-counting primitives, not a complete replacement for every smart-pointer ownership model. Copy operations are intentionally disabled; ownership transfer is represented by move operations or explicit `addref`/`delref` calls.

## Test

`test/testcase/base/system/testcase_shared.cpp` covers both forms:

- an object containing `t_shared_reference<T>` and explicitly releasing references;
- a `t_shared_instance<T>` moved between two owners, verifying that destruction occurs once at the end of the ownership lifetime.
