## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Callback contracts

## 1. Role

`callback.hpp` defines shared function-pointer signatures for enumeration, typed dispatch, and thread callbacks. It provides the calling convention vocabulary used by components that enumerate entries or report items without owning the caller's operation.

## 2. Data Model

- `CALLBACK_HANDLER` receives opaque data and caller parameter.
- `TYPE_CALLBACK_HANDLER` adds a `uint32` type discriminator.
- `TYPE_CALLBACK_HANDLEREXV` receives a type, a count, an array of opaque data pointers, a control output, and caller parameter.
- `ENUM_CALLBACK_HANDLERA/W` enumerate names using narrow or wide character strings, with parameter and context pointers.
- `ENUMTYPE_CALLBACK_HANDLERA/W` add an integer-sized type discriminator to name enumeration.
- `THREAD_CALLBACK_ROUTINE` accepts one opaque argument and returns `return_t`.

The signatures use `void*` for payload and context. Their actual types, ownership, and lifetime are defined by the caller and the API invoking the callback.

## 3. Behavior Model

**Enumeration callbacks**

The narrow/wide aliases select a character representation only when `_MBCS`/`MBCS` or `_UNICODE`/`UNICODE` is already defined as `callback.hpp` is parsed. `charset.hpp` defaults to MBCS when neither mode is selected, but include order matters: including `callback.hpp` before `charset.hpp` can leave the generic aliases undefined unless the build defines a mode macro.

**Extended typed callback control**

`TYPE_CALLBACK_HANDLEREXV` receives a `CALLBACK_CONTROL*`. The callback can communicate `CONTINUE_CONTROL` or `STOP_CONTROL` to its enumerator. The enumerator must define when it checks this value and whether the control pointer is optional.

**Thread callback**

`THREAD_CALLBACK_ROUTINE` standardizes a return-code-bearing callback shape; it does not create a thread or establish synchronization by itself.

## 4. Relationships

- `sdk/base/charset.hpp` — defines the platform text-mode macros that affect the narrow/wide callback aliases.
- `sdk/base/error.hpp` — supplies `return_t`, the callback result type.
- `sdk/base/system/thread.hpp` and platform thread implementations — consumers of thread-related callback conventions.
- Individual enumeration APIs define the payload contract and callback invocation lifetime.
