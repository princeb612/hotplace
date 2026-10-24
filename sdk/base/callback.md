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

### Concrete consumer path: module enumeration callback

The Windows module enumerator shows how an extended callback is used as a synchronous visitor with an explicit stop signal:

```cpp
CALLBACK_CONTROL cbControl = CONTINUE_CONTROL;
// For each MODULEENTRY32 entry:
LPVOID pData[1];
pData[0] = &me;
callback_handler(enum_modules_t::enum_toolhelp, 1, pData, &cbControl, param);

if (STOP_CONTROL == cbControl) {
    break;
}
```

The enumerator passes a type discriminator, a count, an array of payload pointers, the control pointer, and the caller's parameter. Here `pData[0]` points to the current local `MODULEENTRY32 me`; a callback must not retain that pointer after the invocation unless it copies the data. Setting `STOP_CONTROL` requests that this enumeration loop stop. The callback contract does not itself specify the payload's concrete type or lifetime; those details come from this enumerator.

Source: `sdk/base/system/windows/sdk.cpp`, `enum_modules_toolhelp()`.

## 5. Relationships

- `sdk/base/charset.hpp` — defines the platform text-mode macros that affect the narrow/wide callback aliases.
- `sdk/base/error.hpp` — supplies `return_t`, the callback result type.
- `sdk/base/system/thread.hpp` and platform thread implementations — consumers of thread-related callback conventions.
- Individual enumeration APIs define the payload contract and callback invocation lifetime.

## 6. References

No external references are listed.
