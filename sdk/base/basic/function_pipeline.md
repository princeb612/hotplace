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

# Function Pipeline

## 1. Role

`function_pipeline<T, category>` sequences callbacks while carrying the result of the most recently executed step. It is not just a callback list: the current result is interpreted through `error_traits<T, category>`, and that interpretation controls whether ordinary steps run, whether failure handlers run, and whether a step is considered successful.

The pipeline also bridges operations that use different error conventions. A callback may return the pipeline's native `T` result (for example, an OpenSSL-style `int`) or hotplace's `return_t`. The selected `error_traits` specialization supplies the conversion and classification rules that let those results participate in the same flow.

## 2. Data Model

### Pipeline state and error policy

The key pieces of state in `function_pipeline` are:

- `_lastcode` — the current result in the pipeline's selected result type `T`; this is what the continuation predicate evaluates.
- `_discriminant` — the predicate used to classify `_lastcode` for control flow. It is initialized from the selected error traits and can be changed by pipeline helpers such as `set()` and `goahead_if_not_fail()`.
- `_returncode` — remembers a hotplace `return_t` returned by a callback, allowing an explicit hotplace error to be preserved when the pipeline result is converted back.
- `_processed_count` and `_total_count` — count steps considered and successfully processed according to the pipeline's execution logic.
- `_tracer` — optional callback used by the debug tracing path.

The policy type is declared in `sdk/base/system/error.hpp`:

```cpp
template <typename T, typename category = void>
struct error_traits;
```

Its specializations define the meaning of result values for the pipeline. The important contract includes success, exception, invalid-parameter and internal-error values, success/failure predicates, conversion to and from `return_t`, and comparison across result conventions. The `category` tag distinguishes otherwise identical C++ types whose values have different meanings.

## 3. Behavior Model

### Current specializations

- `error_traits<return_t>` uses hotplace's `errorcode_t` values. Its `is_success()` treats both `success` and `expect_failure` as success for pipeline classification. Its `is_not_fail()` asks `error_advisor` for the error category and accepts anything other than `error_category_severe`.
- `error_traits<int, errno_category>` treats zero as success. Its conversion to `return_t` maps zero to `success` and nonzero values to `internal_error`; the reverse conversion maps a hotplace success to zero and other values to its configured internal-error value.
- `error_traits<int, osslerror_category>` treats positive values as success. Its conversion to `return_t` maps success to `success` and nonpositive values to `error_openssl_inside`; the reverse conversion maps success to one and other values to zero.

These are deliberately category-specific policies, not universal interpretations of `int`. A zero from an OpenSSL-style callback is failure, while a zero from an `errno`-style callback is success.

### Result conversion and mixed callbacks

When a callback returns `T`, the pipeline stores that result as `_lastcode` and evaluates it using the selected policy. When a callback returns hotplace `return_t`, `handle_result()` first uses `error_traits<T, category>::from_return_t()` to produce the pipeline-native result used for continuation, and separately saves the original hotplace value in `_returncode`.

Consequently, `result()` returns the pipeline-native `T` value, whereas `result_to_return_t()` returns the remembered non-success `return_t` when one was supplied; otherwise it converts `_lastcode` through `to_return_t()`. This distinction matters when a pipeline mixes native library results with hotplace callbacks: conversion of a native error may be intentionally coarser than a specific `return_t` error supplied by a later callback.

### Policy and callback result flow

```text
operation / callback
  │ returns T or hotplace return_t
  ▼
function_pipeline<T, category>
  │ asks the selected error_traits specialization
  ├── is_success / is_not_fail ──► continuation and failure routing
  ├── from_return_t ─────────────► pipeline-native _lastcode
  └── to_return_t ───────────────► result_to_return_t()
                                      │
                                      ▼
                              hotplace return_t / errorcode_t

return_t classification
  │
  ▼
error_advisor::categoryof()
  │
  ▼
error_category_hint (category, test color/name)
```


### Continuation and failure handling

The pipeline's fluent methods configure when callbacks are eligible to run:

- `run()` and `run_trycatch()` execute normal steps when the current state passes the selected discriminant. `run_trycatch()` converts a caught exception to the policy's `value_exception()`; without the try/catch variant, an exception is rethrown as hotplace's `exception`.
- `walk()` and `walk_trycatch()` provide the corresponding void-callback forms. A walk does not replace `_lastcode` with a callback result; it returns the current state from its wrapper.
- `run_failed()` and `walk_failed()` are eligible when the current state fails the discriminant.
- `walk_always()` runs without regard to the current discriminant, making it useful for finalization or unconditional bookkeeping.
- `test_parameter()` sets the current result to the policy's `value_invalid_parameter()` when its checker returns false.
- `goahead_if_not_fail()` changes the continuation predicate to `error_traits<T, category>::is_not_fail`. With `return_t`, this allows a non-severe result (such as the `debug` category used in the testcase) to continue, even though it is not classified as success.

The predicate is therefore part of the error policy: the same pipeline control flow can work with different native result types, while the category specialization determines what “success” and “not failure” mean.

### Tracing and counts

`run_pipe()` expands to a source-location-aware `run()` overload in debug builds and to ordinary `run()` otherwise. When a tracer is installed with `set_tracer()`, the debug path can report a failing result together with the source file and line. The `processed()` and `size()` counters describe pipeline progress; failure-handling steps are not counted the same way as ordinary expected-success steps.

### Production use: EC key generation

A more representative application of the pipeline appears in `sdk/crypto/basic/key/crypto_keygen_ec.cpp`, in `crypto_keygen::add_ec()`. Unlike the focused unit test, this is production code: it chains parameter validation, OpenSSL context setup, EC key generation, ownership transfer, and insertion into the caller's key collection. The callbacks deliberately return both hotplace `return_t` values and OpenSSL-style `int` results, which is why the pipeline uses `function_pipeline<int, osslerror_category>`.

```cpp
return_t crypto_keygen::add_ec(crypto_key* cryptokey, uint32 nid, keydesc&& desc) {
    EVP_PKEY* pk = nullptr;
    EVP_PKEY_CTX_ptr ctx;
    EVP_PKEY_ptr pkey;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    int type = EVP_PKEY_EC;

    function_pipeline<int, osslerror_category> pipeline;
    pipeline
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != cryptokey); })
        .run_pipe([&]() -> return_t {
            auto hint = advisor->hintof_curve_nid(nid);
            if (nullptr == hint) return errorcode_t::not_supported;
            auto kty = ktyof(hint);
            if (kty_ec != kty) return errorcode_t::different_type;
            return errorcode_t::success;
        })
        .run_pipe([&]() -> int {
            ctx = std::move(EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new_id(type, nullptr)));
            return ctx.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_keygen_init(ctx.get()); })
        .run_pipe([&]() -> int { return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), nid); })
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        .run_pipe([&]() -> int {
            return EVP_PKEY_CTX_set_ec_param_enc(ctx.get(), OPENSSL_EC_NAMED_CURVE);
        })
#endif
        .run_pipe([&]() -> int {
            auto rc = EVP_PKEY_keygen(ctx.get(), &pk);
            return ((rc > 0) && pk) ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            pkey = std::move(EVP_PKEY_ptr(pk));
            return pkey.get() ? 1 : 0;
        })
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        .run_pipe([&]() -> int {
            return EC_KEY_set_asn1_flag(
                (EC_KEY*)EVP_PKEY_get0_EC_KEY(pkey.get()), OPENSSL_EC_NAMED_CURVE);
        })
#endif
        .run_pipe([&]() -> return_t {
            crypto_key_object key(pkey.get(), std::forward<keydesc>(desc));
            auto ret = cryptokey->add(std::move(key));
            if (errorcode_t::success == ret) {
                pkey.release();  // cryptokey owns pkey
            }
            return ret;
        });

    return pipeline.result_to_return_t();
}
```

The stages are meaningful application steps rather than artificial callbacks:

1. Validate the destination collection and confirm that `nid` identifies an EC curve known to the advisor.
2. Create and initialize the OpenSSL key-generation context, then configure the selected curve and (where supported) named-curve encoding.
3. Generate the key and explicitly reject the case where OpenSSL reports success but leaves `pk` null.
4. Wrap the generated key in RAII ownership, apply the legacy OpenSSL ASN.1 flag when required, and transfer ownership to `cryptokey` only if insertion succeeds.
5. Convert the final pipeline result back to hotplace's `return_t` using `result_to_return_t()`.

This example also shows why the pipeline's result policy matters: OpenSSL's positive-success convention and hotplace's richer `return_t` errors share one ordered control flow without losing an explicit hotplace error returned by a callback. The source contains OpenSSL-version-specific stages; the snippet is an implementation example, not a recommendation to reproduce those version checks independently of the SDK.

### Source-level verification

`test/testcase/base/basic/testcase_pipeline.cpp` exercises the control-flow and conversion contract:

- Parameter validation skips normal steps and reaches `walk_failed()`, followed by `walk_always()`.
- A successful arithmetic callback chain runs the ordinary walks and callback; an unexpected result routes execution to the failure walk.
- `goahead_if_not_fail()` permits the `errorcode_t::debug` result to continue to the next callback.
- `function_pipeline<int, osslerror_category>` treats `0` as failure, checks the converted `error_openssl_inside` result, and verifies `result_to_return_t()`.
- `function_pipeline<int, errno_category>` mixes an `int` callback and a `return_t` callback, checking that the explicit hotplace `errorcode_t::unknown` is preserved by `result_to_return_t()`.

These are source-level assertions in the testcase; this document does not claim a new runtime test execution.

### Control-flow trace

```text
callback result
  └─ handle_result()
       ├─ native T ──────────────► _lastcode = result
       └─ hotplace return_t ─────► convert to T for _lastcode
                                   preserve explicit return_t in _returncode

next pipeline step
  ├─ discriminant allows run ───► run / walk
  ├─ discriminant rejects run ──► run_failed / walk_failed
  └─ walk_always ───────────────► execute regardless of current result

result() ───────────────► pipeline-native T
result_to_return_t() ───► preserved return_t, or convert _lastcode
```

This is why the policy type matters: `error_traits<T, category>` classifies the current result and supplies conversions. The same numeric value can mean success under one category and failure under another; the callback return type alone is not enough to infer continuation behavior.

## 4. Relationships

- `sdk/base/system/error.hpp` owns the `error_traits` policy specializations and the `error_advisor` / `error_category_hint` lookup model. `function_pipeline.hpp` consumes those policies; it does not independently define what a category-specific native result means.
- `error_advisor` and `error_category_hint` explain hotplace error-code categories and their descriptive/test metadata. The `return_t` specialization's `is_not_fail()` uses the advisor's category classification; this is how a non-severe category can be distinguished from a severe error.
- `sdk/base/basic/function_pipeline.hpp` implements sequencing, state conversion, exception paths, counters, and debug tracing. `test/testcase/base/basic/testcase_pipeline.cpp` demonstrates the externally observable flow and result conversion.
- Higher-level code can use the pipeline without embedding OpenSSL- or `errno`-specific branches in every callback chain, provided it selects the matching `T, category` pair and respects that specialization's return-value convention.

