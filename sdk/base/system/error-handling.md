# Error handling and error advice

The system error layer connects hotplace's `return_t` / `errorcode_t` model with platform or library-specific return conventions.

## `error_traits`

`error_traits<T, category>` provides a small adapter interface for different error domains.

The current specializations include:

- hotplace `return_t`
- Linux/OS-style integer errors through `errno_category`
- OpenSSL integer return values through `osslerror_category`

The adapter provides operations such as:

- identify success/failure
- map an external result to `return_t`
- map a hotplace result back to an external convention
- compare results across conventions

The intent is to keep protocol/system code using the same hotplace return model even when the underlying API has different success conventions.

## `error_advisor`

`error_advisor` maps hotplace error codes to:

- symbolic error code names
- human-readable messages
- error categories
- display hints such as console color and unittest-oriented names

The table is initialized from the project's error descriptions and protected by a `critical_section`.

This makes error reporting separate from the actual operation that produced the error: the operation returns a code, while the advisor provides its presentation/interpretation.

## Relationship to tracing and tests

The error layer is used by the project's trace macros and unittest result reporting. In particular, error categories can distinguish ordinary success/expected-failure cases from severe errors without forcing every caller to reproduce the mapping logic.

`error_advisor` is therefore a **project-wide error interpretation layer**, rather than merely a wrapper around `errno`.
