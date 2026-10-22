## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# Base basic testcases

## 1. What

The `basic/` testcase group covers pooled allocation, command-line option parsing, memory-dump presentation, function-pipeline control flow, heterogeneous formatting arguments, and typed value conversion from [`sdk/base/basic`](../../../../sdk/base/basic/README.md).

The test methods use different verification styles. Some calculate a final boolean from a sequence of checks and assert it once in a `finally` block; others compare a concrete string, byte sequence, or callback path. Diagnostic output by itself is not a correctness assertion.

## 2. How

### 2.1 Command-line parsing: success is the parser return code

1. [`testcase_cmdline.cpp`](testcase_cmdline.cpp) declares a `MYOPTION` structure and registers six options with `t_cmdline_t<MYOPTION>`:

- `-v`, `-l`, and `-t` are optional flags that set verbose, log, and time fields.
- `-in` and `-out` take values and are marked `preced()`.
- `-keygen` is an optional flag.

2. The helper `do_test_cmdline(expect, argc, argv)` calls `cmdline.parse()`. If the returned `return_t` is not `errorcode_t::success`, it prints help. It then reduces the parser result to a boolean, `test = (ret == success)`, and asserts `expect ? test : !test`. **The pass/fail criterion is therefore the parser's success code, not whether the logged option values look right.** The helper prints `infile`, `outfile`, and `keygen`, but it does not assert those fields against expected values.

3. The two calls made by `test_cmdline()` are:

| Input arguments (excluding program name) | Expected parser result | Why |
|---|---|---|
| `-in test.in` | failure | Required `-out` is missing |
| `-keygen -in test.in -out test.out` | success | Both required value-taking options are present |

4. The separate [`testvector_cmdline.yml`](testvector_cmdline.yml) file declares 12 positive/negative cases, including no arguments, missing option values, malformed `-in-`, reordered options, and a case where option-looking tokens are consumed as values. The `testcase_cmdline()` implementation shown here does **not** load or iterate that YAML file; it invokes only the two hard-coded cases above. Do not claim all 12 YAML cases were executed by this function unless a separate vector runner is identified.

### 2.2 Built-in pool: allocation, fragmentation, exhaustion, policies, and allocators

1. [`testcase_builtinmemory.cpp`](testcase_builtinmemory.cpp) has nine methods called by `testcase_builtinmemory()`. Most tests use a local `test_result` flag, leave early on a failed condition, and assert the final flag in `__finally2`. This gives one result per scenario, so the intermediate checks are the evidence behind that final assertion.

| Test method | Input and operation sequence | What the final assertion establishes |
|---|---|---|
| `test_basic_allocation()` | Create a 1 MiB pool; allocate 256 and 512 bytes; write `0xAA` and `0xBB`; free both blocks. | The pool reports the requested total size, both allocations are non-null, and after release `available_size() == total_size()`. The written bytes are not read back and compared. |
| `test_inplace_reallocate()` | Allocate 1024 bytes, fill with `'A'`, shrink to 512, then expand to 1024. | Both reallocation calls return the same pointer and the first byte remains `'A'`; the block can then be released. It does not compare the full 1024-byte payload. |
| `test_freelist_link_integrity()` | Allocate ten 512-byte blocks; free alternating blocks; allocate 128 bytes into the fragmented pool; free the remaining blocks and the extra block. | Total available size returns to the total size after splitting/coalescing. The test does not directly traverse and assert every internal `_prev/_next` link; the stronger title is supported indirectly by pool restoration. |
| `test_stl_allocator_compatibility()` | Use `builtinpool_allocator<int>` with `std::vector`, push integers 0 through 99, then leave the vector scope. | Vector size is 100, element 99 is 99, and pool capacity is fully restored after the vector releases its storage. |
| `test_pool_exhaustion()` | Fill a 1 MiB pool with 1024-byte allocations, then 16-byte allocations until exhausted; request another 128 bytes and try to reallocate the last block to 2048 bytes; free one block and allocate 16 bytes again. | Initial allocation made progress; requests fail with `nullptr` when depleted; freeing one block permits a new allocation; releasing all remaining blocks restores available capacity. |
| `test_policy_behavior()` | Compare fixed and expandable 64 KiB pools while requesting 4096-byte blocks; attempt 32 blocks from the expandable pool. | A fixed pool rejects an allocation after exhaustion; the expandable pool's `total_size()` grows beyond 64 KiB. The source does not assert the exact number of blocks accepted. |
| `test_pool_expandable_large_allocation()` | Start with 4 KiB and 16 KiB expansion units, request a single 32 KiB block, write `0xAA`, then free it. | The allocation succeeds and can be written and released. It does not verify the entire payload by reading it back. |
| `test_builtinpool_allocator()` | Defines example classes using `builtinpool_vector` and `builtinpool_map`, with a `process()` method that would insert 10,000 records. | This method only declares the examples; it does not instantiate the class or call `process()`, and it contains no assertion. It is not an executed allocator test in this entry point. |
| `test_scoped_allocator()` | Create an expandable local pool; enter `pooled::scope`; create and execute a task using pooled map/vector members; log allocated bytes; after scope, create a pooled vector outside the scope. | This is an exercise of scope-based pool selection and fallback construction, but the method has no explicit assertion on the logged allocation count or on pool restoration. |

2. The pool tests use a 1 MiB backing buffer for most scenarios, while policy behavior uses 64 KiB and the large-allocation case uses a 4 KiB initial buffer. These distinct sizes are purposeful inputs to the tested allocation paths, not merely test fixture details.

### 2.3 Function pipeline: compare the callback path

1. In [`testcase_pipeline.cpp`](testcase_pipeline.cpp), `test_function()` builds a `function_pipeline<return_t>` with a parameter predicate, ordinary `walk()` steps, a `run_pipe()` operation, a failure callback, and an always-run ending callback. Each callback appends a marker to `path`.

| Case | Parameters / operation | Expected callback path |
|---|---|---|
| #1 | Null parameters make `test_parameter()` fail | `test_parameter->walk_failed->end` |
| #2 | `1 + 2` matches expected result `3` | `test_parameter->walk->run_pipe->walk->end` |
| #3 | `1 + 2` does not match expected result `1` | `test_parameter->walk->run_pipe->walk_failed->end` |

2. The test compares the resulting path string, verifying which callbacks ran and in what order. The same source checks `goahead_if_not_fail()`: after a first operation returns `errorcode_t::debug`, a second operation sets `flag = 1`; both the flag and final success result are checked. A separate pipeline uses `osslerror_category` and verifies that the second operation does not run after the first operation returns a nonzero result.

### 2.4 Variant conversion: integer bytes, big numbers, debug formatting, and negative flags

1. [`testcase_variant.cpp`](testcase_variant.cpp) exercises several related paths, each with an explicit expected-value comparison:

| Input / operation | Expected result | What this checks |
|---|---|---|
| Set `uint32(32768)`; call `to_binary()` with `variant_convendian | variant_trunc`; Base16 encode | `00008000` | Four-byte representation for this 32-bit value under the selected flags |
| Set `uint64(0x123456789)`; use the same flags | `0000000123456789` | Eight-byte representation for the wider value |
| Construct `bignumber("0x123456789abcdef")`; shift to `binary_t` | `0123456789abcdef` | Big-number-to-binary conversion |
| Store that big number in `variant`; convert to binary | `0123456789abcdef` | Big-number value through the `variant` wrapper |
| Debug-print the big-number variant | `0123456789abcdef (81985529216486895)` | Hexadecimal and decimal debug presentation |
| Set zero and `vt_flag_negative`; convert through `bignumber` | `t_bntoi<int32>() == -1` and `t_bntoi<uint32>() == -1` | The negative-flag/sentinel representation is propagated by both tested conversions |

2. These checks connect the typed value, byte representation, and debug presentation. They cover the listed values and flags only; they do not exhaust all integer widths, endian/truncation combinations, or negative-flag inputs.

### 2.5 Heterogeneous formatting arguments

1. [`testcase_valist.cpp`](testcase_valist.cpp) assembles values such as `3.141592`, `"phi"`, and `123` in a `valist`, then checks numbered placeholders, reordered values, missing placeholders, format modifiers, binary formatting, and ABI-boundary argument ordering.

2. The direct tests compare complete strings for the simple formatting path, reordered and absent placeholders, format modifiers, bytes 0 through 127 rendered as printable characters or dots, and Base16 output. The ABI-boundary test builds the same eleven logical arguments in several type-width combinations and checks five placeholder orders against expected strings. This is specifically intended to expose argument-slot/alignment and sign-extension problems across Windows/Linux ABI shapes; it is not a general proof of portability to every ABI.

#### YAML vectors and the negative-integer conversion trap

3. [`testvector_valist.cpp`](testvector_valist.cpp) loads [`testvector_valist.yml`](testvector_valist.yml). For each vector, it converts the YAML `args` into a `valist`, applies every `format` string, and compares the produced string with `expect`. The YAML data includes negative values at several widths (`int8: -3`, `int16: -300`, `int32: -2147483648`, and `int64: -2147483649`) as well as reordered placeholders and format modifiers.

4. **Maintainer warning — yaml-cpp and negative integers:** the comment in the vector consumer is intentional and important for anyone adding or changing cases. Do not first decode a negative YAML integer directly into an unsigned ABI/storage type and expect that conversion to behave like a signed parse followed by a cast. Depending on the target type and yaml-cpp conversion path, the conversion may fail before the formatter is reached, making the test fail for a YAML conversion reason rather than for the behavior under test. Read the YAML scalar through an appropriate signed type first (for example, `int` or `long long` according to the value's range), then explicitly cast to the target width/type where the test is deliberately exercising that conversion. Keep the YAML literal negative and the type label consistent with the intended test case; do not “fix” such a case by silently changing its sign or widening away the boundary being tested.

5. The `test_valist_cpp14()` path is separately guarded by `__cplusplus >= 201402L`; C++11 builds record `not_supported`. This optional path is not part of the C++11 baseline.

### 2.6 Memory-dump output: parameterized calls, but no golden-output check

1. [`testcase_dumpmemory.cpp`](testcase_dumpmemory.cpp) uses the fixed ASCII text `still a man hears what he wants to hear and disregards the rest` (commented as a lyric excerpt) and calls `do_test_dump_routine()` four times:

| Call configuration | Purpose represented by the arguments |
|---|---|
| Defaults: `hex_part = 16`, `indent = 0` | Baseline byte dump |
| `hex_part = 32` | Wider hexadecimal row |
| `hex_part = 16, indent = 4` | Indented output |
| `hex_part = 16, indent = 4, rebase = 0x1000` | Supplies a nonzero rebase value to the helper |

2. There is an important implementation detail in the last row: although `rebase` is accepted and included in the test log message, `do_test_dump_routine()` does not pass it to `_logger->dump()`. The call is still `_logger->dump(dump_address, dump_size, hex_part, indent)`; therefore this testcase does not actually verify rebased addresses.

3. The helper initializes `ret` to `errorcode_t::success` unconditionally and then records `_test_case.test(ret, ...)`. That result is not computed from the dump output. The remaining calls use `_logger->hdump()` for a `std::string`, the same text converted to `binary_t`, and an empty `binary_t`; each is followed by unconditional `assert(true)`.

4. So these cases exercise the logging/dump call paths and selected arguments, but none compares the rendered bytes, row layout, indentation, address base, or empty-input output with a golden string. In particular, the current `rebase` argument is logged metadata rather than a tested dump option.

## 3. Evidence

### Source-level coverage

**1. Command-line parsing**

```text
hard-coded argument list -> do_test_cmdline() -> parse()
  -> assert parse status == success
  -> print parsed option fields (diagnostic only)
```

The adjacent 12-case YAML file is not loaded by this function.

**2. Pool / allocator**

```text
allocate / reallocate / scoped allocator operations
  -> intermediate operations
  -> final asserted status/result where present
```

Written bytes are not necessarily read back, and the scoped allocator example has no explicit expected-value assertion. Do not infer byte-content verification from allocation success.

**3. Pipeline, variant, formatting**

```text
pipeline callbacks -> record observed callback path -> compare selected path
variant value -> conversion flags -> binary bytes -> Base16 -> compare expected hex
format arguments -> formatter -> compare expected string (only where supplied)
```

**4. Memory dump and YAML consumers**

```text
dump-memory parameters -> dump helper -> diagnostic text only
YAML file -> consumer explicitly loads schema/fields -> assertions in that consumer
```

The dump is not compared against a golden output; vector claims are limited to schemas actually loaded by source.



The supplied [Test Report Snapshot](../../test-report-status.md) records group-level results including `cmdline`, `valist`, `variant`, `pipeline`, and dump-memory cases. It lists `pipeline` as `success 6` with `expt 2`; these categories are preserved as reported rather than reinterpreted as a normal all-pass count.

A group report does not establish that every method above ran: in particular, the `test_builtinpool_allocator()` method has no invocation/assertion of its local example, and the scoped allocator path has no explicit expected-value assertion. The report does not independently identify the tested source revision, OS, compiler, or complete build configuration.



## 4. Relationships

- [`sdk/base/basic/README.md`](../../../../sdk/base/basic/README.md) — implementation roles and relationships.
- [Base testcase overview](../README.md) — aggregate suite and report provenance.
- [`../CMakeLists.txt`](../CMakeLists.txt) — base testcase source collection.
- [`testcase_cmdline.cpp`](testcase_cmdline.cpp) and [`testvector_cmdline.yml`](testvector_cmdline.yml) — hard-coded parser cases versus separately declared vector cases.
- [`testcase_builtinmemory.cpp`](testcase_builtinmemory.cpp) — the pool scenarios and their individual checks.
- [`testcase_pipeline.cpp`](testcase_pipeline.cpp), [`testcase_variant.cpp`](testcase_variant.cpp), and [`testcase_valist.cpp`](testcase_valist.cpp) — direct expected-result examples.
- [Test Report Snapshot](../../test-report-status.md) — report provenance and interpretation limits.

## 5. References

No external reference is required to explain these testcase flows.
