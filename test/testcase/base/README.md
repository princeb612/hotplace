## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# Base testcase suite

## 1. What

This directory contains testcases for reusable `sdk/base` facilities: general utilities and value types, encoding, in-memory streams and strings, algorithms and data structures, platform-adjacent helpers, and the project's unittest/logging infrastructure.

The suite mixes focused C++ testcase functions with data-driven test vectors. The retained YAML schemas cover big-number operations, capacity calculations, command-line parsing, `valist` formatting, regular expressions, floating-point arithmetic, Aho-Corasick and KMP matching. A schema's presence alone does not mean every field or case is consumed; the source determines which vectors are loaded and which expected values are checked.

| Test area | Representative behavior | Example source |
|---|---|---|
| Basic values and utilities | Variant conversion, command-line options, formatting, memory dumps | `basic/` |
| Numeric operations | Big-number arithmetic, capacity calculations, floating-point cases | `basic/` and vector consumers |
| Pattern matching | Regex, KMP, Aho-Corasick and wildcard cases | `pattern/` |
| Data structures and graphs | Container operations, graph traversal and path algorithms | `graph/` and related groups |
| Graph-Structured Stack (GSS) | Branching/merging graph paths and path reconstruction, distinct from ordinary DFS/BFS traversal | `graph/` (`testcase_gss()`) |
| Streams and strings | In-memory stream, buffer, string and conversion behavior | `stream/`, `string/` |
| Platform/system helpers | Date/time, endian, process, synchronization and shared objects | `system/` and related groups |
| Test infrastructure | Test vectors, logging and assertion/report behavior | `unittest/` and the suite entry point |

The suite entry point is `sample.cpp`. It explicitly invokes testcase groups in sequence, with `testcase_signalwait_threads()` called only when `-thread` is supplied. The CMake file collects source files with GLOB patterns; registration in CMake and invocation from `main()` are different facts and should not be conflated.

## 2. How

The suite combines direct C++ tests with selected YAML-driven vectors. Read each procedure as a sequence of input preparation, operation, and explicit oracle. A printed value is not an assertion unless the source compares it with an expected value.

### 2.1 Typed conversion and formatting

1. In `basic/testcase_variant.cpp`, assign the input integer to a `variant` and request binary conversion with the case's endian and truncation flags.
2. Convert the produced bytes to Base16 and compare the complete hexadecimal string with the expected value. The debug dump is not the oracle.
3. In `basic/testcase_valist.cpp`, prepare heterogeneous formatting arguments and call the hotplace formatting wrapper.
4. Compare the produced formatted text with the expected string. This checks the wrapper's formatting path, not portability of native `va_list` representations.

### 2.2 Range and set operations

1. In `nostd/testcase_set.cpp`, insert the supplied overlapping or adjacent intervals into the range set.
2. Call `merge()` and compare the resulting interval count and endpoints with the expected ranges.
3. In subtraction cases, remove the requested intervals and compare the remaining ranges.
4. In the ACK conversion case, check the constructed ACK fields and the range set reconstructed from those fields.

### 2.3 Pattern matching

1. In `pattern/testcase_kmp.cpp`, prepare the source data and search pattern.
2. Run the same search through the supported input representations (byte storage, contiguous memory, values, and pointers).
3. Compare each returned match index with the expected position.
4. For other pattern algorithms, compare the result using the case's own representation, such as an exact match-range multimap or occurrence-offset set. Do not assume all algorithms share one result type or one oracle.

### 2.4 Graph operations

1. In `graph/testcase_graph.cpp`, build the graph fixture required by the selected adjacency, DFS, BFS, Dijkstra, or topological-sort case.
2. Invoke the operation under test using that graph.
3. Compare the returned order or result with an expected value only in cases that define such an expectation.
4. Treat traversal output followed by unconditional `assert(true, ...)` as diagnostic execution, not verification of the printed traversal.

### 2.5 Stream, buffer, string, and system utilities

1. Prepare the input stream, buffer contents, strings, time values, endian values, or numeric inputs required by the selected testcase.
2. Invoke the corresponding stream/buffer/string/system operation, such as append, format, extract, edit, search, or conversion.
3. Check the exact property asserted by that testcase: selected content, size, return value, or parsed field.
4. Treat lifetime-only exercises and printed dumps as weaker evidence than explicit content comparisons. Interpret platform/compiler guards and optional command-line flags from the dispatch path before claiming coverage.

### 2.6 YAML-driven vector procedures

1. Confirm that the relevant testcase function actually loads the associated YAML file and selects the expected schema identifier. The existence of a nearby fixture alone does not prove that it is consumed.
2. Read only the fields used by that consumer. The schemas below document the available input layout; the consumer determines which fields are mandatory in practice and which expected values are compared.
3. For big-number, capacity, floating-point, and related arithmetic vectors, prepare the values from the item's input fields, run the selected operation, and compare only the expected results explicitly checked by the source.
4. For command-line vectors, supply the listed argument sequence to the parser and check the parser outcome and any expected diagnostic/reason field that the consumer actually asserts.
5. For VALIST vectors, convert the typed YAML arguments, call the formatting wrapper with the requested format string, and compare the resulting text. Decode signed values through the signed YAML type used by the consumer before casting to the target width; otherwise YAML conversion can fail before the formatting code executes.
6. For REGEX, AHO CORASICK, and KMP vectors, prepare the input and pattern/options, run the corresponding matcher, and compare the specific result shape used by that consumer (for example, match results or occurrence positions). Do not infer that every field shown in a schema is asserted.
7. Interpret a successful status, exact expected-value equality, and diagnostic logging separately. Platform/version guards and optional flags can change which vector paths run.

### 2.7 Data-driven YAML vector formats

##### YAML schema

* bignumber YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: BIGNUMBER STRING                # [mandatory] "BIGNUMBER STRING"
    items:
      - hex: hexstring
        desc: decimalstring
  - example: string                         # [mandatory] testcase
    schema: BIGNUMBER ARITHMETIC            # [mandatory] "BIGNUMBER ARITHMETIC"
    items:
      - int1: decimalstring|hexstring       # [mandatory]
        int2: decimalstring|hexstring       # [mandatory]
        add: decimalstring|hexstring        #
        sub: decimalstring|hexstring        #
        mul: decimalstring|hexstring        #
        div: decimalstring|hexstring        #
        mod: decimalstring|hexstring        #
        lshift1: decimalstring|hexstring    #
        rshift1: decimalstring|hexstring    #
  - example: string                         # [mandatory] testcase
    schema: BIGNUMBER INTMINMAX             # [mandatory] "BIGNUMBER INTMINMAX"
    items:
      - bits: uint32                        # [mandatory]
        intmin: decimalstring|hexstring
        intmax: decimalstring|hexstring
        uintmax: decimalstring|hexstring
  - example: string                         # [mandatory] testcase
    schema: BIGNUMBER BITWISE               # [mandatory] "BIGNUMBER BITWISE"
    items:
      - int1: decimalstring|hexstring       # [mandatory]
        int2: decimalstring|hexstring       # [mandatory]
        and: decimalstring|hexstring
        or: decimalstring|hexstring
        xor: decimalstring|hexstring
  - example: string                         # [mandatory] testcase
    schema: BIGNUMBER NEGATIVE              # [mandatory] "BIGNUMBER NEGATIVE"
    items:
      - value: decimalstring|hexstring      # [mandatory]
        expect: decimalstring|hexstring     # [mandatory]
  - example: string                         # [mandatory] testcase
    schema: BIGNUMBER MODPOW                # [mandatory] "BIGNUMBER MODPOW"
    items:
      - base: decimalstring|hexstring       # [mandatory]
        exp: decimalstring|hexstring        # [mandatory]
        mod: decimalstring|hexstring        # [mandatory]
        expect: decimalstring|hexstring     # [mandatory]
````

* capacity YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: UNSIGNED BYTE CAPACITY          # [mandatory] "UNSIGNED BYTE CAPACITY"
    items:
      - value: decimalstring|hexstring      # [mandatory]
        expect: int                         # [mandatory]
  - example: string                         # [mandatory] testcase
    schema: SIGNED BYTE CAPACITY            # [mandatory] "SIGNED BYTE CAPACITY"
    items:
      - value: decimalstring|hexstring      # [mandatory]
        expect: int                         # [mandatory]
````

* cmdline YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: CMDLINE                         # [mandatory] "CMDLINE"
    template: myoption                      # [mandatory] "myoption" MYOPTION structure
    items:
      - item: string
        args:                               # [mandatory] 0..9
          - argv1                           # argv[1]
          - argv2                           # argv[2]
          - argv3                           # argv[3]
          - argv4                           # argv[4]
          - argv5                           # argv[5]
        expect: boolean                     # [mandatory]
        reason: string
````

* valist YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: VALIST                          # [mandatory] "VALIST"
    args:
      - type: string                        # [mandatory] "float"|"string"|"int"|"int8"|"uint8"|"int16"|"uint16"|"int32"|"uint32"|"int64"|"uint64"
        value: string                       # [mandatory] YAML scalar converted according to type
    items:
      - item: string
        format: string                      # [mandatory] value={1} value={2} value={3}
        expect: string                      # [mandatory] expected formatted output
````

**Test-author warning:** negative values must be decoded through a suitable signed YAML type before being cast to the target width. For example, the consumer reads `int8`, `int16`, and `int32` values through `as<int>()`, then casts; `int64` uses `as<long long>()`. Do not decode a negative scalar directly as an unsigned ABI type and assume yaml-cpp will produce a wrapped value—the YAML conversion can fail before the formatting code under test runs. The live consumer and its rationale are documented in [`basic/README.md`](basic/README.md).

* regular expression YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: REGEX                           # [mandatory] "REGEX"
    items:
      - item: string                        #
        input: string                       # [mandatory]
        expr: expression                    # [mandatory]
        results:
        - "string"                          # [mandatory] 0..*
````

* floating point YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: FLOATINGPOINT                   # [mandatory] "FLOATINGPOINT"
    items:
      - float1: string                      # [mandatory] 123.45, -0.00123 1.2e8 1/3 355/113 22/7 ...
        float2: string                      # [mandatory]
        add: string                         #
        sub: string                         #
        mul: string                         #
        div: string                         #
````

* aho corasick YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: AHO CORASICK                    # [mandatory] "AHO CORASICK"
    items:
      - item: string                        # [mandatory]
        input: string                       # [mandatory]
        option: array of option string      # [mandatory] ex. [wildcards, ignorecase]
                                            #             if wildcards option is included, wildcards such as ?, * can be included.
        pattern:                            # [mandatory]
          words: array of range pair        # [mandatory] ex. "words": [[begin1, end1], [begin2, end2], ...]
````

* KMP YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: KMP                             # [mandatory] "KMP"
    items:
      - item: string                        # [mandatory]
        pattern: string                     # [mandatory]
        match: string                       # [mandatory]
          words: array of occurrence        # [mandatory] ex. "words": [pos1, pos2, ...]
````
## 3. Evidence

### Source-level coverage

**1. Typed conversion and formatting**

```text
variant.set(value) -> to_binary(flags) -> Base16 encode -> compare expected hex
format arguments -> hotplace formatting wrapper -> compare expected string
```

These paths check the selected bytes/text, not every flag combination or native `va_list` ABI.

**2. Range and ACK data**

```text
insert ranges -> merge/subtract -> compare count + endpoints
ACK fields -> construct/reconstruct range set -> compare expected fields + ranges
```

**3. Pattern matching versus graph traversal**

```text
KMP / selected pattern vectors -> search -> compare expected index/ranges/offsets

graph traversal / selected Dijkstra helpers
  -> traverse and print nodes/path/distance
  -> unconditional assertion in some helpers
  -> invocation evidence only; no expected traversal/path comparison
```

Topological-sort cases are a separate path that compares returned order with an expected sequence. GSS checks are only as strong as the concrete node/path comparisons in each case.

**4. Stream, string, system, and YAML-backed paths**

```text
operation -> result/state -> compare only the explicitly asserted fields
YAML file -> schema registered by consumer -> fields loaded -> result comparison
```

A nearby YAML file is not coverage unless the source loads it. Dumps, lifetime traces, and optional/platform-guarded paths are not equivalent to explicit expected-value assertions.



Source review and runtime reports answer different questions. The source establishes which functions are invoked, what operations they perform, and whether results are compared with expectations; it does not establish that every branch ran on every platform. Conversely, a report records the outcomes emitted by a particular run but does not prove that output-only tests verified their output.

### Recorded execution evidence

#### Revision 1106 CTest runs supplied by the maintainer

- **Ubuntu 20 · Sanitizer:** `./make.sh debug sanitize ctest` — 12/12 CTest test files passed.
- **Windows 11 · MinGW64 · Application Verifier basic checks:** `./make.sh debug odbc ctest` — 13/13 CTest test files passed, including the `test-odbc` target.

These Revision 1106 figures count CTest test files/targets that passed in the supplied MinGW64 and Ubuntu 20 runs. They are not per-testcase assertion totals and should not be compared numerically with the older aggregate report below. A passing `test-odbc` target also does not establish live database integration when no connection string/database interaction was supplied.

#### Revision 1104 aggregate report snapshot

The separately supplied aggregate report is documented in [Test Report Snapshot](../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest**, with 1,718 pass, 13 expt, 0 fail, 1 skip and 1 triv for the `base` group. The report collects per-directory report files generated after the MinGW64 CTest run and aggregates their individual testcase outcomes. It also lists 27 pass entries for `stream` and 30 pass entries for `bufferio`; these are subgroup counts and must not be added again to the parent total.

The two records use different counting units: Revision 1104 aggregates testcase-level outcomes from report files, while Revision 1106 records the number of CTest test files/targets that passed on MinGW64 and Ubuntu 20. They are not directly comparable totals. The Revision 1104 report payload does not independently identify the tested source commit, exact GCC version, or complete build configuration.

The maintainer-facing backlog of candidate test improvements is kept separately in [Developer Notes - Testcase reinforcement candidates](Developer%20Notes%20-%20Testcase%20reinforcement%20candidates.md). It is not a statement of current test coverage or a mandatory test plan.



## 4. Relationships

- [`sdk/base/README.md`](../../../sdk/base/README.md) — implementation map and module responsibilities.
- [`test/testcase/CMakeLists.txt`](../../CMakeLists.txt) and [`CMakeLists.txt`](CMakeLists.txt) — target registration and source/data collection.
- [`sample.cpp`](sample.cpp) — entry point and explicit invocation order.
- `basic/`, `graph/`, `pattern/`, `stream/`, `string/`, `system/`, and other sibling directories — concrete testcase groups.

## 5. References

- [Modular exponentiation — Wikipedia](https://en.wikipedia.org/wiki/Modular_exponentiation) — background for modular-exponentiation cases in the big-number vectors.

