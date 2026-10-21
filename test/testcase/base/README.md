## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Documented with GPT-6                        │
│ Source basis: Revision 1105                  │
│ Documentation scope: testcase inventory      │
│ and verification                             │
└──────────────────────────────────────────────┘
```

# Base testcase suite

## 1. Role

This directory contains testcases for the reusable `sdk/base` facilities: general utilities and value types, encoding, in-memory streams/strings, algorithms and data structures, platform-adjacent helpers, and the project's own unittest/logging infrastructure. The testcase groups are source-level checks; their presence does not imply that every assertion has run on every target.

## 2. Test model

The base tests combine focused C++ testcase functions with data-driven test vectors. The retained YAML schemas cover big-number operations, capacity calculations, command-line parsing, `valist` formatting, regular expressions, floating-point arithmetic, Aho-Corasick and KMP matching. The source files determine which schema is loaded and which expected values are actually asserted.

| Test area | Representative behavior | Example source |
|---|---|---|
| Basic values/utilities | Variant conversion, command-line options, formatting and memory dumps | `test/testcase/base/basic/` |
| Numeric operations | Big-number arithmetic and floating-point cases | `test/testcase/base/basic/` and vector consumers |
| Pattern matching | Regex, KMP, Aho-Corasick and wildcard cases | `test/testcase/base/pattern/` |
| Data structures/graphs | Container operations, graph traversal and path algorithms | `test/testcase/base/graph/` |
| Streams/strings/system | In-memory stream, string, synchronization and helper behavior | Corresponding sibling directories |

## 3. Example: typed value to binary expectation

`test/testcase/base/basic/testcase_variant.cpp` sets a typed integer in `variant`, converts it to binary with the selected endian/truncation flags, encodes the bytes as Base16, and compares the result with an expected hexadecimal string. This is a concrete assertion path from a typed value through binary representation to a readable expected value.

`test/testcase/base/basic/testcase_valist.cpp` assembles formatting arguments, passes them through the project's formatting interface, and compares the produced text. The test exercises the wrapper integration; it does not make native `va_list` layouts portable.

## 4. Test and verification status

### 4.1 Source-level coverage

The source-level claims above identify representative test paths, not exhaustive coverage of all algorithms or platform branches. Check the actual assertions and feature guards in each testcase.

### 4.2 Documentation and verification status

The latest available aggregate report is recorded in [Test Report Snapshot](../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with 1,718 pass, 13 expt, 0 fail, 1 skip and 1 triv for the `base` group. The report notes 27 pass entries for `stream` and 30 pass entries for `bufferio`; these are report subgroups and should not be added again to the parent totals.

The report payload does not independently identify the tested source commit, exact GCC version, or full build configuration. This README describes source-level coverage and does not claim that the current working tree was re-tested. Preserve the snapshot until a newer, revision-associated report is available.

Runtime verification must be tied to a report with a known source revision and environment. This README does not claim that the current working tree was executed in any particular environment.

## 5. Relationships

- [`sdk/base/README.md`](../../../sdk/base/README.md) — implementation map and module responsibilities.
- [`test/testcase/CMakeLists.txt`](../../CMakeLists.txt) and [`test/testcase/base/CMakeLists.txt`](CMakeLists.txt) — testcase target registration and source/data collection.
- [`sample.cpp`](sample.cpp) — entry point and explicit invocation order for the base testcase functions.
- `basic/`, `graph/`, `pattern/`, `stream/`, `string/`, `system/`, and the other sibling directories — concrete testcase groups. The entry point should be consulted alongside these directories to distinguish registered source files from functions actually called by `main()`.

## 6. References

- [Modular exponentiation — Wikipedia](https://en.wikipedia.org/wiki/Modular_exponentiation) — background for the modular-exponentiation cases in the big-number test vectors.
- [Big Number Calculator](https://www.calculator.net/big-number-calculator.html) — an external calculator that can be used as a spot-check reference for selected big-number examples; it is not the test oracle for the whole suite.
- [BigCalculator](https://bigcalculator.org/) — an additional external comparison tool for selected arithmetic examples, not proof of full test coverage.

## 7. Developer Notes (for maintainer review)

The YAML schemas below are retained from the previous README to preserve the documented shapes consumed by older and current vector-driven tests. They describe test data formats; they are not runtime reports.

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
    schema: VALIST                          # [mandatory] "VALIST SPRINTF"
    args:
      - type: string                        # [mandatory] "float"|"string"|"int"|"int8"|"uint8"|"int16"|"uint16"|"int32"|"uint32"|"int64"|"uint64"
        value: string                       # [mandatory]
    items:
      - item: string
        format: string                      # [mandatory] value={1} value={2} value={3}
        expect: boolean                     # [mandatory] result
````

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
