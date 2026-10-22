## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# nostd testcase overview

## 1. What

This directory tests project-owned STL-style utilities under [`sdk/base/nostd`](../../../../sdk/base/nostd/README.md): binary conversion, range and bit sets, AVL and binary trees, general tree traversal, list/vector/map/heap containers, integer conversion, lookup helpers, checked narrowing, exceptions, and deferred values.

The directory is not one uniform conformance suite. Some tests compare exact values and state transitions; others only print traversal or lifetime diagnostics and finish with `assert(true)`. The sections below distinguish those levels rather than treating a testcase name or report entry as proof of every behavior suggested by the name.

## 2. How

### 2.1 Range sets: interval normalization and subtraction

1. [`testcase_set.cpp`](testcase_set.cpp) checks the merged interval list after overlapping/adjacent intervals and subtraction:

- Add `[0,1]` and `[1,31]`; after `merge()`, expect exactly one interval, `[0,31]`.
- Add `[1,4]` and `[6,10]`, subtract `[3,7]`; expect `[1,2]` and `[8,10]`.
- Subtract `[1,7]` from the same initial ranges; expect only `[8,10]`.
- Add `[-10,4]` and `[6,10]`, subtract `[-3,8]`; expect `[-10,-4]` and `[9,10]`.

2. These examples assert both result count and endpoints. They cover selected closed-interval edge cases, not all combinations of empty, open, unbounded, or adjacent ranges.

### 2.2 Range sets as an ACK representation

1. The same source converts `t_range_set<uint32>` to `ack_t` and back. Its helper builds an ACK from the source ranges, decodes it to a temporary range set, then asserts both that the ACK equals a preconstructed expected structure and that the round-trip range set equals the original.

2. The examples build ranges from packet numbers such as `7..12`, `14`, `15..18`, and `21..22`. Expected ACK values check the largest acknowledged number, first ACK range, and additional gap/range pairs. This makes the sparse-range encoding visible through concrete expected structures.

3. Subtraction is tested in two forms: subtract a sequence of individual/range operations, or subtract a separately constructed range set. For the sample source ranges `7..12`, `15..18`, and `19..25`, removing `7..11`, `16`, `17..19`, and `23..25` must leave `12`, `15`, and `20..22`. Further cases cover subtracting from a larger ACK-like set and character ranges: subtracting `C..E` from `A..C` and `D..F` expects `A..B` and `F`.

### 2.3 Bounded bit set: membership, clear, and encoded bytes

1. [`testcase_bitset.cpp`](testcase_bitset.cpp) constructs `t_bit_set<int>(0, 255)` and attempts to add `-5, -3, -1, 1, 3, 5, 7, 9, 11, 13, 15`. The negative values are outside the configured domain. The test checks membership for the valid odd values, subtracts `1, 5, 9, 13`, moves out the backing bytes and logs their Base16 form, then clears the bit set and asserts that every listed value is absent.

2. The encoded byte string is diagnostic only; it is not compared with a fixed expected encoding. The test does not separately assert the intermediate membership state after the four removals. The report's `expt` category for this group should be preserved as reported, not treated as an assertion-pass count.

### 2.4 AVL tree and binary tree: duplicate insertion and ordering policies

1. [`testcase_avltree.cpp`](testcase_avltree.cpp) inserts each integer from `0` through `19` twice. It asserts that the tree size is 20, then removes each integer and asserts size zero and `empty() == true`. Traversal is printed but not compared with an expected ordered sequence. The test therefore checks duplicate insertion's effect on size and removal for this insertion sequence, not balancing invariants directly.

2. [`testcase_btree.cpp`](testcase_btree.cpp) tests more value/comparator combinations:

- Insert integers `0..19` twice; assert size 20, then remove each and assert size zero and empty.
- Insert `"hello"`, `"world"`, and `"t_btree"`; assert size 3.
- Insert five `testdata1` values whose comparator orders first by numeric key and then by string value; assert size 5.
- Insert five `testdata2` values whose comparator reverses that priority (string value first, then numeric key); assert size 5.
- Insert characters from the fixed sentence “still a man hears what he wants to hear and disregards the rest” into a tree with a custom comparator on `symbol`. A callback increments each symbol's `weight`, and the test asserts 15 unique symbols.

3. The traversals and accumulated weights are printed, but those printed sequences/weights are not compared with a full expected table. The custom-comparator case checks the number of unique symbols, not each frequency.

### 2.5 General tree: AST-shaped construction and three traversal interfaces

1. [`testcase_tree.cpp`](testcase_tree.cpp) constructs an AST-like shape:

```text
SEQUENCE
  builtin type
    name VisibleString
  builtin type
    ok BOOLEAN
```

2. It then visits the tree with `t_tree_visitor`, walks a cursor using `valid()/next()`, and iterates another cursor with `operator++`. Each path logs node data and depth/indentation. The testcase ends with unconditional `assert(true)`; it does not compare node count, traversal order, or depth against an expected sequence. This is an invocation/demo of the construction and traversal APIs, not a checked AST serialization test.

### 2.6 List and vector: copy and move state

1. [`testcase_list.cpp`](testcase_list.cpp) appends `1, 2, 3` to `t_list<int>`, then asserts size 3 and front/back values 1 and 3. It copy-constructs `l2` and move-constructs `l3` from `l1`; the tests assert both destination sizes are 3 and the moved-from `l1` has size zero. It does not compare the full copied/moved sequences.

2. [`testcase_vector.cpp`](testcase_vector.cpp) performs the same sequence with `t_vector<int>`, but also checks all indexed values `v1[0..2] == 1,2,3` before copying/moving. It then checks both destination sizes and that the moved-from vector is empty. Thus the vector case has a direct element-order check that the list case lacks.

### 2.7 Map hint lookup versus insertion/lifetime diagnostics

1. [`testcase_map.cpp`](testcase_map.cpp) has two distinct paths:

- **Hint lookup:** a `std::map<int,std::string>` is wrapped by `t_maphint`; keys 1, 2, and 3 map to `"one"`, `"two"`, and `"three"`. The test checks that finding key 1 returns `"one"`, finding absent key 10 returns `errorcode_t::not_found`, and the const wrapper finds key 2 as `"two"`.
- **Map insertion experiments:** local value types log constructors, copies, moves, and destructors while `std::map::emplace()`, `find()`, and `operator[]` are exercised. The cases are primarily diagnostic: there are no assertions on exact constructor/destructor sequences. A source comment records a historical Valgrind DRD/Helgrind observation about insertion of a value containing `critical_section`; it is a developer observation, not a currently asserted test result.

### 2.8 Binary conversion: widths, truncation, padding, and byte order

1. [`testcase_binary.cpp`](testcase_binary.cpp) exercises several different conversion routes:

- Load a 16-bit value into a 4-byte destination, then convert the resulting bytes to `uint32` and `uint64`; the expected integer is 1. A 128-bit conversion is included only under `__SIZEOF_INT128__`.
- Narrow `0x12345678` to two bytes using both `binary_load()` and `binary_append_n()`; both are expected to encode `5678`, and conversion to `uint16` must yield `0x5678`.
- Load/append the same 32-bit value into 8-byte and optional 16-byte destinations; expected encodings are `0000000012345678` and, where enabled, `00000000000000000000000012345678`.
- Append a 32-bit or 8-bit value and convert it back to wider integer types; the selected expected value is 1.
- In `test_binary2()`, append `uint16(32768)` without a transformer and expect Base16 `0080`; append it with an `hton16` lambda and expect `8000`.

2. These are explicit byte/value comparisons for the listed widths. The 128-bit branches are compiler-conditional and should not be assumed to execute on every supported platform.

### 2.9 Integer parsing and checked narrowing are different contracts

1. [`testcase_int.cpp`](testcase_int.cpp) compares `t_atoi` results for strings `"-1"`, `"-129"`, `"-128"`, and `"129"` across `int8`, `int16`, and `uint8`, and compares `t_htoi` results for `"0xff"` and `"0x100"` into 8- and 16-bit types. The test compares against casts such as `int8(-129)` and `uint8(129)`; it does not assert an error result for out-of-range text. Describe these as the source's selected conversion-result checks, not as validation/rejection of overflow input.

2. [`testcase_narrowcast.cpp`](testcase_narrowcast.cpp), by contrast, defines a local checked conversion wrapper. It first casts to the destination type, then throws `errorcode_t::miscast_narrow` if converting back to the source type changes the value, or if a signedness change alters the sign. The helper `check()` catches `exception` and asserts whether an exception was observed. Three cases expect rejection: signed `-1` to `uint16`, `32768` to `int16`, and `UINT32_MAX` to `int32`. The test checks exception presence, not the exact error code for each case.

3. [`testcase_findlte.cpp`](testcase_findlte.cpp) uses the ordered set `{1,2,4,7,11,16,22,29}` and inputs `{1,2,3,5,8,10,12,17,20,23,30}`. It compares each result to `{1,2,2,4,7,7,11,16,16,22,29}`, checking exact floor/predecessor lookup for exact hits, values between keys, and an input above the maximum. There is no input below the minimum in this vector.

### 2.10 Priority queue: randomized insertion, monotonic removal

1. [`testcase_pq.cpp`](testcase_pq.cpp) generates ten `uint32` values using `openssl_prng`, pushes them into `t_binary_heap<uint32>`, and checks the initially empty and subsequently non-empty states. It repeatedly reads `top()` and pops the heap, setting `errorcheck` if a later value is smaller than the previous one. The assertions check that the heap is empty at the end and that no descending step was observed.

2. This checks nondecreasing extraction order for one random sample; it does not compare against a sorted copy of the generated input or make the exact sequence deterministic. The use of `openssl_prng` also means this testcase depends on the crypto/random subsystem.

### 2.11 Exception and deferred value behavior

1. [`testcase_exception.cpp`](testcase_exception.cpp) throws `exception(errorcode_t::not_specified)`, catches it by value, captures the error code and message, and asserts that the captured code is `not_specified`. The message is logged but not compared with an expected string.

2. [`testcase_value.cpp`](testcase_value.cpp) checks immediate and deferred `t_value<int64>` behavior:

- An immediate value of 1 is read through `value()`.
- A deferred value named `"test"` is updated to 2 by a worker thread; after `start()` and `join()`, both `value()` and conversion to `int64` must return 2.
- A value initially constructed as 1 is changed to deferred with name `"test"`; the test checks the name and deferred flag, sets its value to 2 from a worker thread, and reads it twice to check the result and cached read.
- The `t_range_value<int64>` cases check a literal value 20, a deferred parameter named `"maxSize"`, resolution to 1024 while retaining the deferred marker, and a comparison showing 500 is less than the resolved value.

3. The worker routine's return code is not independently asserted; the main observable checks are the state flags, names, values, and comparison results.

## 3. Evidence

### Source-level coverage

**1. Range set and ACK reconstruction**

```text
range insertions -> merge/subtract -> compare count + endpoints
ACK representation -> selected ACK fields -> reconstruct range set
  -> compare reconstructed ranges == expected source ranges
```

**2. Bit set**

```text
set / clear selected bits -> query membership -> compare selected true/false results
backing bytes -> hex dump -> diagnostic only (no golden-byte comparison)
```

**3. Containers, conversion and integer parsing**

```text
tree/container operations -> compare ordering / lookup / copy-move state where asserted
binary value -> width/endian/truncation conversion -> compare selected bytes/value
text integer -> parse / checked narrowing -> compare value or expected status
```

**4. Priority queue, exceptions and deferred values**

```text
selected inputs -> pop / throw / defer-resolve operation
  -> compare only explicit order, exception or state assertions
```

Randomized inputs, dumps and lifetime traces do not establish exhaustive ordering or lifecycle behavior. The 11 `expt` entries in the bitset report remain their reported category, not 11 independent passing assertions.



The supplied [Test Report Snapshot](../../test-report-status.md) records binary, bitset, range/set, container, conversion, exception, and value-related groups. The `bitset` group includes 11 `expt` entries; these remain report classifications, not a claim that 11 independent value assertions passed.

The report does not independently identify the tested source revision, OS, compiler, or complete build configuration. It also does not establish that every method, optional compiler branch, random input, or diagnostic-only traversal was executed and verified.



## 4. Relationships

- [`sdk/base/nostd/README.md`](../../../../sdk/base/nostd/README.md) — implementation roles and component-specific notes.
- [Base testcase overview](../README.md) — aggregate suite and execution evidence.
- [`../CMakeLists.txt`](../CMakeLists.txt) — base testcase source collection.
- [`testcase_set.cpp`](testcase_set.cpp), [`testcase_bitset.cpp`](testcase_bitset.cpp), [`testcase_avltree.cpp`](testcase_avltree.cpp), and [`testcase_btree.cpp`](testcase_btree.cpp) — interval, bit-set, and tree checks.
- [`testcase_tree.cpp`](testcase_tree.cpp), [`testcase_list.cpp`](testcase_list.cpp), [`testcase_vector.cpp`](testcase_vector.cpp), [`testcase_map.cpp`](testcase_map.cpp), and [`testcase_pq.cpp`](testcase_pq.cpp) — traversal, container, and heap behavior.
- [`testcase_binary.cpp`](testcase_binary.cpp), [`testcase_int.cpp`](testcase_int.cpp), [`testcase_narrowcast.cpp`](testcase_narrowcast.cpp), [`testcase_findlte.cpp`](testcase_findlte.cpp), [`testcase_exception.cpp`](testcase_exception.cpp), and [`testcase_value.cpp`](testcase_value.cpp) — conversion, lookup, exception, and deferred-value checks.
- [Test Report Snapshot](../../test-report-status.md) — report provenance and interpretation notes.

## 5. References

No external reference is required to explain these testcase flows.
