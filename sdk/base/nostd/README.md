# nostd

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1096
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```


`sdk/base/nostd` is hotplace's C++11-oriented STL-style utility layer. It supplies containers and helpers without making newer standard-library facilities a prerequisite for the project.

The directory is intentionally a collection rather than a single abstraction, so the module records group related headers by role instead of creating one document per small header.

## Documents
- [containers](containers.md) — vector/list/map/set/tree/container families
- [binary-and-range](binary-and-range.md) — binary helpers, ranges, bit sets and capacity
- [set](set.md) — runtime set façade selecting numeric or string backends
- [range_set](range_set.md) — normalized numeric/ordered range set implementation
- [string_set](string_set.md) — string values, ranges, FROM and regex operations
- [traits-and-utility](traits-and-utility.md) — casts, traits, utility helpers and printf/encoding traits
- [keyvalue-and-exception](keyvalue-and-exception.md) — key/value and exception helpers

## Related tests
- `test/testcase/base/nostd/`

## Source
- `sdk/base/nostd/`
