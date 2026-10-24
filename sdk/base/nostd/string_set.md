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

# string_set

## 1. Role

### Introduction

`string_set` is the string-domain counterpart of `t_range_set`. It represents allowed textual values using literal members and lexicographical string ranges, with additional operations needed by ASN.1 string constraints.

### Role in the set engine

```text
                 t_set_runtime<std::string>
                           |
                           v
                      string_set
                           |
             +-------------+-------------+
             |             |             |
          literals       ranges       patterns
```

`t_set_runtime<std::string>` selects `string_set` as its concrete backend. This keeps the ASN.1 evaluator independent of the representation details.

## 2. Data Model

### Representation

The implementation keeps two complementary forms:

- a `std::multiset<std::string>` for literal values
- a vector of `string_range` entries for lexicographical ranges

For example:

```text
literal values
  "ABC"
  "XYZ"

range
  "a" .. "z"
```

Endpoint flags allow open and closed string ranges just as they do for numeric ranges.

## 3. Behavior Model

### Operations

The public API provides:

- literal insertion/removal
- membership checks with `has()` / `contains()`
- range insertion/removal
- union
- intersection
- subtraction
- inversion
- `from()` substring-style matching
- `regex()` pattern matching

The distinction between these operations matters for ASN.1 constraints: a literal value, a permitted string range, a `FROM` restriction, and a `PATTERN` restriction are different semantic forms even though they ultimately describe allowed strings.

## 4. Relationships

- `test/testcase/base/nostd/testcase_set.cpp` covers literal membership, `FROM` matching, string ranges, open/closed range removal, regex matching, and `t_set_runtime<std::string>` integration.
### ASN.1 relationship

```text
ASN.1 constraint
       |
       v
asn1_constraint_evaluator<std::string>
       |
       v
 t_set_runtime<std::string>
       |
       v
  string_set
       |
 +-----+---------+---------+
 |               |         |
value          range      pattern/FROM
```

Constraint composition then works through the same set operations used for numeric values:

```text
A UNION B          → union_with()
A INTERSECTION B   → intersect_with()
A EXCEPT B         → erase_from()
ALL EXCEPT A       → invert()
```

## 5. References

No external references are listed.
