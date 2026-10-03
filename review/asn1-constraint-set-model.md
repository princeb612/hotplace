# ASN.1 Constraint → Set Model

> **Review baseline:** Revision 1096

This review connects ASN.1 constraint evaluation with the generic set infrastructure.

```text
ASN.1 constraint tree
        ↓
asn1_constraint_evaluator<T>
        ↓
t_set_runtime<T>
   ┌────┴────┐
   ↓         ↓
string_set  t_range_set<t_range_value<T>>
   │         │
   └────┬────┘
        ↓
UNION / INTERSECT / EXCEPT / ALL EXCEPT
        ↓
open / closed boundaries
```

The key architectural observation is that a constraint can be treated as a set of allowed values. Constraint nodes then become set operations: values use `insert`, ranges use `insert_range`, UNION uses `union_with`, INTERSECT uses `intersect_with`, EXCEPT uses `erase_from`, and ALL EXCEPT is represented by inversion.

`range_set` and `string_set` are generic `sdk/base/nostd` facilities, not ASN.1-only classes. `t_set_runtime<T>` selects the concrete representation according to the value type.

This is why the topic belongs in `review/`: the implementation crosses `sdk/base/nostd` and `sdk/io/asn.1`, while the review records how the abstractions became connected.

### Related source / documents

- `sdk/base/nostd/range_set.hpp`
- `sdk/base/nostd/set.hpp`
- `sdk/base/nostd/range.hpp`
- ASN.1 semantic constraint classes
- `test/testcase/base/nostd/testcase_set.cpp`
- `test/testcase/asn.1/testcase_constraints.cpp`
- `sdk/base/nostd/README.md`
- `sdk/io/asn.1/basic/semantic/constraints/README.md`
- `sdk/io/asn.1/basic/semantic/constraints/asn1-constraints.md`

---

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace architecture review                 │
│ Revision 1096                                │
│ Documented with GPT-5.6 Luna                 │
│ — architecture, evolution & relationships    │
└──────────────────────────────────────────────┘
```
