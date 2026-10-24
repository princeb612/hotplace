## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Module

## 1. Role

### Role in hotplace

```text
ASN.1 notation
      |
      v
 asn1_parser
      |
      v
  parse_tree
      |
      v
 asn1_publisher
      |
      v
asn1_build_resultset
      |
      v
 asn1_modules
      |
      +-------------------------------+
      |                               |
      v                               v
 asn1_module                    asn1_module
 local module                    imported module
      |                               ^
      +---------- search() -----------+
                    |
                    v
                resolve()
                    |
                    v
              is_resolvable()
```

The important distinction is that `asn1_module` is not the ASN.1 grammar parser. `asn1_parser` handles notation → tokens → parse tree, `asn1_publisher` builds semantic/module information, and `asn1_module` stores and resolves that information.

## 2. Data Model
### Module registry: `asn1_modules`

`asn1_modules` is the process-wide singleton registry for named `asn1_module` instances. It provides `add()`, `get()`, `exist()`, and `remove()` operations, plus a default module and temporary-name/sweep helpers. It replaces the earlier `asn1_module_context` naming; it is not a per-module semantic object.

```text
asn1_modules (singleton registry)
        |
        +-- "CommonDefinitions" ----> asn1_module
        +-- "SecureMessageModule" --> asn1_module
        +-- "<DEFAULT>" -----------> default asn1_module
        `-- "_TEMP_..." -----------> temporary modules
```

The registry manages registration and lifetime bookkeeping. Each `asn1_module` owns one module's definitions, imports/exports, and semantic relationships.

### Main runtime state

A module-capable runtime contains:

- a named-object dictionary;
- module state (`is_module()`);
- module tag/extensibility defaults;
- `asn1_exports` describing the exported symbol list or `ALL`;
- `asn1_symbol_module` entries describing imported symbols and their outer module;
- linkage/reference information used by semantic objects.

The module state is created by `as_module()` and populated through the publisher's module handlers and the runtime import/export APIs.

## 3. Behavior Model

### Linkage update

`update_linkage()` propagates runtime linkage through semantic objects. It updates tagged-type linkage and follows referenced objects while also propagating constructed/explicit relationships through parent objects.

The operation is separate from name resolution:

```text
resolve()
    -> find referenced definitions

update_linkage()
    -> connect semantic objects and propagate linkage
```

This separation is useful when tracing strongly typed/tagged object construction.

### Strongly and weakly typed paths

The runtime also remains the central point for the two decoding styles used by the tests.

```text
weakly typed
DER -> asn1_node tree -> semantic object

strongly typed
runtime schema/reference lookup -> DER -> semantic object
```

The module resolution additions primarily affect the strongly typed/schema side, where a referenced definition may belong to another module.

### Constraint path

Constraint processing crosses the generic parser/runtime boundary:

```text
ASN.1 notation
      |
      v
parser / parse_tree
      |
      v
asn1_publisher
      |
      v
asn1_object + constraint tree
      |
      v
asn1_constraint_evaluator
      |
      v
t_set_runtime<T>
   +---------+
   |         |
   v         v
range_set  string_set
```

The runtime stores the semantic result; constraint evaluation and generic value-domain operations remain in their respective layers. The ASN.1 provider used by this path is `asn1_advisor`, which supplies the shared publisher and parser providers.

### Module representation

`represent()` can now regenerate module notation as well as individual object notation.

For a module runtime it emits module-level information including:

```text
ModuleName DEFINITIONS ... ::= BEGIN
EXPORTS ...
IMPORTS ... FROM ...;
...
END
```

The representation is derived from the runtime's stored module state, exported symbols, imported symbol modules, defaults, and registered definitions.

This makes `represent()` a useful verification point for the parser/publisher/runtime path:

```text
ASN.1 source
    |
    v
parser -> publisher -> runtime
                         |
                         v
                    represent()
                         |
                         v
                 regenerated ASN.1
```

### Practical use: load, publish, then resolve a module

The loader testcase deliberately separates file parsing from semantic publishing so each stage can be checked independently:

```cpp
parse_tree pt;
asn1_loader loader;
auto ret = loader.load_file("example3.asn1", &pt);
_test_case.test(ret, __FUNCTION__, "load ASN.1 file");

asn1_build_resultset result;
auto publisher = asn1_advisor::get_instance()->get_publisher();
ret = publisher->build(&pt, result);
_test_case.test(ret, __FUNCTION__, "publish ASN.1 modules");

auto modules = asn1_modules::get_instance();
for (const auto& name : result.module_names) {
    auto module = modules->get(name);
    if (module) {
        basic_stream bs;
        module->represent(&bs);
        _logger->write(bs);
    }
}
```

The important boundary is between `parse_tree` and `asn1_build_resultset`: loading creates the syntax tree; publishing constructs and registers semantic modules. The registry lookup and `represent()` call then inspect the published result. The testcase additionally asserts expected module/type names and checks module import/export resolvability.

### Related tests

- `test/testcase/asn.1/testcase_basic3.cpp` — strongly typed decoding and reference resolution.
- `test/testcase/asn.1/loader/testcase_loader.cpp` — module loading, regenerated notation, `EXPORTS`, `IMPORTS`, and `is_resolvable()`.
- `test/testcase/asn.1/testcase_constraints.cpp` — semantic construction with constraints.
- `test/testcase/asn.1/runtime/testcase_parser.cpp` — parser/runtime path.
- `test/testcase/asn.1/runtime/testcase_publish.cpp` — publishing path.

### Reference lookup and resolution

The module-aware lookup introduced in revision 1099 lets imported symbols participate in lookup through `search()`.

```text
search(name)
   |
   +-- local _dictionary
   |
   `-- _imports
         |
         +-- imported symbol?
         |
         v
   asn1_modules::get(outer_module)
         |
         v
       outer runtime
```

A local definition is preferred. If the name is not present locally, the runtime walks its imported symbol modules and asks the corresponding outer runtime for the symbol.

`resolve()` uses this lookup when traversing referenced types. Therefore a referenced type can be satisfied by a definition in another imported module rather than requiring every definition to be copied into the current runtime.

`is_resolvable()` is the boolean-facing check over the same dependency-resolution path.

This creates a clear distinction:

```text
get() / local dictionary
        |
        v
local object access

search()
   |
   +-- local object
   `-- imported object
        |
        v
resolve()
        |
        v
reference dependency validation
```

## 5. Relationships
- `asn1_parser` and `asn1_publisher` provide syntax parsing and semantic publication.
- `asn1_modules` owns the module registry; each `asn1_module` resolves local and imported definitions.
- `sdk/io/asn.1/basic/semantic/` supplies the semantic objects whose references are linked into modules.

### Related source

- `sdk/io/asn.1/runtime/asn1_module.hpp`
- `sdk/io/asn.1/runtime/asn1_module.cpp`
- `sdk/io/asn.1/runtime/asn1_parser.*`
- `sdk/io/asn.1/runtime/asn1_publisher.*`
- `sdk/io/asn.1/asn1_advisor.hpp`
- `sdk/io/asn.1/advisor/asn1_advisor.cpp`
- `sdk/io/asn.1/basic/semantic/`
- `sdk/base/nostd/`

