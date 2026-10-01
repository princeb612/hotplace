# ASN.1 Built-in Types

`basic/semantic/builtin` contains concrete implementations for selected ASN.1 built-in primitive types.

The directory currently contains focused implementations such as INTEGER and BIT STRING. They are part of the larger semantic model in `../` rather than a separate encoding/runtime subsystem.

## Related areas

- `../` — ASN.1 semantic type hierarchy
- `../constraints/` — constraints applied to semantic types
- `../../` — structural and visitor layers
- `../../../runtime/` — runtime ASN.1 representation

Detailed module records can be added here as the built-in type implementations grow.
