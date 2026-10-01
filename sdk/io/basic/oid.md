# OID Conversion

## Role

`sdk/io/basic/oid.*` provides the small representation/conversion layer used when an object identifier needs to move between dotted textual form and an integer-node representation.

```text
"1.2.840.113549"
        |
        v
      oid_t
  [1, 2, 840, 113549]
        |
        v
"1.2.840.113549"
```

## Representation

`oid_t` is defined as:

```cpp
typedef std::vector<uint64> oid_t;
```

The basic module deliberately does not implement ASN.1 OBJECT IDENTIFIER encoding here. It only provides textual conversion.

## Conversion

`str_to_oid()` scans a dotted decimal string and appends each numeric node to the vector.

`oid_to_str()` writes the vector back to a `basic_stream`, inserting `.` between nodes.

The implementation uses hotplace's existing string scanning and numeric conversion helpers rather than introducing another parser.

## Standards context

The header comments associate the representation with ITU-T X.660 / ISO/IEC 9834-1 and ISO/IEC 6523 identifier structures.

ASN.1 DER/BER OBJECT IDENTIFIER encoding is handled by the ASN.1 subsystem; this utility is only the textual/node representation boundary.

## Related source

- `sdk/io/basic/oid.hpp`
- `sdk/io/basic/oid.cpp`
- `sdk/base/string/string.hpp`
- `sdk/base/nostd/atoi.hpp`
- `sdk/base/stream/basic_stream.hpp`

## Related areas

- `sdk/io/asn.1/basic/` — ASN.1 OBJECT IDENTIFIER semantic/encoding support
- `sdk/crypto/basic/oid.md` — cryptographic OID-related material
