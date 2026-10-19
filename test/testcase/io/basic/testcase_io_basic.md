## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Basic I/O Testcases

## 1. Role

Documents the source-level tests for `sdk/io/basic`, primarily the declarative `payload` read/write layer and its QUIC-specific encoded-field extension.

## 2. Test model

`testcase_payload.cpp` exercises field-order serialization/deserialization, reference-sized binary fields, optional groups, condition-controlled groups, 24-bit/48-bit values, and bignumber values. `testcase_payload_quic.cpp` covers QUIC integer/payload integration.

## 3. Example: payload write/read round trip

The test constructs named payload members, writes a binary representation, and checks expected field values and encoded bytes. A representative assertion compares the serialized output against an expected byte sequence.

## 4. Test and verification status

### 4.1 Source-level coverage

Assertions compare expected payload values and byte buffers in several paths. The source includes checks for both serialization bytes and values recovered during decoding; individual cases should still be reviewed for boundary coverage before claiming exhaustive validation.

### 4.2 Documentation and verification status

The source assertions described here are source-level evidence, not a new runtime run. The supplied report archive does not record the exact OS/compiler configuration or source revision; it therefore cannot establish that these cases ran against Revision 1104.

## 5. Relationships

- Implementation: `sdk/io/`
- Test registration: the adjacent `CMakeLists.txt` and shared testcase harness.

## 6. References

- `test/testcase/io/basic/testcase_payload.cpp`
- `test/testcase/io/basic/testcase_payload_quic.cpp`
