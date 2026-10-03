# Hotplace Binary Construction Abstraction

> **Review baseline:** Revision 1096

Binary construction appears repeatedly in hotplace without forming one universal serialization framework.

```text
protocol structure
       ↓
small binary construction helper
       ↓
sequential field writes
       ↓
binary stream / payload
```

` sdk/base/stream/binary_stream` is convenient for simple sequential binary writes and was also useful for construction-oriented tasks such as parsing-table generation.

`io/basic/payload` represents a related abstraction whose use evolved from fixed-length binary representation toward variable-length construction as protocol work progressed, including QUIC.

HTTP Digest construction provides another example of a small, fluent construction style.

The important pattern is not “all binary builders use one class”; it is that hotplace repeatedly uses small, purpose-driven abstractions to avoid repetitive low-level binary writing.

### Related source / documents

- `sdk/base/stream/binary_stream`
- `sdk/io/basic/payload`
- HTTP authentication / RFC 2617 digest implementation
- `test/testcase/net/http/testcase_http.cpp`
- parser table generation
- stream and payload module documentation

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
