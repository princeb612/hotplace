# Base Stream

`sdk/base/stream` is the common stream/buffer/text-output layer used throughout hotplace. It is lower-level than `sdk/io/stream`, which adapts streams to OS-backed files.

## Documents
- [basic-stream](basic_stream.md) — main in-memory text stream and formatted output
- [binary-stream](binary_stream.md) — binary stream representation
- [lowlevel-bufferio](lowlevel-bufferio.md) — buffer and printf machinery
- [string-stream](string-stream.md) — ANSI/wide string stream behavior
- [splitter](splitter.md) — byte splitting and descriptor-driven segmentation

## Related areas
- `sdk/io/stream/` — file/OS stream adaptation
- `sdk/base/string/` — string-level scanning/splitting

## Related tests
- `test/testcase/base/stream/testcase_stream.cpp`
- `test/testcase/base/stream/testcase_bufferio.cpp`
