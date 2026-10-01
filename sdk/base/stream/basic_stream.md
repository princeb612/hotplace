# Basic Stream

`basic_stream` is the main mutable in-memory stream used for formatted text and small binary/text assembly throughout the SDK.

It extends `stream_t` and provides buffer editing and formatted output operations such as `printf`, `println`, `vprintf`/`vaprintf`, insertion and cutting. The stream also participates in the project's encoder-stream traits so encoding helpers can write directly into it.

`stream_policy` and `local_stream_policy` control allocation behavior used by the stream layer.

## Related tests

- `test/testcase/base/stream/testcase_stream.cpp`

The stream testcase covers buffer operations, formatted output and stream behavior used by higher-level modules.
