# Stream Splitting

The stream layer provides two related segmentation facilities.

`split()` divides a byte sequence into fixed-size fragments and can optionally include a prefix size in the callback information.

`splitter<DESCRIPTOR_T>` provides descriptor-driven segmentation. The caller supplies a descriptor type and receives segment index/offset/length information together with the descriptor while `run()` walks the source.

These helpers are useful when protocol or binary processing needs to operate on bounded pieces without introducing a higher-level protocol object.

## Source

- `split.hpp/.cpp`
- `splitter.hpp`

## Related tests

- `test/testcase/base/stream/testcase_stream.cpp`
