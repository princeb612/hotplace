# BASE-004 — encoder_stream chunking and finalization

- **Status:** Open — streaming contract needs confirmation
- **Area:** `sdk/base/encoding/encoder_stream`
- **Historical basis:** Revision 1107 review. Implementation details below are questions to verify, not guarantees for every encoding.
- **Source entry points:** [encoder_stream.cpp](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/encoding/encoder_stream.cpp), [encoding module](https://github.com/princeb612/hotplace/tree/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/encoding)

## Background

`encoder_stream` adapts incremental encoding to a stream-like interface. Its key contract is how incomplete input at a chunk boundary is retained and how pending state is finalized when the caller asks for the encoded string or bytes. The review specifically called out Base64 tail bytes, Huffman bit state, repeated finalization, and the `_maxsize` limit.

## Current understanding

- The current source entry point defines `encoder_stream` with an encoding selector and a configurable `_maxsize`; the checked snapshot initializes `_maxsize` to `1 << 15`.
- The review notes describe Base64 tail bytes and Huffman bit state as persistent across chunks, with `str()` / `bin()` acting as finalization/readout points.
- Exact flush behavior and repeat-call semantics must be verified per encoding.

## Behavior path to verify

```text
input chunk
    |
    v
encode complete units ------------------> output buffer
    |
    +--> retain incomplete Base64 tail / Huffman bits
                  |
                  v
          next input chunk
                  |
                  v
             finalization
                  |
                  +--> emit pending output / padding?
                  +--> expose str() or bin()
```

## Questions to settle

1. Which encodings keep state between calls, and what exact state is retained?
2. Does `str()` or `bin()` mutate/finalize the encoder, or merely expose current output?
3. Is calling either accessor twice idempotent? What if more input is appended after finalization?
4. For Base64, how are one- and two-byte tails handled at finalization?
5. For Huffman coding, how are residual bits padded and is the padding encoding-specific?
6. Does `_maxsize` limit output capacity, input size, or both? What happens on overflow?
7. Do existing tests compare one-shot output against chunk sizes 1..N and cover empty/final partial chunks?

## Next steps

Trace constructor, write/append path, encoding-specific state, and accessors. Compare chunked output to the same encoding's one-shot result using existing test patterns. Only propose behavior changes if a mismatch or unsafe contract is demonstrated; otherwise document the precise finalization rule.

## History

- **Revision 1107 review:** Incremental state and finalization were identified as the key points to verify.
- **No test run or source fix recorded.**
