# BASE-005 — Huffman decoding paths and padding

- **Status:** Open — distinguish generic and HTTP/2 contracts
- **Area:** `sdk/base/encoding/huffman_coding`
- **Historical basis:** Revision 1107 review; the exact decoder behavior has not been re-proven in this record.
- **Source entry points:** [encoding module](https://github.com/princeb612/hotplace/tree/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/encoding), [encoding testcase documentation](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/test/testcase/encode/README.md)

## Background

The module contains two concepts that should not be conflated: a generic Huffman coding facility that works with a learned/provided code table, and the HTTP/2 Huffman coding path based on the fixed code table in RFC 7541. Their table source, accepted terminal padding, and wrapper behavior may differ.

## Current understanding

- The review describes generic decoding as trie-based and chunk-aware.
- The HTTP/2 path uses the fixed RFC 7541 table and has its own encoding/decoding wrapper.
- It is not established that both paths share the same padding validation or malformed-input behavior.

## Behavior path to verify

```text
encoded bytes / bits
       |
       v
select code table
       |
       +--> generic Huffman table
       |       +--> decode trie / state across input
       |
       +--> HTTP/2 fixed RFC 7541 table
               +--> protocol-specific terminal padding checks
       |
       v
decoded symbols or error
```

## Questions to settle

1. How is the generic code table constructed and how are prefix collisions or invalid tables handled?
2. Can decoding continue across chunks without losing the current trie node/bit position?
3. What terminal states are accepted at end-of-input?
4. Does the HTTP/2 wrapper validate padding exactly as RFC 7541 requires, and does it reject EOS as a symbol in ordinary content?
5. Are invalid/incomplete codewords reported distinctly from a valid empty output?
6. Which tests use reference vectors and malformed encodings?

## Next steps

Read the generic table builder/decoder and HTTP/2 wrapper separately. Compare the HTTP/2 behavior with RFC 7541, without imposing protocol-specific padding rules on the generic API unless its contract says so. Add or adjust focused cases only where existing tests fail to express an important supported behavior.

## History

- **Revision 1107 review:** Generic and HTTP/2 Huffman paths were explicitly separated in the docs; terminal padding remains to be verified.
- **No source change or test run recorded.**
