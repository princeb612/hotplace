# Study Drafts

This directory is a temporary preservation space for important context discovered during study and reconstruction before it is assigned to a final topic document.

The purpose is not to create another documentation hierarchy. A draft may contain:

- important reasoning that should not be lost;
- conceptual diagrams;
- relationships whose final destination is not yet decided;
- observations that still need source verification;
- wording that may later be compressed into a topic README.

## Working rule

```text
conversation / source inspection
            ↓
      important discovery
            ↓
          draft
            ↓
   verify / connect / compress
            ↓
     appropriate topic doc
```

A draft is therefore allowed to be exploratory. Final topic documents remain concise and source-grounded.

## Current preserved context

- [Study Flow](study-flow.md) — why the project moved through HTTP/2 → HPACK → QPACK → QUIC → TLS → QUIC → ASN.1.
- [Testcase Context](testcase-context.md) — the common execution/verification/observation model around `cmdarg`, `testcase`, `test_case`, and `logger`.
- [ASN.1 Parser Boundary](asn1-parser-boundary.md) — current distinction between grammar experimentation, parser-table infrastructure, and semantic/runtime work.

These drafts are preservation records, not final architectural claims. When a point becomes stable enough, move or compress it into the document that owns the concept.
