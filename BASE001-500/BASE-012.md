# BASE-012 — source-basis revision metadata

- **Status:** Open — documentation provenance needs checking
- **Area:** `sdk/base` Markdown documents
- **Historical basis:** Revision 1107 documentation review. The recorded labels were observed in documents but were not reconciled against every source snapshot during that pass.

## Background

Some SDK documentation pages were labelled Revision 1105 while nearby pages used Revision 1107. That mismatch could mean stale metadata, or it could accurately record that a page was written against an older source snapshot. The correct action is to establish provenance, not normalize every label to the newest number.

## Files listed in the Revision 1107 review

- `sdk/base/README.md`
- `sdk/base/basic/crc.md`
- `sdk/base/c++14.md`
- `sdk/base/callback.md`
- `sdk/base/charset.md`
- `sdk/base/error.md`
- `sdk/base/inline.md`
- `sdk/base/nostd/README.md`
- `sdk/base/nostd/memory.md`
- `sdk/base/nostd/string_set.md`
- `sdk/base/nostd/traits.md`
- `sdk/base/stream.md`
- `sdk/base/system/datetime.md`
- `sdk/base/system/endian-and-wire-integers.md`
- `sdk/base/system/error-handling.md`
- `sdk/base/system/ieee754.md`
- `sdk/base/system/threading-and-synchronization.md`
- `sdk/base/trace.md`
- `sdk/base/types.md`

## Decision rule

A revision label is source-basis metadata, not a generic “last edited” timestamp. Keep Revision 1105 when a document genuinely describes that source snapshot; update it only when its content has been reconciled with the newer source. If the label's intended meaning is ambiguous, clarify the convention rather than guessing.

## Next steps

1. Confirm what the revision label means in this documentation set.
2. For each listed file, compare the described APIs and behavior against the source snapshot it claims to represent.
3. Update only labels whose provenance is known to be wrong; keep a short record of the reason for any change.
4. Avoid unrelated wording cleanup while doing this check.

## History

- **Revision 1107 review:** Recorded the list of pages carrying Revision 1105 labels amid nearby Revision 1107 documentation.
- **No labels were normalized during that pass.** The source basis must be checked before changing them.
