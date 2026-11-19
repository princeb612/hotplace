# Document Guide

Edition 1 · Based on hotplace Revision 1132

> Source base : Revision 1132

## Purpose

Study documents record the meaning, relationships, development history,
implementation structure, behavior, and study/verification traces needed to
understand a topic.

Source is authoritative for current implementation. Documentation records the
compressed understanding around that implementation.

## Structure

```text
Context
History
Conceptual
Structural
Flow
Study & Verification
Status
```

- **Context** — project position and related topics.
- **History** — recorded and reconstructed development path; CHANGELOG first,
  no invented motivation.
- **Conceptual** — concepts and relationships the reader must understand.
- **Structural** — current realization, important state and stable relationships.
- **Flow** — behavior; diagrams are preferred when clearer than prose.
- **Study & Verification** — study, construction, RFC comparison, vectors,
  PCAP, applets, and testcase traces, with their purpose.
- **Status** — current factual implementation/verification state.

## Semantic First

Prefer:

```text
meaning → relationship → structure → behavior → study → source
```

Class/function/testcase names are navigation anchors, not narrative subjects.

## Topic Ownership

Each document owns a set of questions. Related topics are introduced only
enough to establish context, then linked to their own documents.

## Document Relationships

Use real relative Markdown links. Document relationships are distinct from
source relationships and study chronology.

## Revision / Edition

At the start of a documentation pass, read the public repository's root
`version.txt`. Its `VERSION_BUILD` value is the authoritative current source
baseline; `CHANGELOG.md` is a corroborating history, not a substitute for the
build value. If `VERSION_BUILD` advances, the workspace target and current
audit baseline must advance with it.

Each topic document records the source revision actually inspected for its
claims. A topic may retain an older baseline when it has not been re-audited;
do not imply that an older topic baseline is current. When a document is
re-audited against the current `VERSION_BUILD`, update its marker only after
the relevant claims have been checked. The project map itself records the
current study baseline.

```text
Edition: 1
Based on: Revision <inspected source baseline>
Current workspace baseline: version.txt VERSION_BUILD
```

## Reading Density

Prefer compact paragraphs and meaningful diagrams. Avoid excessive blank lines,
repeated explanations, and source dumps.

## Signature

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1132            │
│ Documented with GPT-6                │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```
