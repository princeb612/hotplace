# Document Guide

Edition 1 · Based on hotplace Revision 1090

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

Each document records the source baseline used for that document. A topic may
retain an older baseline when its content has not required re-audit; that does
not mean the rest of the study map is frozen at that revision. The project
map itself records the current study baseline.

```text
Edition: 1
Based on: Revision <topic baseline>
```

## Reading Density

Prefer compact paragraphs and meaningful diagrams. Avoid excessive blank lines,
repeated explanations, and source dumps.

## Signature

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1090            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```
