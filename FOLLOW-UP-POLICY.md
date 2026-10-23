# Follow-up Workspace — Working Agreement

This branch is a continuity workspace for the maintainer and GPT across source/documentation review sessions. It is not part of hotplace product documentation and must never be merged into `master` or ordinary documentation branches.

## Purpose

hotplace is a one-person project space for studying, experimenting, integrating, documenting, and playing. Follow-up records should preserve useful context without turning the project into a QA program or administrative task list.

## Before every follow-up session

1. Read this file.
2. Read the top-level `DATA-BEHAVIOR-FOLLOW-UP.md` for the current index.
3. Open the relevant per-issue file(s) before asking the user to reconstruct the background.
4. Read the revision record(s) for historical context.
5. Check the current source/revision/commit before assuming an old finding still applies.

## Layout and responsibilities

- Top-level `DATA-BEHAVIOR-FOLLOW-UP.md`: concise cumulative index of IDs, current status, and links to per-issue files.
- Area-prefixed range directories hold self-contained working records; create files only for actual issues, not empty placeholders:
  - `BASE001-500/BASE-NNN.md` and later BASE ranges
  - `IO001-500/IO-NNN.md` and later IO ranges
  - `CRYPTO001-500/CRYPTO-NNN.md` and later CRYPTO ranges
  - `NET001-500/NET-NNN.md` and later NET ranges
- The numeric range is a storage convention; the area prefix identifies the technical domain.
- `revision-NNNN/DATA-BEHAVIOR-FOLLOW-UP.md`: historical review record for findings observed against that revision. Preserve it as historical context; do not rewrite it to pretend old observations were made against a newer source snapshot.
- Every open index item should link to a per-issue file that lets work resume without reconstructing the issue from conversation history. Include background, source basis and links, current understanding, confirmed facts versus hypotheses, useful behavior flow, next steps, and concise history as appropriate.
- The branch contains follow-up records and this agreement only. Do not copy source files, tests, or ordinary hotplace Markdown documentation into it.

## Issue IDs and status

- Keep one stable ID for one continuing issue; never reuse an ID after resolution.
- The directory range is only a storage convention, not an issue taxonomy.
- Use concise status labels when useful: `Open`, `Investigating`, `Resolved`, `Recheck`, or `Closed`. These are continuity aids, not a required workflow.
- On a newer source revision, re-check the finding and update its status only when evidence supports the change.
- Keep historical context and decisions in the issue file; keep the cumulative index short.
- Do not bulk-create shallow boilerplate files. Detail should be enough to resume work, but remain proportionate to the issue.

## Recording and working style

- Describe what was observed, where it was observed, why it matters, and what would be useful to check next.
- Distinguish confirmed facts from hypotheses, possible defects, and documentation-boundary questions.
- Treat proposed corrections as proposals until source review and any useful verification are complete.
- Source fixes and testcase changes are separate decisions. Avoid generic checklists and broad QA expansion; retain only details that help future work.
- A separate bug bounty conversation may be used to investigate and discuss a particular ID. After meaningful progress, update that ID's file with the decision, evidence, unresolved question, or next step. The conversation does not need to be copied wholesale.
- The user chooses what to work on and when. GPT should check continuity at the start of relevant sessions.

## Safety boundary

Never modify `master`. Never claim a branch, file, source fix, test run, or deletion succeeded unless the result has been verified.
