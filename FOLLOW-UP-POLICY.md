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
- `BASE001-500/BASE-001.md`: the self-contained detail record for BASE-001. Create only the issue files that are needed; do not generate empty placeholders.
- `BASE501-1000/`: create this directory only when an ID in that range is first needed. Use the same pattern for later ranges.
- `revision-NNNN/DATA-BEHAVIOR-FOLLOW-UP.md`: historical review record for findings observed against that revision. Preserve it as historical context; do not rewrite it to pretend old observations were made against a newer source snapshot.
- Each per-issue file should be sufficient to resume work without asking GPT to reconstruct the issue from conversation history. Include background, source basis and links, current understanding, confirmed facts vs hypotheses, next steps, and a concise history. Add behavior diagrams or focused verification guidance when they materially help.
- The branch contains follow-up records and this agreement only. Do not copy source files, tests, or ordinary hotplace documentation into it.

## Issue IDs and status

- Keep one stable ID for one continuing issue; never reuse an ID after resolution.
- The directory range is only a storage convention, not an issue taxonomy.
- Use concise status labels when useful: `Open`, `Investigating`, `Resolved`, `Recheck`, or `Closed`. These are continuity aids, not a required workflow.
- On a newer source revision, re-check the finding and update its status only when evidence supports the change.
- Keep historical context and decisions in the issue file; keep the cumulative index short.
- When a finding is first recorded in a revision overview, create or expand its per-issue file when it becomes a practical candidate for work. Do not bulk-create shallow boilerplate files.

## Recording and working style

- Describe what was observed, where it was observed, why it matters, and what would be useful to check next.
- Distinguish confirmed facts from hypotheses, possible defects, and documentation-boundary questions.
- Treat proposed corrections as proposals until source review and any useful verification are complete.
- Source fixes and testcase changes are separate decisions. Avoid generic checklists and broad QA expansion; retain only details that help future work.
- A separate bug bounty conversation may be used to investigate and discuss a particular ID. After meaningful progress, update that ID's file with the decision, evidence, unresolved question, or next step. The conversation does not need to be copied wholesale.
- The user chooses what to work on and when. GPT should check continuity at the start of relevant sessions.

## Safety boundary

Never modify `master`. Never claim a branch, file, source fix, test run, or deletion succeeded unless the result has been verified.
