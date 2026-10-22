# Follow-up Workspace — Working Agreement

This branch is a private-feeling working space for the maintainer and GPT to preserve continuity across source/documentation review sessions. It is not part of the hotplace product documentation and must not be merged into `master` or ordinary documentation branches.

## Purpose

hotplace is a one-person project space for studying, experimenting, integrating, documenting, and playing. Follow-up work should support that flow, not turn the project into a QA program or an administrative task list.

## Before every follow-up session

1. Read this file first.
2. Read the top-level `DATA-BEHAVIOR-FOLLOW-UP.md` to understand currently open items.
3. Read the relevant revision record(s) before making claims about previous findings.
4. Check the current source/revision/commit before assuming an earlier finding still applies.
5. If a newer source commit is available, compare it with the recorded source basis and update status from evidence.

## Branch and file layout

- Top-level `DATA-BEHAVIOR-FOLLOW-UP.md`: concise cumulative index of open items, latest status, and links to revision records.
- `revision-NNNN/DATA-BEHAVIOR-FOLLOW-UP.md`: findings and context recorded against that source revision. Preserve historical findings; do not rewrite history to make old notes appear current.
- This branch should contain only follow-up working records and this agreement. Do not copy source files, test files, or ordinary hotplace Markdown documentation into it.
- Keep the working records outside `master` and source-tree documentation branches. Do not merge this branch into those branches.

## How to record findings

- Describe a concrete observation, the source/document basis, why it matters, and the next useful check.
- Distinguish a confirmed defect from a hypothesis, a documentation boundary issue, or a question needing verification.
- Keep source fixes and testcase changes as separate decisions; do not silently turn a documentation review into a QA expansion.
- Record revision/commit identifiers when known. Never assume a revision label is interchangeable with a commit SHA.
- Avoid generic checklists and exhaustive audits. Keep only useful items that would otherwise be forgotten or are worth revisiting.

## How to maintain the cumulative index

- One stable ID per continuing issue; do not duplicate an item just because a new revision is reviewed.
- On a new revision, re-check open items against actual source. Mark fixed, no longer applicable, verified, or still open only when there is evidence.
- Link each open item to the revision record where its context is documented.
- Remove resolved items from the open list, but retain enough history in the revision record to understand what happened.
- If an item is obsolete or disproved, say so briefly instead of carrying it forward indefinitely.
- Report only meaningful remaining items at the end of a session; no need to turn every session into a formal report.

## Working style

The user chooses what to work on and when. Items may be handled one at a time during breaks; there is no obligation to clear the whole list. GPT is responsible for checking continuity at the start of a relevant session so the user does not need to remember to prompt it.

## Safety boundary

Never modify `master`. Do not claim a branch, file, source fix, test run, or deletion succeeded unless the result has been verified.
