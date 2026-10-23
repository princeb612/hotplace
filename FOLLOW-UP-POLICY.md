# Follow-up Workspace — Working Agreement

This branch is a continuity workspace for the maintainer and GPT across source/documentation review sessions. It is not part of hotplace product documentation and must never be merged into `master` or ordinary documentation branches.

## Purpose

hotplace is a one-person project space for studying, experimenting, integrating, documenting, and playing. Follow-up records should preserve useful context without turning the project into a QA program or administrative task list.

## Before every follow-up session

1. Read this file on `workspace-follow-up`.
2. Read the top-level `FOLLOW-UP.md` index.
3. Open the relevant per-issue file(s) before asking the user to reconstruct the background.
4. Read the relevant revision record(s) for historical context.
5. **Check the latest `master` commit first.** Record its full commit SHA and commit message/date, then inspect the relevant source files at that exact commit. Do not assume a revision label, a branch name, a previously pasted snippet, or a prior session's SHA proves the source is current.
6. Compare the current source against the source basis recorded in the issue. Inspect the relevant diff and related declarations/tests when needed. If `master` has moved since the last check, re-evaluate the finding against the new source rather than carrying forward the old conclusion.
7. Keep the latest `master` source as the source-of-truth for current behavior, and `workspace-follow-up` as the source-of-truth for follow-up tracking/history. Never mix their roles.

## Layout and responsibilities

- Top-level `FOLLOW-UP.md`: concise cumulative index of IDs, current status, and links to per-issue files.
- Area-prefixed range directories hold self-contained working records; create files only for actual issues, not empty placeholders:
  - `BASE001-500/BASE-NNN.md` and later BASE ranges
  - `IO001-500/IO-NNN.md` and later IO ranges
  - `CRYPTO001-500/CRYPTO-NNN.md` and later CRYPTO ranges
  - `NET001-500/NET-NNN.md` and later NET ranges
- The numeric range is a storage convention; the area prefix identifies the technical domain.
- `revision-NNNN/DATA-BEHAVIOR-FOLLOW-UP.md`: historical review record for findings observed against that revision. Preserve it as historical context; do not rewrite it to pretend old observations were made against a newer source snapshot.
- Supplemental records such as `revision-NNNN/SOURCE-DOC-FOLLOW-UP-MIGRATION.md` may record a separate cleanup/migration pass without rewriting the original revision review.
- Every open index item should link to a per-issue file that lets work resume without reconstructing the issue from conversation history. Include background, source basis and links, current understanding, confirmed facts versus hypotheses, useful behavior flow, next steps, and concise history as appropriate.
- The branch contains follow-up records and this agreement only. Do not copy source files, tests, or ordinary hotplace Markdown documentation into it.

## Issue IDs and status

- Keep one stable ID for one continuing issue; never reuse an ID after resolution.
- The directory range is only a storage convention, not an issue taxonomy.
- Use concise status labels when useful: `Open`, `Investigating`, `Resolved`, `Recheck`, or `Closed`. These are continuity aids, not a required workflow.
- On a newer source revision, re-check the finding and update its status only when evidence supports the change.
- Keep historical context and decisions in the issue file; keep the cumulative index short.
- Do not bulk-create shallow boilerplate files. Detail should be enough to resume work, but remain proportionate to the issue.

## Source check, updates, and verification

1. **Read before writing.** Fetch the latest `master` commit and the relevant source at that exact SHA. Fetch the latest `workspace-follow-up` head and the current issue/index files separately.
2. **Do not infer identity from branch names alone.** Record full commit SHAs in the issue when source identity matters. Link to immutable commit-SHA URLs for source evidence; branch URLs may be added for convenient navigation but are not historical evidence.
3. **State evidence precisely.** Separate (a) what source inspection confirms, (b) what a diff confirms, (c) what existing tests appear to cover, and (d) what was actually executed in this session. Never imply that source inspection proves a test passed. Do not claim a build/test result unless it was actually run and its result observed.
4. **Make only the needed tracking changes.** Update the relevant issue record first, then update `FOLLOW-UP.md` if the status or navigation changed. Preserve the original revision record. Do not change product source or tests from this workspace.
5. **Target the correct branch explicitly.** All writes in this workflow must target `workspace-follow-up`. Before writing, confirm the branch exists and retrieve the current file/blob SHA and branch HEAD. If the branch or file changed since it was read, refresh and reconcile rather than overwriting blindly. Never target `master` for a write.
6. **Verify after writing.** Read the updated files back from `workspace-follow-up`, verify the intended content and index consistency, and confirm the new commit's parent/branch. Check that `master` was not modified by this operation.
7. **Report the outcome briefly.** Give the issue ID, disposition, exact changed files, follow-up commit link, and any verification not performed. Keep unresolved work visible; do not call an issue resolved merely because a proposed fix looks plausible.

## Recording and working style

- Describe what was observed, where it was observed, why it matters, and what would be useful to check next.
- Distinguish confirmed facts from hypotheses, possible defects, and documentation-boundary questions.
- Treat proposed corrections as proposals until source review and any useful verification are complete.
- Source fixes and testcase changes are separate decisions. Avoid generic checklists and broad QA expansion; retain only details that help future work.
- A separate bug bounty conversation may be used to investigate and discuss a particular ID. After meaningful progress, update that ID's file with the decision, evidence, unresolved question, or next step. The conversation does not need to be copied wholesale.
- The user chooses what to work on and when. GPT should check continuity at the start of relevant sessions.

## Safety boundary

Never modify `master`. Never claim a branch, file, source fix, test run, or deletion succeeded unless the result has been verified.
