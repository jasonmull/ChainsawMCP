# ChainsawMCP: Accuracy and Evidence-Integrity Self-Assessment

The short version: ChainsawMCP is built for **traceability over trust**. It
doesn't ask you to believe its findings, it gives you a way to check every one of
them against the original evidence. This document covers what the tool can get
wrong, and why each surfaced finding can be verified rather than taken on faith.

We ran seven `.E01` images (from the SRL-2018 Intrusion dataset provided as part of the SANS FIND EVIL AI Hackathon) through the
full pipeline (E01 to EVTX extraction to Chainsaw hunt to report).  Sample reporting from two of the E01 files is provided with this project as an example of provided output. We do not claim a false-positive or
false-negative rate, because these images have no documented attack inventory to
measure against. Claiming a rate without ground truth would be fabrication.

## Findings are verifiable, not trusted

All detection is Chainsaw's. The server runs the Chainsaw binary as a subprocess
and makes zero LLM calls (`docs/ADR-combined.md:47`). The MCP client does the
reasoning, but it reasons over Chainsaw's output, not in place of it.

Every hunt is provenance-stamped. `chainsaw_provenance.json` records the exact
command, Chainsaw version, the binary's SHA-256, the output SHA-256, and a UTC
completion time. Every detection in `hunt_results.json` carries a unique `hit_id`
plus the fields that point back to the original Windows record (`event_record_id`,
`source`, `channel`). The `get_hit` tool resolves any cited `hit_id` back to its
full raw record and the provenance hash, so the chain runs:

> claim → `hit_id` → record in hash-verified `hunt_results.json` → provenance →
> staged EVTX → original E01.

A finding that can't resolve to a `hit_id` is unsupported, by definition. That's
the hallucination-detection mechanism, and it's enforced by protocol rather than
left to good intentions.

Adding `hit_id`s means the annotated results aren't byte-identical to Chainsaw's
raw output, so the server snapshots the verbatim output to `hunt_results.raw.json`
first and hashes both files. The ID scheme is deterministic and recorded in
provenance, so anyone can re-derive the annotated file from the raw one and
confirm it matches. The annotation is a reproducible derivation, not an edit.

## What it can get wrong

The server adds no detection logic, so it has no false positives of its own. The
rules are SigmaHQ core plus Chainsaw's bundled set, so any rule-level FP is
upstream of this project. ChainsawMCP doesn't suppress or invent hits, it relays
what Chainsaw emits.

Most of that output is noise. About 90% of the headline run was informational
severity (routine activity like "RDP Session Disconnected") surfaced for
correlation, not as alerts. `get_detections` filters by severity and rule, and
`chainsaw_report` leads with the severity breakdown so an analyst triages
critical and high first.

Things the tool can miss:

- **Corrupt EVTXs are skipped, not fatal.** `--skip-errors` is always passed, so
  one bad log doesn't abort the hunt. Skipped files show up in
  `chainsaw_stderr.log`, so completeness is observable.
- **Coverage is EVTX-only.** Registry, MFT, prefetch, AmCache and similar
  artifacts are out of scope. A clean ChainsawMCP hunt is not a clean-host verdict.
- **The silent-zero-hits trap.** Sigma rules loaded without a `--mapping` file
  produce zero matches and no error, evidence that looks clean but was never
  evaluated. This was the most dangerous failure mode we found in testing. A hunt
  with Sigma rules but no mapping now fails loudly instead of returning a
  misleading empty result (`src/chainsawmcp/monitor.py:346`).

## Hallucinations

During development the model invented a few plausible Chainsaw CLI flags that
don't exist (`--accept-license`, `--no-progress`, `--rules`), which were caught
and corrected against the binary's `--help`. The lesson recorded in the session
log: the installed binary's `--help` is the only reliable source of truth, not
docs and not inference.

We never observed the model inventing a detection Chainsaw didn't produce, but
not seeing it isn't proof it can't happen. The real safeguard is the traceability
above: every claim has to resolve to a hash-verified `hit_id` via `get_hit`, and
the analysis skill requires that citation. A claim that can't be cited gets
withdrawn, which turns a potential hallucination into a protocol violation the
workflow catches.
