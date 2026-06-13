# ChainsawMCP — Accuracy & Evidence-Integrity Self-Assessment

_Last updated: 2026-06-13 (UTC). Scope: the ChainsawMCP server, not the upstream
Chainsaw/Sigma detection rules it invokes._

This document is an honest self-assessment of how accurate ChainsawMCP is, where
it can be wrong, and — critically — how the architecture lets an analyst **verify
every individual claim** rather than trust the tool. It covers false positives,
missed artifacts, hallucinated claims observed during development, evidence
integrity, and what happens when prompt-based restrictions are ignored.

Where a statement rests on code, it cites `file:line` so it can be checked.

---

## 1. Scope & methodology

**What was exercised end-to-end.** Five `.E01` images from a public Windows
intrusion dataset (`base-dc-cdrive`, `base-file-cdrive`, `base-rd-01-cdrive`,
`base-rd-02-cdrive`, `base-wkstn-01-c-drive`) were run through the full pipeline on
Linux: E01 → EVTX extraction → Chainsaw hunt → report. The headline run produced
**7,098 hits across 74 rules** — 78 critical, 75 high, 413 medium, 155 low, 6,377
informational (`README.md:368`, `README.md:374`).

**Ground-truth limitation — stated plainly.** These images are from a known public
source, but there is **no documented attack inventory** ("this image contains
exactly these N malicious events"). Without that ground truth, this report does
**not** claim a completed false-positive / false-negative rate. Doing so would
itself be fabrication. Instead it characterizes the noise profile, enumerates the
known limitation classes, and documents the mechanism by which any single finding
can be traced to verifiable evidence.

---

## 2. Determinism & claim traceability

This is the foundation the rest of the assessment rests on.

- **All detection is Chainsaw's, none is the model's.** Detections come only from
  the Chainsaw binary invoked as a subprocess; the server makes **zero LLM calls**
  (ADR Decision 3, `docs/ADR-combined.md:47`). The MCP client does the reasoning,
  but it reasons *over Chainsaw's output*, not in place of it.
- **Every hunt is provenance-stamped.** `chainsaw_provenance.json` records the exact
  argv, Chainsaw version, the Chainsaw binary's SHA-256, the output SHA-256, and a
  UTC completion time (`src/chainsawmcp/monitor.py:233`).
- **Every detection is individually citable.** Each record in `hunt_results.json`
  now carries a unique `hit_id` of the form `<job_id>-<index>` (e.g.
  `47962594-000123`), injected into the file before the provenance hash is taken
  (`src/chainsawmcp/monitor.py:196`, `:463`). Alongside it, each record carries the
  intrinsic fields that point back to the original Windows record:
  `event_record_id`, `source` (the EVTX path), and `channel`.
- **Citations are mechanically verifiable.** The `get_hit` tool resolves any cited
  `hit_id` back to its full raw record plus the provenance `output_sha256`
  (`src/chainsawmcp/server.py:476`). The verification chain is:

  > claim → `hit_id` → record in hash-verified `hunt_results.json` → provenance →
  > staged EVTX → original E01.

**Consequence:** a finding that cannot resolve to a `hit_id` is, by definition,
unsupported. This is the project's hallucination-*detection* mechanism, and it is
backed by a protocol rule (§5, §7) rather than left to good intentions.

### Preserved raw output

Injecting `hit_id`s means `hunt_results.json` is no longer byte-identical to
Chainsaw's stdout. To keep this forensically defensible, the server **snapshots
Chainsaw's verbatim output to `hunt_results.raw.json` before any annotation**, and
the provenance record hashes *both* files (`raw_output_sha256` for the pristine
original, `output_sha256` for the annotated working copy —
`src/chainsawmcp/monitor.py:258`, `:264`). Because the ID scheme is deterministic
and declared in provenance (`annotated_by`, `id_scheme`), anyone can re-derive the
annotated file from the raw original and confirm it matches. The annotation is an
auditable, reproducible derivation — not a one-way edit of the evidence.

---

## 3. False positives

- **The server adds no detection logic, therefore no false positives of its own.**
  Rules are SigmaHQ core plus Chainsaw's bundled rules; any rule-level FP is
  upstream of this project. ChainsawMCP neither suppresses nor invents hits — it
  faithfully relays what Chainsaw emits.
- **Noise is dominated by informational events, by design.** In the headline run,
  6,377 of 7,098 hits (~90%) were info-severity (`README.md:374`) — routine
  activity (e.g. "RDP Session Disconnected") surfaced for *correlation*, not as
  alerts. This is expected and is mitigated, not eliminated: `get_detections`
  supports severity/rule filtering and `chainsaw_report` leads with the severity
  breakdown so an analyst triages critical/high first.
- **No per-rule FP rate is computed**, for the ground-truth reason in §1. Claiming
  one would be unsupported.

---

## 4. Missed artifacts (known limitation classes)

Being specific about what the tool can miss is more useful than a blanket
"coverage is good."

- **Corrupt EVTXs are skipped, not fatal.** `--skip-errors` is always passed
  (`src/chainsawmcp/chainsaw.py:124`): a deliberate availability/completeness
  trade-off so one bad log doesn't abort the hunt. Skipped files are visible in
  `chainsaw_stderr.log` — completeness is observable, not silent.
- **EVTX-only coverage.** Registry, MFT, prefetch, AmCache, and similar artifacts
  are out of scope by design — they are other SIFT tools' job. A clean ChainsawMCP
  hunt is not a clean-host verdict.
- **The silent-zero-hits failure mode (the most dangerous miss found in testing).**
  Sigma rules loaded without a `--mapping` file produce **zero matches with no
  error** — evidence that looks clean but was never actually evaluated. This was
  caught during development (session log: "the most dangerous silent failure mode",
  `docs/session-log-combined.md:17`) and fixed architecturally: a hunt with Sigma
  rules but no mapping now fails loudly instead of returning a misleading empty
  result (`src/chainsawmcp/monitor.py:346`, and the explicit failure at `:430`).

---

## 5. Hallucinated claims found during testing

Honesty requires separating two very different categories.

**Development-time hallucinations — observed, caught, and documented.** While
building the Chainsaw invocation, plausible-but-nonexistent CLI flags were
introduced and then corrected against ground truth:

- `--accept-license` and `--no-progress` — neither exists in the installed Chainsaw
  (`docs/session-log-combined.md:114`, `:23`).
- `--rules` (plural) — rejected; the correct flag is `--rule`
  (`docs/session-log-combined.md:22`).
- The `--mapping` omission described in §4.

The recorded lesson is explicit: *"the installed binary's `--help` output is the
only reliable source of truth — not docs, not inference"*
(`docs/session-log-combined.md:15`).

**Analysis-time hallucinations — none observed, with an honest caveat.** Across the
testing sessions, no instance was observed of the model inventing a detection that
Chainsaw did not produce. **Absence of observed cases is not proof of absence.**
The real safeguard is not "we didn't see it happen" — it is the architectural
traceability of §2: every claim must resolve to a provenance-hashed `hit_id` via
`get_hit`, and the analysis skill *requires* that citation (§7). A claim that
cannot be cited is to be withdrawn, which converts a potential hallucination from
an undetectable error into a protocol violation that the workflow catches.

---

## 6. Evidence integrity — architectural enforcement

Original evidence is never opened writable. This is enforced in code, not policy:

- **Linux E01 access is read-only by construction.** Extraction uses the
  `pytsk3.Img_Info` read-only API (`src/chainsawmcp/evidence.py:191`); the fallback
  path uses The Sleuth Kit `fls`/`icat` CLI tools, which are read-only
  (`src/chainsawmcp/evidence.py:143`). There is **no** FUSE or loopback mount of the
  image at all.
- **Windows E01 access is explicitly read-only.** Arsenal Image Mounter is invoked
  with the `/readonly` flag (`src/chainsawmcp/evidence.py:388`, `:407`).
- **All writes are confined to the case directory.** Generated artifacts go only to
  `analysis/`, `exports/`, and `reports/` subdirectories of
  `CHAINSAWMCP_CASE_DIR`. The server has **no code path** that writes into an
  evidence source.
- **Results integrity is independently verifiable.** Both the raw and annotated
  hunt outputs are SHA-256-stamped in provenance (§2), so post-hoc tampering with
  *results* is detectable.
- **Supporting controls.** Webhook delivery is HTTPS-only — non-HTTPS URLs are
  rejected because payloads carry case data (`src/chainsawmcp/config.py:123`) — and
  a Stop hook appends a timestamped entry to `forensic_audit.log` per session.

---

## 7. Prompt-based restriction — and what happens if the model ignores it

The Protocol SIFT "Strict read-only" directive lives in `CLAUDE.md:176`. It is
essential to be clear about what that directive can and cannot guarantee. The
answer has two layers.

**Layer 1 — architectural, holds regardless of model behavior.** The ChainsawMCP
*server's own tools* cannot modify evidence: every evidence-touching code path
opens read-only (§6). If the model completely ignores `CLAUDE.md`, the server still
provides no tool that can write to the image. This layer does not depend on the
model obeying anything.

**Layer 2 — prompt-based, and it can fail.** The `CLAUDE.md` directive also governs
the *client agent's other tools* (e.g. a general shell tool the analyst has
enabled). That is a prompt-level instruction, and a sufficiently errant or
adversarially-steered model could ignore it. **There is no code-level guard in this
repository that prevents the client's non-ChainsawMCP tools from writing into
`/cases/` or a mounted evidence path.** Stating otherwise would be false assurance.

**Residual-risk handling (recommended for engagements):**

1. Mount evidence shares read-only at the OS level, so the guarantee does not
   depend on any agent's behavior.
2. Hash images before and after the engagement; the immutable image hash is the
   ground truth for tamper detection.
3. Rely on `chainsaw_provenance.json` output hashes for post-hoc detection of any
   change to *results*.

The honest summary: **evidence-source integrity is architecturally enforced for the
server's tools and operationally recommended for everything else.** The citation
mechanism (§2) makes *fabricated findings* detectable; OS-level read-only mounts
make *evidence modification* preventable. Neither is left solely to a prompt.

---

## 8. Self-correction record

The fixes above were not hypothetical — they came out of a working error-handling
loop, which is itself evidence that the self-assessment process is real:

- Failures return structured payloads (`status`, `exit_code`, `stderr`,
  `suggested_fix`, `attempt`) classified by `_classify_error`
  (`src/chainsawmcp/monitor.py:274`), with a retry cap.
- Even the classifier had a bug that was caught and fixed (mapping errors were
  misrouted because the filename contained the substring "sigma"). It is documented
  rather than hidden.

---

## 9. Test suite

The repository ships **58 deterministic tests** (`tests/test_chainsaw.py`), all
subprocess calls mocked. Coverage includes Chainsaw JSON/NDJSON parse edge cases,
evidence validation and error paths, and the `hit_id` injection mechanism —
determinism, intrinsic-field extraction, defensive `EventRecordID` handling, valid
JSON round-trip, and citation display.

---

## Summary

ChainsawMCP's accuracy posture is **traceability over trust.** It does not claim a
measured false-positive/false-negative rate (no ground truth exists for the test
images), and it does not claim hallucinations are impossible. What it provides is a
chain in which every surfaced finding is anchored to a hash-verified Chainsaw record
an analyst can dereference with one tool call — and an evidence-integrity model that
holds in code for the server's tools and is backed by operational controls for
everything else.
