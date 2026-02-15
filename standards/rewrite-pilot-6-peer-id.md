# Rewrite Pilot #6 Standards Mapping and Remediation (`peer_id`)

Date: 2026-02-15

Target module scope:
- `/Users/multi/Documents/GitHub/libp2p/c-libp2p/src/peer_id/peer_id.c`
- `/Users/multi/Documents/GitHub/libp2p/c-libp2p/src/peer_id/peer_id_rsa.c`
- `/Users/multi/Documents/GitHub/libp2p/c-libp2p/src/peer_id/peer_id_ed25519.c`
- `/Users/multi/Documents/GitHub/libp2p/c-libp2p/src/peer_id/peer_id_ecdsa.c`
- `/Users/multi/Documents/GitHub/libp2p/c-libp2p/tests/peer_id/test_peer_id.c`

## Step 3: Explicit Standards Rule Selection and Selective Reading

### Local PDFs used
- `/Users/multi/Documents/GitHub/libp2p/standards/misra-c/MISRA C 2012 Guidelines for the use of.pdf`
- `/Users/multi/Documents/GitHub/libp2p/standards/sei-c/sei-cert-c-coding-standard-2016-v01.pdf`
- `/Users/multi/Documents/GitHub/libp2p/standards/sei-c/Secure Coding C and CPP _ 2nd edition.pdf`

### ToC browse evidence (local-PDF pass)

ToC extraction method used for this module pass:
- `pdfinfo <pdf>`
- `pdftotext <pdf> <txt>`
- `nl -ba <txt> | sed -n ...` to capture ToC anchors
- `rg` for rule/chapter anchors in ToC sections tied to parser, integer, string, and ownership risks in `peer_id`

Reviewed ToC entries with page numbers:

- `MISRA C:2012` (`/Users/multi/Documents/GitHub/libp2p/standards/misra-c/MISRA C 2012 Guidelines for the use of.pdf`)
  - `7.4 Code design` (p24)
  - `8.8 Declarations and definitions` (p63)
  - `8.10 The essential type model` (p81)
  - `8.12 Expressions` (p103)
  - `8.15 Control flow` (p122)
  - `8.17 Functions` (p136)
  - `8.18 Pointers and arrays` (p143)
  - `8.21 Standard libraries` (p165)
  - `8.22 Resources` (p172)
  - `Appendix A Summary of guidelines` (p180)
  - `Appendix B Guideline attributes` (p189)

- `SEI CERT C (2016)` (`/Users/multi/Documents/GitHub/libp2p/standards/sei-c/sei-cert-c-coding-standard-2016-v01.pdf`)
  - `4 Expressions (EXP)` (p68)
  - `EXP34-C` (section 4.4, p85)
  - `5 Integers (INT)` (p132)
  - `INT30-C` (section 5.1, p132)
  - `INT31-C` (section 5.2, p138)
  - `7 Array (ARR)` (p193)
  - `ARR30-C` (section 7.1, p193)
  - `8 Characters and Strings (STR)` (p226)
  - `STR31-C` (section 8.2, p230)
  - `STR32-C` (section 8.3, p242)
  - `Memory Management (MEM)` (p256)
  - `MEM31-C` (section 9.2, p262)

- `Secure Coding in C and C++ (2nd ed.)` (`/Users/multi/Documents/GitHub/libp2p/standards/sei-c/Secure Coding C and CPP _ 2nd edition.pdf`)
  - `Chapter 2 Strings` (p29)
  - `Common String Manipulation Errors` (p42)
  - `Improperly Bounded String Copies` (p42)
  - `Off-by-One Errors` (p47)
  - `Null-Termination Errors` (p48)
  - `strlen()` section (p86)
  - `Pointer Subterfuge` (Chapter 3, p121)
  - `Chapter 5 Integer Security` (p225)

### Section dive focus and extracted requirements for `peer_id`

Selected risk classes for this module:
- Integer and bounds safety for varint framing, multibase decode sizes, and CID prefix offsets.
- Parser correctness for legacy base58 peer IDs versus CIDv1 multibase strings.
- Deterministic API error/output behavior (especially `peer_id_to_string()` and parse failure paths).
- Ownership and lifetime of allocated peer-ID byte buffers.
- Private-key handling invariants in helper paths (avoid mutating caller-owned key buffers).

Section-dive conclusions that drove this rewrite:
- `EXP34-C`: every public API path must hard-fail on invalid pointers and keep deterministic output state.
- `INT30-C` + `INT31-C`: all size arithmetic and cast paths must be guarded before allocation and offset math.
- `ARR30-C`: parsed offsets/lengths for CID and multihash framing must be range-validated before indexing/copy.
- `STR31-C` + `STR32-C`: string decode/encode paths must reject malformed inputs and reset caller output on failure.
- `MEM31-C`: all allocated temporary buffers must be released on every error and success path.
- MISRA control-flow and expression guidance (`8.10`, `8.12`, `8.15`, `8.18`): explicit typed constants, bounded offset checks, and clear failure-state propagation.

Selected SEI CERT C rules and selective-reading targets:
- `EXP34-C`
- `INT30-C`
- `INT31-C`
- `ARR30-C`
- `STR31-C`
- `STR32-C`
- `MEM31-C`

Selected MISRA C:2012 rules/directives and selective-reading targets:
- Rule `8.4` (Required)
- Rule `10.4` (Required)
- Rule `10.8` (Required)
- Rule `12.1` (Advisory)
- Rule `15.5` (Advisory)
- Rule `15.7` (Required)
- Rule `17.7` (Required)
- Rule `18.4` (Advisory)
- Rule `21.3` (Required)
- Directive `4.1` (Required)

Risk-to-rule mapping used for this pass:
- Legacy/CID parse hardening and framing validation:
  - CERT `ARR30-C`, `STR32-C`, `EXP34-C`
  - MISRA Rule `15.7`, Rule `18.4`, Directive `4.1`
- Size arithmetic and conversion safety:
  - CERT `INT30-C`, `INT31-C`
  - MISRA Rule `10.4`, Rule `10.8`, Rule `12.1`
- Output determinism and API error contracts:
  - CERT `STR31-C`, `EXP34-C`
  - MISRA Rule `15.5`, Rule `17.7`, Directive `4.1`
- Ownership/lifetime cleanup:
  - CERT `MEM31-C`
  - MISRA Rule `21.3`, Directive `4.1`

## Step 7: Standards Finding Remediation Pass and Closure

Finding `F-01` (closed):
- Rule mapping: CERT `STR31-C`, `EXP34-C`; MISRA Rule `17.7`, Directive `4.1`.
- Issue: `peer_id_to_string()` returned positive error codes while API contract and callers expected negative error signaling (`< 0` checks), causing silent error-path ambiguity.
- Remediation: normalized `peer_id_to_string()` to return negative `peer_id_error_t` values, reset output buffers on failure, and preserved positive lengths on success.

Finding `F-02` (closed):
- Rule mapping: CERT `ARR30-C`, `STR32-C`, `INT30-C`; MISRA Rule `10.4`, Rule `15.7`, Rule `18.4`.
- Issue: string parse logic had duplicated decode paths and weaker legacy/CID discrimination and framing checks.
- Remediation: centralized decode helpers, enforced explicit CIDv1+`libp2p-key` framing validation, and added strict multihash structural validation before accepting parsed bytes.

Finding `F-03` (closed):
- Rule mapping: CERT `INT31-C`, `MEM31-C`; MISRA Rule `10.8`, Rule `21.3`, Directive `4.1`.
- Issue: several size/offset/allocation paths relied on repeated ad-hoc math and inconsistent cleanup.
- Remediation: added overflow-checked size-add helper, deterministic output reset helper, and explicit allocation/copy helpers with unified cleanup behavior.

Finding `F-04` (closed):
- Rule mapping: CERT `EXP34-C`, `MEM31-C`; MISRA Rule `8.4`, Directive `4.1`.
- Issue: private-key helper implementations cast away `const` and attempted to zero caller-owned input buffers.
- Remediation: removed caller-buffer mutation from RSA/Ed25519/ECDSA helper paths so function behavior no longer writes into externally owned input memory.

Finding `F-05` (closed):
- Rule mapping: CERT `ARR30-C`, `STR31-C`; MISRA Rule `15.5`, Rule `17.7`, Directive `4.1`.
- Issue: legacy `test_peer_id` coverage was monolithic and under-specified for negative/error contract behavior.
- Remediation: replaced test flow with vector-driven round-trips across all key types plus explicit negative/boundary checks (null inputs, malformed protobuf/string, short buffer output reset, equality/destroy semantics).

Closure evidence:
- Build/tests:
  - `cmake --build --preset macos-full --target peer_id peer_id_proto peer_id_rsa peer_id_ecdsa peer_id_ed25519 test_peer_id test_protocol_noise`
  - `ctest --preset macos-full -R '^(Testpeer_id|Testprotocol_noise)$' --output-on-failure`
  - `ctest --preset macos-full --output-on-failure`
- Sanitizer validation:
  - `cmake --preset linux-asan-ubsan`
  - `cmake --build --preset linux-asan-ubsan --target test_peer_id test_protocol_noise`
  - `ctest --preset linux-asan-ubsan -R '^(Testpeer_id|Testprotocol_noise)$' --output-on-failure`
  - `ctest --preset linux-asan-ubsan --output-on-failure`
- Formatting:
  - `clang-format --style=file --dry-run --Werror src/peer_id/peer_id.c src/peer_id/peer_id_rsa.c src/peer_id/peer_id_ecdsa.c src/peer_id/peer_id_ed25519.c tests/peer_id/test_peer_id.c`
- Static analysis:
  - `cppcheck --error-exitcode=1 --std=c99 --enable=warning,portability --quiet --suppress=missingIncludeSystem src/multiformats include/multiformats tests/multiformats src/peer_id include/peer_id tests/peer_id`
- Fast-lane parity:
  - `scripts/dev/run-fast-lane-local.sh --platform macos`

Open findings status for selected rules:
- Selected-rule remediation status for rewritten `peer_id` scope: closed for parser, integer/bounds, API determinism, and ownership findings addressed in this pass.
- CI-required gates for merge (`macos-smoke`, `linux-smoke`, `windows-smoke`) remain authoritative and are validated on the PR before merge.

## Step 8: Module Code Updated to Align with Findings

Delivered alignment changes:
- Rewrote core `peer_id` creation/parse/format logic with helper-driven framing validation, overflow-safe sizing, and deterministic output contracts in:
  - `/Users/multi/Documents/GitHub/libp2p/c-libp2p/src/peer_id/peer_id.c`
- Hardened private-key helper behavior to avoid mutation of caller-owned key buffers in:
  - `/Users/multi/Documents/GitHub/libp2p/c-libp2p/src/peer_id/peer_id_rsa.c`
  - `/Users/multi/Documents/GitHub/libp2p/c-libp2p/src/peer_id/peer_id_ed25519.c`
  - `/Users/multi/Documents/GitHub/libp2p/c-libp2p/src/peer_id/peer_id_ecdsa.c`
- Replaced `peer_id` tests with vector-driven positive/negative/boundary coverage in:
  - `/Users/multi/Documents/GitHub/libp2p/c-libp2p/tests/peer_id/test_peer_id.c`
