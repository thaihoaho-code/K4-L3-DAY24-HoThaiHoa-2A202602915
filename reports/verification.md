# Verification record

Date: 2026-10-12 (local workspace, Asia/Saigon). Results below are from this checkout or explicitly marked as output supplied by the user.

## Checkpoints

| Checkpoint | Command and observed output | Status |
|---|---|---|
| PII detection and redaction | `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp\` — Python 3.13.13, pytest 9.1.1; `[pii] gold=118 pred=118 tp=118`; precision `1.000`, recall `1.000`; `2 passed in 0.41s`. Output supplied by user. | PASS |
| Split runs and injection lures | `.venv\Scripts\python.exe -m pytest tests/test_split.py tests/test_injection.py -q` — `9 passed in 2.40s`, no skips. Output supplied by user. | PASS |
| Supply-chain checkpoint | `pre-commit install` — installed hook; `pre-commit run --all-files` — `Detect hardcoded secrets ... Passed`; `python -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp` — `3 passed in 0.05s`. Output supplied by user. Hook pins Gitleaks `v8.30.1`; no standalone `gitleaks version` output was captured. | PASS; scanner version established by pinned hook |
| Full test suite | `.venv\Scripts\python.exe -m pytest tests/ -q --basetemp=.pytest_tmp\` — `33 passed in 3.22s`. Run in this checkout on Python 3.13.13; 0 skipped. | PASS |
| Ledger integrity | `.venv\Scripts\python.exe -c "from pathlib import Path; from agent.ledger import verify; print(verify(Path('reports/ledger.jsonl')))"` — actual check returned `True`. Ledger has 48 lines at this inspection. | PASS |
| Attack log and ledger comparison | Read-only check: `reports/attack-before.log` is 1,196 bytes; lines 1–4 contain POST bodies with synthetic `KH-000999`. `reports/attack-after.log` is 0 bytes. `reports/ledger.jsonl:24` and `:48` record `http_post`, `deny`, reason `restricted data cannot be used while egress is enabled`, and `on_behalf_of=dpo`. | PASS for inspected current files |
| Historical secret scan | `gitleaks git --config .gitleaks.toml` — user-provided output: 4 commits, about 138.24 KB, 1 finding. | PASS as recorded in `reports/secrets-incident.md` |
| Current-file secret scan | `gitleaks dir --config .gitleaks.toml --redact .` — user-provided output: about 37.32 MB scanned, no leaks. | PASS as recorded in `reports/secrets-incident.md` |

## Errors and corrections recorded

- During the PII work, the first matching pass had overlapping numeric candidates and punctuation-boundary issues. The detector was adjusted to prioritize labeled account numbers and more specific entity types, resolve overlapping spans, and redact from right to left. The final reported test set is exact at 118/118.
- An earlier attempt to capture a baseline replay appended entries to `reports/attack-before.log`. At the user's direction, those manually added entries were removed and the file was restored to 1,196 bytes. Current comparison above inspects the existing file; no log text was manually fabricated for this report.
- No full-suite failures or skips were observed in the current run. No remaining checkpoint is being marked successful based on inference.

## Limits

The PII score is for `tests/vn_pii_testset.jsonl`, not a guarantee for real-world data. Regexes can miss unusual formatting and may flag unlabeled 8–16 digit sequences as accounts. Gitleaks version was not independently printed by a standalone version command; `v8.30.1` comes from the configured, successfully run pinned pre-commit hook.
