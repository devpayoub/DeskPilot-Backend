# DeskPilot — Secret Exposure & Credential Audit Plan

**Target:** `DeskPilot-Backend` + `DeskPilot-Frontend`
**Date:** 2026-10-29
**Status:** Plan — awaiting approval before execution

---

## 0. Why this audit, and why now

Two facts make this urgent rather than routine:

1. **Both repositories are public.** Verified against the GitHub API: `DeskPilot-Backend` → HTTP 200, `DeskPilot-Frontend` → HTTP 200. Anything that has ever been committed is readable by anyone, right now, without authentication.
2. **The system holds real credentials by design.** It stores directory passwords (`PasswordReset`), mints JWTs, holds a provider API key, and can drive a host agent that performs remediation on a Windows machine. A leak here is not cosmetic.

A secret committed once is compromised permanently. Deleting it in a later commit does **not** remove it from history, forks, or caches. So this audit must cover *history*, not just the current tree.

---

## 1. Scope

### In scope

| # | Asset class | Examples |
|---|---|---|
| A1 | LLM provider credential | `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL` |
| A2 | Django / signing secrets | `DJANGO_SECRET_KEY`, session signing |
| A3 | Auth tokens | JWT access/refresh, WS trace tickets, BFF session cookie |
| A4 | Service-to-service secrets | `HOSTAGENT_TOKEN`, LDAP bind password, DB password |
| A5 | Credentials at rest | `PasswordReset.password`, `.env`, `db.sqlite3` |
| A6 | Internal URLs / topology | API base URLs, host-agent URL, provider endpoint, ports |
| A7 | Client bundle exposure | anything inlined via `NEXT_PUBLIC_*` into shipped JS |
| A8 | Third-party data egress | what leaves the machine to `api.apinex.bond` |
| A9 | Git history & artefacts | deleted files, `.next/`, `.venv/`, logs, tarballs |

### Out of scope (stated explicitly so nobody assumes coverage)

- Business-logic authz beyond token handling (already covered by the 10-gate chokepoint tests).
- Dependency CVE scanning / `pip-audit` / `npm audit` — separate workstream.
- Container escape, OS hardening, network segmentation.
- The hosted deployment, because there isn't one yet.

---

## 2. Recon already completed (evidence, not assumptions)

Run before writing this plan, so the phases below target real gaps instead of generic checklist items.

### Clean ✅

| Check | Method | Result |
|---|---|---|
| `.env` committed? | `git log --all --diff-filter=A --name-only` on both repos | **No.** Only `.env.example` has ever been added. |
| Ignore rules correct? | read `.gitignore` ×2 | **Yes.** Backend ignores `.env` / `.env.*` with `!.env.example`; web ignores `.env*.local`. |
| Live provider key in any tracked file? | `git grep -F <key>` on both repos | **Not found.** |
| Live provider key in git history? | `git log --all -S<key>` | **Not found.** |
| Hardcoded `sk-…` / `Bearer …` literals? | `git grep -E` on tracked source | **None.** |
| Secret read from a client component? | scanned every `"use client"` file for `process.env` | **One hit, and it is not a secret** — `NEXT_PUBLIC_WS_URL` in `live-trace.tsx`. |
| Prod hardening present? | `config/settings/prod.py` | **Yes.** Refuses to boot on the dev `SECRET_KEY`; sets SSL redirect, secure cookies, HSTS 30d, proxy SSL header. |

### Findings already visible — these go straight into the report

| ID | Severity | Finding | Location |
|---|---|---|---|
| F-01 | **High** | `LDAP_BIND_PASSWORD` silently defaults to `"admin"`. If `LDAP` backend is selected and the env var is missing, the app binds with `admin` instead of failing closed. | `config/settings/base.py:236` |
| F-02 | **High** | `PasswordReset.password` is stored **in plaintext** in the DB. The vault prevents the *model* from seeing it, but not the *database* from holding it. `db.sqlite3` is git-ignored, not encrypted. | `apps/directory/vault.py:16-25` |
| F-03 | **High** | `HOSTAGENT_TOKEN` defaults to a shared static string `dev-shared-secret` in `.env.example`, and is a single bearer secret with no rotation, no per-call nonce, and no mTLS. If that agent ever runs for real, the token is the whole perimeter. | `.env.example`, `config/settings/base.py:226` |
| F-04 | **Medium** | `SECRET_KEY` falls back to `insecure-dev-key-do-not-use-in-production` in `base.py`. `prod.py` guards it — but any run that sets `DJANGO_DEBUG=0` without importing `prod` boots with a publicly known signing key. | `config/settings/base.py:40` |
| F-05 | **Medium** | `POSTGRES_PASSWORD` defaults to `deskpilot` and is embedded in `DATABASE_URL` in plaintext in compose. Fine locally; a landmine if copied to a server. | `docker-compose.yml:19,52,76` |
| F-06 | **Medium** | No `SIMPLE_JWT` block anywhere → library defaults: 5-min access, **1-day refresh, no rotation, no blacklist**. A stolen refresh token is valid for 24h and cannot be revoked. | `config/settings/base.py:144` |
| F-07 | **Medium** | No DRF throttling configured → `/api/auth/token/` accepts unlimited password guesses. | `config/settings/base.py` (absent) |
| F-08 | **Medium** | `CORS_ALLOWED_ORIGINS` defaults to ports **3000**, but the console runs on **3001** (`web/.env.local`). The tempting "fix" is `CORS_ALLOW_ALL_ORIGINS=True`, which would silently widen the perimeter. | `config/settings/base.py:160` |
| F-09 | **Low** | `NEXT_PUBLIC_WS_URL` is a build-time-inlined value. It is a `ws://` URL, not a secret — but it establishes that this channel *would* leak a secret if one were ever added there. Needs a written rule + a CI guard, not just a comment. | `web/src/.../live-trace.tsx:86` |
| F-10 | **Low** | Provider endpoint is a third-party **free proxy** (`api.apinex.bond`). Ticket text, SAM account names and group memberships are sent there in prompts. This is a data-egress decision, not a bug — but it is undocumented. | `config/settings/base.py:211` |

### Not yet verified — the actual work

These need the phases below. I am not claiming they are clean:

- Whether the JWT refresh token is reachable from JavaScript (localStorage / non-httpOnly cookie) versus httpOnly.
- Whether `ws_tokens.py` enforces `scope` + `run` on the consumer side, or only mints them.
- Whether audit rows / step `result` fields persist secrets, passwords or PII.
- Whether `check_llm` or any logger prints the key (including tracebacks with `repr(request)`).
- Whether the built `.next/` bundle contains anything beyond the one public var.
- Whether the on-disk `db.sqlite3`, `.venv/`, and the `Desktop/DeskPilot_frontend_backup_*.tar.gz` archive contain secrets.

---

## 3. Audit model — the nine surfaces

Each phase below is a closed loop: **detect → confirm exploitability → rate → remediate → prove the fix**.

```
A9 history ──► A1 provider key ──► A2 signing key
                    │
A3 auth tokens ─────┼──── A4 service secrets
                    │
A5 at rest ──── A6 URLs ──── A7 client bundle ─── A8 egress
```

---

## 4. Phases

### S0 — Baseline & tooling (no findings yet)

- Confirm both repos public, record commit SHAs audited (`backend@6529b00`, `web@5491a3b`).
- Install a scanner into an **isolated** venv (never global): `detect-secrets` (Yelp) + `trufflehog` if available.
- Establish the false-positive baseline so the report separates *new* leaks from known dev placeholders (`dev-shared-secret`, `deskpilot`, `insecure-dev-…`).

**Exit:** baseline file committed as `docs/.secrets.baseline`, scanner runs cleanly on both repos.

### S1 — Git history sweep (highest priority)

The current tree is already known-clean; history is where the risk is.

- `detect-secrets scan --all-files` and `trufflehog git file://. --only-verified` across **all** branches and tags, both repos.
- Enumerate every path ever added, and diff against the current tree to find **deleted** files (deleted ≠ gone).
- Entropy scan for high-randomness strings in history, not just pattern matches.
- Search history specifically for: the live key prefix `sk-apx`, `Bearer `, `Authorization:`, private-key headers (`BEGIN RSA/OPENSSH/PGP`), `.pem`/`.pfx` blobs.
- Check commit messages and author fields for pasted credentials.

**Exit:** a definitive statement — "no secret in history" or a list with blob SHAs and the commit that introduced each.

### S2 — Live credential inventory

For every env var in `.env` / `.env.example` / compose / settings: where is it read, where does it flow, is it logged, is it reachable from the browser.

- Grep every read site of `LLM_API_KEY`, `HOSTAGENT_TOKEN`, `DJANGO_SECRET_KEY`, `LDAP_BIND_PASSWORD`, `POSTGRES_PASSWORD`.
- Trace whether any of them reaches a response body, an error message, a log line, or a DRF serializer.
- Inspect `check_llm` and the LLM client for `repr()`/`%s` of headers or the key.
- Verify `prod.py` refuses to boot on every weak default, not just `SECRET_KEY` (F-01, F-03, F-05 are the gaps).

**Exit:** a credential flow table — var → reader → sink → exposure verdict.

### S3 — Token lifecycle (A3)

- `ws_tokens.py`: is `scope` and `run` **enforced** at the consumer, or only embedded in the token? Is it single-use? Does it expire server-side? Replay it and see.
- JWT: confirm lifetimes, add rotation + blacklist decision (F-06). Test that a logged-out refresh token stops working.
- BFF cookie: confirm `httpOnly`, `secure` in prod, `sameSite`, and that no route echoes the token back in a JSON body.
- Confirm the frontend never persists a token in `localStorage`/`sessionStorage` (`grep -r "localStorage"`).

**Exit:** each token classified as revocable / expiring / replayable, with a test that proves it.

### S4 — Secrets at rest & egress (A5, A8)

- `PasswordReset`: decide plaintext → encrypted-at-rest or hash-and-never-recall (F-02). Confirm TTL and single-retrieval actually hold.
- Inspect `db.sqlite3` for live secrets; confirm it is not in any backup that gets shared.
- Check `Desktop/DeskPilot_frontend_backup_2026-10-28.tar.gz` for stray env files.
- Document exactly what payload leaves to the provider (F-10) and add a data-egress note to `docs/guardrails.md`.

**Exit:** written statement of what sits in plaintext on disk, plus a remediation patch for the vault.

### S5 — Client bundle & repo hygiene (A7, A9)

- Build the console, then grep `.next/static/**/*.js` for the live key, the JWT secret, `HOSTAGENT`, and any `sk-` string. This is the only way to *prove* no server secret is inlined.
- Add a CI guard that fails the build if a `NEXT_PUBLIC_*` name matches `/KEY|SECRET|TOKEN|PASSWORD/i`.
- Confirm `.gitignore` still covers every artefact the build produces.

**Exit:** a bundle grep showing zero hits, plus the CI rule.

### S6 — Report & remediation

- `docs/SECURITY_AUDIT.md`: findings with severity, evidence (file:line), exploitability, blast radius, fix, and verification command.
- Apply the low-risk fixes directly (defaults that fail closed, throttling, CORS port, JWT rotation flags, CI guard).
- Leave anything that changes behaviour or needs a decision to the user, listed as **Decision required**.
- Re-run the suite: the existing 10-gate tests plus `pytest` must stay green.

**Exit:** report + patch + green tests.

---

## 5. Severity rubric

| Level | Meaning in this project |
|---|---|
| **Critical** | A live secret is readable in a public repo. Rotate immediately, then purge history. |
| **High** | A credential is exposed through a plausible path (default password, plaintext at rest, unrevocable token). |
| **Medium** | Weakens defence in depth: missing throttling, permissive CORS, long-lived tokens, forgeable dev key. |
| **Low** | Hygiene: documented-but-unenforced rules, missing CI guard, undocumented egress. |

---

## 6. Deliverables

1. `docs/SECURITY_AUDIT_PLAN.md` — this document.
2. `docs/SECURITY_AUDIT.md` — findings, evidence, severity, remediation status.
3. `docs/.secrets.baseline` — scanner baseline so future commits are checked against a known state.
4. Code patches for every fix rated Low/Medium that does not change product behaviour.
5. A **credential rotation checklist** — which keys to rotate, in what order, and what breaks when each rotates.
6. Green `pytest` run proving nothing regressed.

---

## 7. Rules I will hold myself to

- **Never print a secret value** into a report, log, commit, or chat message. Findings reference location and length only, e.g. `LLM_API_KEY` (53 chars, `sk-apx…`).
- **Never rotate a credential without explicit approval** — rotation breaks the running system.
- **Never rewrite git history** without explicit approval. History rewriting is destructive and would need a force-push to a public repo.
- **Assume the key is already compromised** until S1 proves otherwise, and say so plainly rather than reassuring.
- Report what I *verified*, and label everything else as unverified. No "should be fine".

---

## 8. Decisions I need from you before executing

| # | Question | Why it matters |
|---|---|---|
| D1 | Has the `LLM_API_KEY` (`sk-apx…`, 53 chars) ever been shared, screenshotted, pasted into a chat, or committed elsewhere? | Determines whether this is a *rotation* task or just a *containment* task. |
| D2 | Should the two GitHub repos stay public? | If they can be private, the blast radius of any historical leak drops sharply. |
| D3 | Is `HOSTAGENT_TOKEN` ever going to guard a real machine, or is the host agent permanently simulated? | Decides whether F-03 is High or Low. |
| D4 | Is `SAFE_MODE=1` / `ALLOW_REAL_WRITES=0` the permanent posture for the demo, or will this ever run for real? | Decides how hard the at-rest and token findings bite. |

If you would rather not answer, I will assume the worst case — **the key is compromised, the repos stay public, and the host agent could become real** — and audit accordingly. That is the safer default and it costs you nothing but a longer fix list.

---

## 9. Execution order & effort

| Phase | Focus | Blocking? |
|---|---|---|
| S1 | History sweep | **Yes** — everything else is secondary until we know nothing leaked |
| S2 | Credential flow | Yes |
| S3 | Token lifecycle | No |
| S4 | At rest / egress | No |
| S5 | Bundle / hygiene | No |
| S6 | Report + patch | No |

**First thing I will do on approval:** S1, because it is the only phase that can turn this from an audit into an incident.
