# DeskPilot — Secret Exposure & Credential Audit

**Audited:** 2026-10-29
**Repositories:** `devpayoub/DeskPilot-Backend` @ `6529b00` · `devpayoub/DeskPilot-Frontend` @ `5491a3b`
**Visibility:** both **public** (verified via GitHub API, HTTP 200)
**Plan this executes:** [`SECURITY_AUDIT_PLAN.md`](./SECURITY_AUDIT_PLAN.md)

---

## Executive summary

**No secret is exposed in either public repository.** That is the headline, and it is
verified rather than assumed: neither repo has ever contained a `.env` file, the live
provider key does not appear in any tracked file, in any commit, or in the shipped
JavaScript bundle, and there are no private keys, certificates, or database files in
version control.

The risk in this project is therefore **not** "a key leaked to GitHub". It is that
several credentials are **weaker than they look** — plaintext at rest, unrevocable,
defaulted to a known value, or unthrottled. Those are the findings below, and the
most serious two are real.

| | Count |
|---|---|
| Verified clean (no action) | 14 checks |
| Findings | 13 |
| Addressed | **13 / 13** |
| — fixed outright | 10 |
| — mitigated (guarded in prod, root cause by design) | 2 (SEC-05, SEC-06) |
| — documented only, pending a business decision | 1 (SEC-08) |
| Credential rotations required | **0** — D1 answered "no" |

**The single most important sentence in this report:** the refresh token cannot be
revoked. Logout clears a cookie and nothing else, so a stolen token stays valid for
its full lifetime no matter what the user does. That is fixed.

---

## 1. Method

| Phase | What was actually done |
|---|---|
| S0 | Recorded audited SHAs. Confirmed both repos public. Installed `detect-secrets` 1.5.0 into an isolated venv — no project dependency changed. |
| S1 | Full-history sweep: `git log --all --diff-filter=A/D`, `git log -S<key>`, `fsck --lost-found`, deleted-file enumeration, private-key header search, `detect-secrets --force-use-all-plugins`, and a direct `grep -F` for the live key value across both repos. |
| S2 | Traced every secret-bearing setting from reader to sink: logging, error handlers, serializers, DRF exception handler, management commands, and `prod.py` fail-closed coverage. |
| S3 | Read and reasoned about token minting, verification, consumption, cookie flags, storage, and revocation paths. |
| S4 | Inspected `PasswordReset` storage, the live SQLite database, the backup tarball, and the exact payload sent to the LLM provider. |
| S5 | Scanned all 26 shipped JS files in `.next/static` for the live key, the signing key, `HOSTAGENT_TOKEN`, and `Bearer `; enumerated every `NEXT_PUBLIC_*` reference in source. |
| S6 | Report + remediation patch + test suite. |

**History scope note:** both repos contain exactly **one squashed commit**, local and
remote SHAs are identical, and `git fsck` reports no dangling objects. There is no
prior history to leak from — which is why S1 came back clean so decisively.

---

## 2. Verified clean

Each row is something a reviewer would reasonably worry about. These were checked
directly, not assumed.

| # | Check | Evidence |
|---|---|---|
| 1 | `.env` ever committed? | `git log --all --diff-filter=A` on both repos → only `.env.example` |
| 2 | Ignore rules correct? | backend ignores `.env`/`.env.*` with `!.env.example`; web ignores `.env*.local` |
| 3 | Live provider key in tracked files? | `git grep -F <key>` → 0 hits, both repos |
| 4 | Live provider key in history? | `git log --all -S<key>` → 0 commits |
| 5 | Live provider key anywhere on disk? | `grep -rl` across the tree → exactly 1 file: `backend/.env` |
| 6 | Live provider key in the client bundle? | 26 JS files scanned → 0 hits |
| 7 | Signing key in the client bundle? | 0 hits |
| 8 | Hardcoded `sk-…` / `Bearer …` literals? | `detect-secrets` + `git grep` → none in source |
| 9 | Private keys / certs / DBs committed? | `.pem`, `.key`, `.p12`, `.pfx`, `.sqlite3` → none tracked |
| 10 | Build artefacts committed? | `.next/`, `node_modules/`, `.venv/` → none tracked |
| 11 | Credentials embedded in git remotes? | `git config` → plain HTTPS URLs, no `user:pass@` |
| 12 | Token in browser storage? | `grep -r localStorage` → only theme/preference code, no tokens |
| 13 | Secrets in the backup tarball? | `tar -tzf` on `DeskPilot_frontend_backup_*.tar.gz` → no env files |
| 14 | Stack traces leaked to API clients? | `apps/common/exceptions.py` returns a generic 500 body; `DEBUG` defaults to `False` |

Two `detect-secrets` hits were reviewed and dismissed as false positives:
`windows_probe.py:143` (a long Windows registry path) and
`login/route.ts:20` (the variable named `password`). The one genuine hit is SEC-09.

### Controls that are already good

Worth stating plainly, because a report that only lists problems misleads:

- **Cookies** are `httpOnly`, `sameSite=lax`, `secure` in production. No token is
  readable from JavaScript, so an XSS bug cannot exfiltrate a session.
- **WebSocket trace tickets** are 60-second, `scope="ws:trace"`, bound to one `run`,
  and both checks are **enforced** in `consumers.py`, not merely embedded. The mint
  endpoint is scoped to the caller's own runs.
- **Audit rows** never store raw arguments: `redact_args()` masks any key containing
  `password`, `token`, `secret`, `api_key`, `credential`, `authorization`, or
  `private_key`, then hashes the canonical form for the approval binding.
- **Host agent** uses HMAC-SHA256 with a 300-second replay window and
  `hmac.compare_digest`, fails closed on an empty secret, binds `127.0.0.1` by
  default, exposes only read-only capabilities, and rejects unexpected arguments.
- **LLM client** logs model name and token counts only — never headers, never the key.
- **`lib/env.ts`** throws at import time if a client component pulls in server env.

---

## 3. Findings

Severity reflects this project's actual posture: a public repo, a demo deployment
model, and a system that can drive remediation on a real machine.

| ID | Severity | Finding | Status |
|---|---|---|---|
| SEC-01 | **High** | Directory passwords stored in plaintext, and expired rows never deleted | **Fixed** — encrypted at rest + purged |
| SEC-02 | **High** | Refresh tokens cannot be revoked; logout is cosmetic | **Fixed** |
| SEC-03 | Medium | `LDAP_BIND_PASSWORD` silently defaulted to `"admin"` | **Fixed** |
| SEC-04 | Medium | `HOSTAGENT_TOKEN` ships a published default; no replay nonce | **Fixed** — nonce added, default rejected in prod |
| SEC-05 | Medium | `SECRET_KEY` dev fallback lives in `base.py`, not just `dev.py` | Guarded in prod |
| SEC-06 | Medium | Compose `POSTGRES_PASSWORD` defaults to `deskpilot` in plaintext | Guarded in prod |
| SEC-07 | Medium | No throttling on authentication — unlimited password guessing | **Fixed** |
| SEC-08 | Medium | Ticket text and host inventory sent to a free third-party proxy | Documented |
| SEC-09 | Medium | `bootstrap_demo` publishes an admin password and has no prod guard | **Fixed** |
| SEC-10 | Low | CORS default port (3000) did not match the console (3001) | **Fixed** |
| SEC-11 | Low | The "never put secrets in `NEXT_PUBLIC_*`" rule was a comment, not a gate | **Fixed** |
| SEC-12 | Low | `/api/v1/schema/` and `/api/v1/docs/` are unauthenticated | **Fixed** — auth required in production |
| SEC-13 | Low | Provider error strings persisted verbatim to step records | **Fixed** — redacted at both storage chokepoints |

---

### SEC-01 — Directory passwords are plaintext at rest, and never deleted

**Severity: High** · `apps/directory/models.py:94`, `apps/directory/vault.py`

The vault solves the *model* exposure problem correctly — the agent only ever sees an
opaque `reference`, and the password never enters the prompt, the step record, or the
audit row. That part is genuinely well designed.

What it does not solve is the database. `password = models.CharField(max_length=128)`
stores the generated credential as-is. Worse, `expires_at` only gates **retrieval**;
nothing deletes the row. Every password the agent has ever generated stays in
plaintext indefinitely, including ones that may still be valid on a real directory.

**Blast radius:** anyone with a database dump — a backup, a laptop, a `.sqlite3` copied
for debugging — gets a list of working credentials for real user accounts.

**Exploitability:** requires DB read access, so this is not a remote attack. It is a
"the backup is on a shared drive" attack, which is how most of these actually happen.

**Fixed:**
- `purge_expired()` runs on every `store_password()`, so expiry means deletion.
- The column is now `password_ciphertext`, encrypted with Fernet
  (`apps/directory/crypto.py`). The key comes from `VAULT_ENCRYPTION_KEY`, stretched
  with SHA-256; when absent it is derived from `SECRET_KEY` so a fresh clone still
  runs, and `prod.py` refuses to start without an explicit value.
- `reveal_password()` is the only way back to plaintext, and it raises
  `VaultDecryptionError` rather than returning an empty string the operator would
  paste into a directory.
- Migration `0002_encrypt_password_reset` adds the column, encrypts existing rows,
  then drops the plaintext one — in that order, so it is safe on a database with data.

**Trade-off, stated plainly:** changing `SECRET_KEY` or the passphrase makes existing
rows unreadable. For a 15-minute credential that is the right trade, and it fails
loudly instead of silently.

---

### SEC-02 — Refresh tokens cannot be revoked

**Severity: High** · `apps/accounts/urls.py`, `config/settings/base.py`

There was **no `/auth/logout/` endpoint**. The console's BFF posted to it, got a 404,
and swallowed the error — so logout cleared three cookies and changed nothing on the
server. Combined with no `token_blacklist` app and no `SIMPLE_JWT` block (so the
library defaults applied), a refresh token stayed valid for its full lifetime with no
way to kill it.

This matters more than it looks. It means:

- "Log out everywhere" is impossible.
- A token stolen from a shared machine keeps working after the user logs out.
- There is no incident-response lever. If a token leaks, the only remedy is rotating
  the signing key, which signs out every user.

There was also a silent mismatch: the cookie max-age was **7 days**, but the backend
default refresh lifetime was **1 day**. The browser kept a dead token for six days.

**Fixed:**
- `LogoutView` added at `POST /api/v1/auth/logout/`, blacklisting the presented
  refresh token.
- `rest_framework_simplejwt.token_blacklist` added to `INSTALLED_APPS`; migrations
  applied.
- Explicit `SIMPLE_JWT` block: 15-minute access, 1-day refresh,
  `ROTATE_REFRESH_TOKENS=True`, `BLACKLIST_AFTER_ROTATION=True`.
- The BFF already handled a rotated refresh token (`refresh/route.ts:32`), so rotation
  is safe to enable without a frontend change.

---

### SEC-03 — `LDAP_BIND_PASSWORD` defaulted to `"admin"`

**Severity: Medium** · `config/settings/base.py:236`

```python
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD", "admin")   # before
```

Selecting `DIRECTORY_BACKEND=ldap` without setting the variable produced a working
bind as the OpenLDAP sample admin account. A default that *works* is worse than one
that crashes: nobody investigates a successful connection.

**Fixed:** no default. `base.py` now raises at import when
`DIRECTORY_BACKEND=ldap` and the password is empty. `prod.py` additionally rejects
`""` and `"admin"`.

---

### SEC-04 — `HOSTAGENT_TOKEN` ships a published default

**Severity: Medium** · `.env.example:52`, `packages/toolcore/toolcore/adapters/signing.py`

The signing scheme is solid: HMAC-SHA256 over `timestamp.body`, 300-second window,
constant-time comparison, fails closed when unset. Two residual issues:

1. `.env.example` suggests `dev-shared-secret`. Anyone who copies the example into a
   real deployment hands out a signing key that is printed in a public repository.
2. The signature covers the timestamp and the body but there is **no nonce**, so an
   identical request can be replayed within the 300-second window.

**Fixed:**
- `prod.py` refuses to boot if the token is any documented dev value.
- The signature now covers `timestamp "." nonce "." body`, and the host agent keeps a
  `NonceCache` bounded by the same 300-second window. A captured request is refused on
  the second use. The nonce is burned **after** the signature verifies, so an attacker
  cannot poison the cache under a nonce a real client is about to use.
- Both sides moved together — `signing.py` is shared, so the client and server cannot
  drift.

**Residual limit:** the cache is in-process, which is correct for one host agent.
A multi-process deployment would need a shared store, or the same nonce could be
accepted once per process.

---

### SEC-05 — Development signing key reachable outside `prod.py`

**Severity: Medium** · `config/settings/base.py:41`

`SECRET_KEY` falls back to `insecure-dev-key-do-not-use-in-production`. `prod.py`
correctly refuses to start on it — but only if `prod.py` is the module actually
loaded. Any deployment that runs `DJANGO_DEBUG=0` with `base` settings gets a publicly
known key, which forges sessions and JWT signatures.

**Mitigated:** the prod guard is retained and the settings contract is now documented
in `docs/SECURITY.md`. **Open:** moving the fallback out of `base.py` entirely would
break `manage.py` for anyone without a `.env`, so it stays — with the guard as the
control.

---

### SEC-06 — Compose database password

**Severity: Medium** · `docker-compose.yml:19,52,76`

`POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-deskpilot}` with the password also embedded
in `DATABASE_URL`. Correct for local compose, dangerous the moment the file is copied
to a server.

**Fixed:** `prod.py` refuses to start when `DATABASE_URL` still contains
`:deskpilot@`.

---

### SEC-07 — No throttling on authentication

**Severity: Medium** · `config/settings/base.py`

No `DEFAULT_THROTTLE_*` anywhere. `/api/v1/auth/login/` and `/api/v1/auth/token/`
accepted unlimited attempts, so password guessing was bounded only by network speed.

The login view does avoid an account-enumeration oracle (one message for both "no such
account" and "wrong password") — good — but that only stops *confirmation*, not
*guessing*.

**Fixed:** `AnonRateThrottle` and `UserRateThrottle` enabled globally, rates
configurable via `THROTTLE_ANON` (default `60/min`) and `THROTTLE_USER` (default
`600/min`). The test suite clears the cache between tests, so the existing fixtures
are unaffected.

---

### SEC-08 — Ticket text and host inventory leave the machine

**Severity: Medium** · `apps/agent/runtime.py:66-115`, `config/settings/base.py:212`

Every run sends to `LLM_BASE_URL` — currently a **free third-party proxy** — the
following, in plaintext over HTTPS:

- The ticket subject and body (employee-written, often personal).
- Every tool observation in the transcript: SAM account names, group memberships,
  service names, event-log excerpts, installed software, disk and port state.
- Truncated to 200 characters per string, 8 rows per list, 3,500 characters per
  observation — but that is a volume limit, not a privacy control.

This is not a bug; it is an architecture decision that was never written down. For a
helpdesk handling employee data it is also a GDPR-relevant data-processing question.

**Documented** in `docs/SECURITY.md` and `docs/guardrails.md`. Choosing a provider with
a data-processing agreement, or a self-hosted model, is **D2**.

---

### SEC-09 — Published admin password in `bootstrap_demo`

**Severity: Medium** · `apps/accounts/management/commands/bootstrap_demo.py:17`

`PASSWORD = "DeskPilot!2026"` creates three accounts, one of which is
`is_staff = True` (Django admin). The file is honest about it — it prints the password
so nobody mistakes it for a secret — but honesty is not a control. In a public repo
this is a documented credential for an admin account.

**Fixed:** the command now refuses to run when `DEBUG` is off unless `--force` is
passed.

---

### SEC-10 — CORS default did not match the console

**Severity: Low** · `config/settings/base.py:160`

Defaulted to ports 3000/3000, while the console runs on **3001**. A developer hitting
CORS errors is one search away from `CORS_ALLOW_ALL_ORIGINS = True`, which would
silently widen the perimeter for everyone.

**Fixed:** defaults now include 3001 and 3000.

---

### SEC-11 — The `NEXT_PUBLIC_*` rule had no enforcement

**Severity: Low** · `web/src/app/(main)/dashboard/tickets/[id]/_components/live-trace.tsx:86`

Only one `NEXT_PUBLIC_*` exists (`NEXT_PUBLIC_WS_URL`) and it is a URL, not a secret.
But Next.js inlines **every** `NEXT_PUBLIC_*` value into the browser bundle in
plaintext at build time. The protection was a comment in `.env.example`. One
`NEXT_PUBLIC_STRIPE_KEY` later and a secret is public forever, in every cached copy.

**Fixed:** `web/scripts/check-public-env.mjs` fails the build (`prebuild` hook) on any
`NEXT_PUBLIC_*` name matching `KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE|AUTH`,
with an explicit allowlist for the one legitimate case. Verified with a negative
control: a planted `NEXT_PUBLIC_LLM_API_KEY` exits 1, removal exits 0.

---

### SEC-12 — Schema and Swagger UI are unauthenticated

**Severity: Low** · `config/urls.py:24-29`

`/api/v1/schema/` and `/api/v1/docs/` are reachable without a token, publishing the
full API surface to anyone who asks. No secrets are in the schema, but it is free
reconnaissance.

**Fixed:** `SPECTACULAR_SETTINGS["SERVE_PERMISSIONS"]` is now `IsAuthenticated` **in
`prod.py` only**. A deployment requires a token; local development keeps Swagger open,
because opening it without logging in first is genuinely useful and the risk there is
nil. Verified both ways: dev → **200**, prod → **401**, `/health/` still **200**.

---

### SEC-13 — Provider error strings persisted verbatim

**Severity: Low** · `apps/agent/runtime.py:189-202`

`emit({"error": f"llm_error: {type(exc).__name__}: {exc}"})` wrote the raw exception
text into the step record, which the console then renders. Provider bodies do not
contain the API key, so this was not a live leak — but it was an unvalidated
passthrough of third-party text into stored, user-visible data.

The part that made it worth fixing rather than filing: **the transcript is fed back to
the model on the next iteration.** A credential echoed in an observation would be
stored, rendered, *and* shipped to the provider — the worst of the three sinks, because
that one leaves the machine.

**Fixed** — redaction happens at the two chokepoints where text is stored, not at each
call site:

- `redact_deep()` in `runtime.emit()`. Every step passes through it before reaching the
  database, the WebSocket, or the next prompt.
- `redact_text()` on `ToolInvocation.error_message` in the audit path.

Matching is by **shape** (`sk-…`, `Bearer …`, `user:pass@host`, `key=value` for
anything naming itself a credential) plus **exact value** for the configured
`LLM_API_KEY`, `HOSTAGENT_TOKEN` and `VAULT_ENCRYPTION_KEY` — because no pattern list
covers every provider's key format. Secrets shorter than 8 characters are ignored so
ordinary words are not shredded.

Two properties the tests hold it to: the message must stay **readable** after
redaction (a blank trace is its own failure), and unbounded third-party text is capped.

**Verified with a negative control:** bypassing `redact_deep` makes the key appear in
the stored row, so the assertion is load-bearing rather than decorative.

Also fixed: `check_llm` used to print the **first** six characters of the key
(`sk-apx`), leaking the provider prefix. It now prints the **last** four.

---

## 4. Files changed

| File | Change |
|---|---|
| `config/settings/base.py` | Explicit `SIMPLE_JWT`; token blacklist app; throttling; CORS ports; LDAP password fails closed; `VAULT_ENCRYPTION_KEY` |
| `config/settings/prod.py` | Rejects LDAP sample password, dev host-agent token, compose DB password, non-HTTPS LLM URL, wildcard hosts, missing vault key; requires auth on schema |
| `apps/accounts/views.py` | New `LogoutView` that blacklists the refresh token |
| `apps/accounts/urls.py` | Route `logout/` |
| `apps/accounts/management/commands/bootstrap_demo.py` | Refuses to seed a published admin password outside `DEBUG` |
| `apps/directory/crypto.py` | **New** — Fernet encrypt/decrypt for the vault |
| `apps/directory/models.py` | `password` → `password_ciphertext` + `reveal_password()` |
| `apps/directory/migrations/0002_encrypt_password_reset.py` | **New** — add, backfill, then drop the plaintext column |
| `apps/directory/vault.py` | `purge_expired()`; encrypts on write |
| `apps/directory/views.py` | Decrypts for the approver; reports `undecryptable` instead of returning blank |
| `packages/toolcore/toolcore/adapters/signing.py` | Nonce in the signed message; `NonceCache` |
| `packages/toolcore/toolcore/adapters/host_agent.py` | Fresh nonce per request |
| `services/hostagent/main.py`, `auth.py` | Verify the nonce, per-app cache |
| `apps/llm/management/commands/check_llm.py` | Prints last 4 chars of the key, not the first 6 |
| `web/scripts/check-public-env.mjs` | **New** build-time guard against secret-named public env vars |
| `web/package.json` | `prebuild` + `check:public-env` scripts |
| `requirements/base.txt` | `cryptography` declared explicitly (was arriving transitively) |
| `docs/SECURITY.md` | **New** — operating rules, rotation runbook, threat model |

---

## 5. Verification

Every fix was checked, not assumed.

| Fix | How it was proven | Result |
|---|---|---|
| SEC-01 encryption | `tests/test_directory.py` asserts the stored column is a Fernet token and does not contain the SAM | ciphertext at rest; plaintext only via `reveal_password()` |
| SEC-02 revocation | 4 new tests in `tests/test_auth_api.py` | logged-out refresh → **401**; rotated refresh replayed → **401**; logout without a token → **204**; unauthenticated logout → **401** |
| SEC-03 / SEC-04 / SEC-06 fail-closed | `DJANGO_SETTINGS_MODULE=config.settings.prod manage.py check` | **Refuses to boot**: `RuntimeError: HOSTAGENT_TOKEN is still a documented development value` |
| SEC-04 replay | 5 new tests in `tests/test_hostagent.py` | same signed request twice → **200 then 401** `nonce already used`; client sends a distinct nonce per call |
| SEC-11 public-env guard | Planted `NEXT_PUBLIC_LLM_API_KEY`, ran the guard, removed it | violation → **exit 1**; clean → **exit 0** |
| SEC-12 schema auth | `django.test.Client` GET under both settings modules | dev → **200**, prod → **401**, `/api/v1/health/` still **200** |
| SEC-13 redaction | 6 unit tests on `redact_text` / `redact_deep` + 2 end-to-end runtime tests | key absent from the stored step **and** from the next prompt |
| SEC-13 negative control | bypassed `redact_deep` in a throwaway test | key **does** appear in the stored row — the assertion is load-bearing |
| Test isolation | registered a tool without cleanup, then ran the catalogue tests | tool gone at the next test boundary; catalogue passes |
| No regressions | full suite | **245 passed, 19 skipped** (was 224 before any of this work) |

The 19 skips are the LDAP contract tests, which need an OpenLDAP container on
`localhost:3890`. They are skipped by design, not failing.

---

## 6. Decisions

| # | Question | Owner's answer | Consequence |
|---|---|---|---|
| D1 | Has the provider key (`sk-apx…`, 53 chars) been pasted into a chat, screenshot, or another repo? | **No** — confirmed 2026-10-29 | **No rotation required.** The key is contained to `backend/.env`. |
| D2 | Should prompts containing ticket text and directory data go to a free proxy? | Open — business decision | SEC-08 stays documented, not fixed |
| D3 | Encrypt `PasswordReset.password` at rest, or hash-and-never-recall? | **Encrypt** — done | SEC-01 closed |
| D4 | Add a nonce to the host-agent signature? | **Yes** — done | SEC-04 closed |
| D5 | Require auth on `/api/v1/schema/`? | **Yes, in production** — done | SEC-12 closed |

### D1 closure note — and one self-inflicted exposure

With D1 answered "no", the incident scenario is off the table and **nothing needs
rotating**. Recording two things so this report stays honest:

1. **During the audit, one of my own commands echoed the full key** into the local
   session transcript at
   `~/.workbuddy-ai/projects/…/0cf5a4a1-….jsonl`. It was a `grep` that printed the
   value it was searching for, which is exactly the mistake this report warns about.
   The file is local, not published, and `backend/.env` on the same disk already holds
   the key in plaintext — so the marginal exposure is effectively nil. It is still a
   secret in a log. To scrub it once this session is closed:

   ```bash
   KEY=$(grep -E '^LLM_API_KEY=' backend/.env | cut -d= -f2-)
   sed -i "s|$KEY|REDACTED|g" ~/.workbuddy-ai/projects/*/0cf5a4a1-*.jsonl
   ```

2. **The `.env` file itself is plaintext on disk**, which is correct and expected for
   local development. It becomes a finding only if that file is ever copied into a
   backup, a container image, or a screenshot.

---

## 7. Credential rotation checklist

Run only if a credential is later exposed, or on a schedule. **Not needed now** — D1
was answered "no".

| Order | Credential | How | What breaks |
|---|---|---|---|
| 1 | `LLM_API_KEY` | Provider dashboard → revoke → issue → update `backend/.env` → restart API **and** worker | Runs fail until restarted; no data loss |
| 2 | `DJANGO_SECRET_KEY` | `python -c "import secrets; print(secrets.token_urlsafe(50))"` | **Every session is invalidated.** All users must log in again |
| 3 | `HOSTAGENT_TOKEN` | `python -c "import secrets; print(secrets.token_urlsafe(32))"` in **both** API and host agent | Host agent rejects requests until both are updated |
| 4 | `LDAP_BIND_PASSWORD` | Directory admin → set → update env | Directory tools fail until restart |
| 5 | `POSTGRES_PASSWORD` | `ALTER ROLE deskpilot PASSWORD …` → update `DATABASE_URL` | API cannot reach DB until restarted |

**Never** rewrite public git history to "remove" a secret. It does not work — the
commit stays in forks, caches, and the GitHub API — and a force-push on a public repo
is itself destructive. Rotation is the only remedy.

---

## 8. Re-running this audit

```bash
# Tracked files only — what is actually on GitHub
python -m detect_secrets scan

# Whole history, all branches
python -m detect_secrets scan --all-files --force-use-all-plugins

# Does the live key appear anywhere it should not?
KEY=$(grep -E '^LLM_API_KEY=' backend/.env | cut -d= -f2-)
git -C backend grep -F "$KEY" ; git -C backend log --all -S"$KEY" --oneline

# Client bundle
grep -rl --binary-files=without-match -F "$KEY" web/.next/static

# Public-env guard
cd web && node scripts/check-public-env.mjs
```

---

## 9. Known limitation of this audit

The client-bundle check was run against the existing **development** build in
`web/.next/static` (26 JS files, zero hits for the key, the signing key, or
`HOSTAGENT_TOKEN`). A fresh production build could not be produced in this
environment: `.next` is held open by another process, and Turbopack refuses to resolve
`next` through a junctioned `node_modules` in a copied workspace.

The claim still holds on two independent grounds:

1. The dev bundle inlines `NEXT_PUBLIC_*` exactly as production does, and it is clean.
2. Next.js inlines **only** `NEXT_PUBLIC_*` values. The complete set of such
   references in `src/` is one, and it is a URL — so no server secret has a path into
   the bundle at all.

The permanent `prebuild` guard closes the gap for the future, which matters more than
a one-off grep of a build that will be replaced.
