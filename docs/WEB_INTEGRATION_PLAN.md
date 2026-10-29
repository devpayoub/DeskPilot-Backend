# Web console: integrating DeskPilot into the `copier` starter

Status: **Complete (P0-P5).**
Supersedes: the hand-written `frontend/` app (plain CSS, 6 pages).

---

## 1. Why the template wins

`copier` is a production-shaped admin dashboard ("Studio Admin") — Next.js 16 App
Router, React 19, Tailwind v4, shadcn `radix-nova`, TanStack Query/Table, zustand,
recharts, Biome. 230 files, 18 dashboard routes, and — the part that matters — a
**complete API integration layer**:

| Layer | File | What it already solves |
|---|---|---|
| Browser → server | `src/app/api/bff/[...path]/route.ts` | Prefix allowlist, path-segment sanitising, trailing-slash restore, `x-forwarded-for` passthrough |
| Server components | `src/lib/api/server.ts` | `serverFetch` with the httpOnly cookie, no token in JS |
| Token refresh | `src/proxy.ts` | Refresh happens in the proxy, not in RSC (which cannot set cookies) |
| Session | `src/lib/auth/session.ts` | One `/auth/me/` call per request, deduped with React `cache()` |
| Authorisation | `src/lib/auth/capabilities.ts` | Role → capability map for hiding UI the API already refuses |

The old `frontend/` had none of this: a JWT in `localStorage`, a hand-rolled
`fetchClient`, and ~280 lines of bespoke CSS. The template is a straight upgrade
on every axis except familiarity.

**What the template is not:** it is a *different product* (AI assistant platform
with organisations, members, API keys, knowledge bases). Its DTOs, routes and role
model do not match DeskPilot. Roughly a third of its screens must be deleted, and
every remaining screen needs its data layer replaced.

---

## 2. Decisions

| # | Decision | Reason |
|---|---|---|
| D1 | Rename `copier/` → `web/` | "copier" is the template's name, not ours. One web app, one obvious name. |
| D2 | Delete `frontend/` after zipping it outside the repo | Not a git repo, so deletion is unrecoverable. |
| D3 | Keep the template's **BFF + cookie** session model | No token readable from JavaScript. The old app stored a JWT in `localStorage`, which is an XSS liability. |
| D4 | Model DeskPilot as a **single workspace** | The template's whole session shape assumes organisations. Returning one synthetic membership keeps `requireTenant()`, the org switcher and `members` working with near-zero change. |
| D5 | Replace the template's `Role` union with DeskPilot's | `OWNER/DEVELOPER/MEMBER/READ_ONLY` are another product's roles. Mapping `TECHNICIAN → DEVELOPER` would be dishonest and would confuse an interviewer. |
| D6 | Enable DRF pagination and return `{count, next, previous, page, page_size, results}` | The template's `Paginated<T>` needs `page` and `page_size`; DRF's default omits them. `apps/common/pagination.py` already exists. |
| D7 | Delete the marketing site `(external)` | DeskPilot is an internal tool. A landing page with pricing is noise. |
| D8 | Add `/api/v1/auth/login/` and `/api/v1/auth/me/` to Django rather than change the BFF | Two small endpoints beat rewriting the auth layer. `/auth/token/` stays for the CLI and tests. |

### Role mapping

| DeskPilot role | Capabilities (UI gating only — the API enforces) |
|---|---|
| `REQUESTER` | `ticket:read` (own tickets only) |
| `SERVICE_DESK` | + `ticket:write`, `tool:read`, `audit:read`, `approval:read`, `usage:read` |
| `TECHNICIAN` | + `run:trigger`, `tool:invoke`, `approval:decide`, `directory:read` |
| `ADMIN` | + `policy:write`, `killswitch:write`, `settings:write`, `eval:read` |

---

## 3. Backend changes (small, additive)

| Change | File | Why |
|---|---|---|
| `POST /api/v1/auth/login/` → `{access, refresh, user}` | `apps/accounts/views.py` (new) | The BFF calls this exact path |
| `GET /api/v1/auth/me/` → `{user, memberships:[one]}` | same | Session + role resolution |
| `DefaultPagination.get_paginated_response` adds `page`, `page_size` | `apps/common/pagination.py` | Match `Paginated<T>` |
| Apply pagination to `tickets/`, `guardrails/invocations/`, `guardrails/approvals/`, `evals/runs/`, `directory/employees/` | the views | Tables need paging |
| `GET /api/v1/guardrails/settings/` → kill switch + SAFE_MODE + LLM model | new | Settings screen has nothing to show otherwise |

Nothing existing is modified in a breaking way: `/auth/token/` and all list
endpoints keep working (pagination adds keys, it does not remove the array
semantics for callers that ignore them — `TicketListView` currently returns a bare
list, so its test needs updating).

---

## 4. Frontend changes

### 4.1 Foundation (must land before any screen)

| File | Change |
|---|---|
| `src/lib/api/types.ts` | Replace the DTOs with DeskPilot's: `Ticket`, `AgentRun`, `AgentStep`, `ApprovalRequest`, `ToolSpec`, `ToolPolicy`, `ToolInvocation`, `EvalRun`, `Employee`, `Device`, `Stats` |
| `src/lib/auth/capabilities.ts` | New `Role` union + capability map (table above) |
| `src/app/api/bff/[...path]/route.ts` | Allowlist → `tickets`, `runs`, `tools`, `guardrails`, `evals`, `directory`, `stats` |
| `.env.local` | `API_BASE_URL=http://127.0.0.1:8010`, `APP_URL=http://localhost:3001` |
| `src/navigation/sidebar/sidebar-items.ts` | DeskPilot navigation, with capability gates |
| `package.json` | `name: "deskpilot-web"` |

### 4.2 Screens

Keep the shell, replace the data. `✎` = adapt an existing screen, `+` = new.

| Route | Nav | Source | API | Shows |
|---|---|---|---|---|
| `/dashboard/overview` | Overview | ✎ `overview` | `/stats/` | Auto-resolve rate, open tickets, pending approvals, **blocked actions**, p95 latency, cost/run, latest eval gate |
| `/dashboard/tickets` | Tickets | ✎ `conversations` | `/tickets/` | Queue with the agent's verdict, confidence, priority, status |
| `/dashboard/tickets/[id]` | ↳ detail | ✎ `conversations/[id]` | `/tickets/{id}/`, `/runs/{id}/`, `ws://…/ws/runs/{id}/` | Reported problem → diagnosis → **live step trace** → Run agent |
| `/dashboard/approvals` | Approvals | + | `/guardrails/approvals/`, `POST /approvals/{pk}/approve/` | Risk class, dry-run preview, args hash, expiry countdown, approve/reject |
| `/dashboard/tools` | Tools | ✎ `policies` | `/tools/`, `/guardrails/policies/` | 17-tool catalog: risk, domain, requires-approval, enabled toggle, role allowlist |
| `/dashboard/audit` | Audit | ✎ `audit` (near 1:1) | `/guardrails/invocations/` | Every attempt including **denials**, with actor, outcome, risk, latency |
| `/dashboard/evals` | Evaluations | ✎ `usage` | `/evals/runs/` | Triage accuracy, tool P/R, unsafe-action rate, gate verdict |
| `/dashboard/directory` | Directory | ✎ `members` | `/directory/employees/`, `/directory/devices/` | Seeded AD tenant: lockout, groups, devices |
| `/dashboard/settings` | Settings | ✎ `settings` | `/guardrails/killswitch/`, `/guardrails/settings/` | Kill switch, SAFE_MODE, LLM provider/model, read-only banner |

**Delete:** `assistants/**`, `knowledge/**`, `api-keys/**`, `playground/**`,
`conversations/**`, `usage/**`, `policies/**` (becomes `tools`), `(external)/**`,
`api/auth/register|verify-email|password-reset|deactivate` (DeskPilot has no
self-service registration), `api/org/select` (single workspace).

### 4.3 What is deliberately not built

- **Knowledge base** — DeskPilot has no RAG yet. The template's `knowledge` screens
  would be an empty shell pretending to be a feature.
- **API keys / playground** — no such endpoints, and no plan for them.
- **Usage quotas** — DeskPilot reports cost per run, not plan quotas.

---

## 5. Phases

| Phase | Work | Done when |
|---|---|---|
| **P0** ✅ | Archive `frontend/`, rename `copier` → `web`, compose service `web` → `api`, Makefile, `.gitignore`, env, ports pinned to 3001 | `make web` on :3001, `make api` on :8010 |
| **P1** ✅ | Django `/auth/login/` + `/auth/me/` + pagination envelope + 10 tests | BFF login sets httpOnly cookies and returns the role |
| **P2** ✅ | `types.ts`, `capabilities.ts`, BFF allowlist, sidebar, 30 dead files removed, **all 9 pages built** | every dashboard route 200 with real data |
| **P3** ✅ | Ticket detail: run-scoped WS ticket, live trace, "Run agent", polling fallback | press Run, watch steps arrive |
| **P4** ✅ | Approve/reject with note; policy toggles; policy rows created on demand | approve a write from the UI |
| **P5** ✅ | Pagination on 6 list endpoints; pager on 4 pages; out-of-range fallback | `npm run build`, pager verified |
| **P3** | Overview + Tickets + Ticket detail with live trace | Open a ticket, press Run agent, watch steps stream in |
| **P4** | Approvals + Tools + Audit | Approve a proposed write from the UI; audit shows the denial rows |
| **P5** | Evals + Directory + Settings | All 9 screens live; `npm run build` clean; README screenshots |

---

## 6. Risks

| Risk | Mitigation |
|---|---|
| Deleting `frontend/` loses work | Zip to `Desktop/DeskPilot_frontend_backup_<date>.zip` first; not a git repo, so this is the only copy |
| Template pages silently break (they call endpoints that no longer exist) | Delete unused screens in P2 rather than leaving them to 404 |
| `trailingSlash` trap that bit the old app | The BFF **already** restores the trailing slash (line 63) — do not add `trailingSlash: true` on top of it |
| Auth loop | Verify `proxy.ts` refresh path matches `/api/v1/auth/refresh/` (DeskPilot's name) in P2 |
| Two sources of truth for roles | `capabilities.ts` mirrors the API only to hide buttons; every action is re-checked server-side |
| Port confusion | API **8010**, web **3001** — 3000 is held by an unrelated project on this machine (`New folder (2)`), so the dev script pins the port instead of silently hopping. |

---

## 7. Non-goals

- Rewriting the backend to match the template's DTOs (wrong direction).
- Keeping the old `frontend/` alive behind a flag.
- Adding the knowledge/RAG screens before the backend has retrieval.


---

## 8. Deviations recorded during P2

| Planned | Actual | Why |
|---|---|---|
| P2 = foundation + shell only | **All 9 pages built** | Half the sidebar pointing at 404s looks broken; the pages are read-only tables, so they were cheap to do properly |
| Pagination applied in P1 | **Deferred to P5** | The API still returns bare arrays; every table renders unpaginated. `DefaultPagination` is ready, the views are not wired |
| `/guardrails/settings/` endpoint | **Not built** | The Settings page reads the existing kill-switch endpoint and documents the env vars instead of inventing an endpoint |
| — | **Approve/reject not wired** | Deliberate: the buttons need the role + self-approval checks exercised together. That is P4 |
| — | **Live trace not wired** | The ticket page shows the persisted trace; streaming is P3 |


---

## 9. P3: what the trace forced us to fix

Building the live trace exposed three defects that had nothing to do with the UI.

**1. The socket accepted any session token, for any run.** `RunTraceConsumer`
validated the JWT and stopped there — no scope, no run binding. Any authenticated
user could subscribe to `ws/runs/<any id>/` and read another ticket's tool output,
and the token rode in a query string where proxies log it.

Fixed with a **run-scoped ticket** (`apps/agent/ws_tokens.py`): `POST
/runs/<id>/ws-ticket/` mints a 60-second token carrying `scope="ws:trace"` and
`run=<id>`. The consumer requires both to match. This also solved a UI problem —
the console's access token is in an httpOnly cookie, so JavaScript cannot read it
to put in a WebSocket URL. Now it never has to.

**2. A provider refusal was reported as a budget failure.** A 402 from the LLM
provider ("daily check-in required") was caught by the loop's generic
`except Exception`, counted as a parse failure, retried four times, and surfaced
as *"budget exceeded: too many consecutive provider/parse failures"* — which
sends you hunting for an agent loop bug when the real problem is an unpaid
account. `chat_client` now raises `ChatProviderError` for 401/402/403/404, the
loop re-raises it without retrying, and the run fails with the provider's own
words.

**3. Failed steps had no explanation.** `_persist_step` used the emitted `error`
string only to compute the step's status, then threw the text away — so the trace
showed `[error]` with a blank reason, which is precisely the question a trace
exists to answer. It is now stored in `result` with `error_code="llm_error"`.

Known gap, recorded not hidden: `run.iterations` stays 0 on a failed run, because
the exception escapes before the loop's bookkeeping. The persisted step count is
the honest measure of "how many attempts happened".


---

## 10. P4: the approval gate, exercised from the UI

**What was wired.** `ApprovalActions` (approve / reject + a note that is recorded
against the approver) and `PolicyToggle` (optimistic switch with rollback). Both
call the existing endpoints through the BFF; neither re-implements a rule. The
components only decide what to *offer* — the API re-checks the approver's role and
refuses self-approval, so a drift bug can hide a button but never grant access.

**A backend fix the toggle forced.** `ToolPolicyDetailView.patch` used
`get_object_or_404`, so toggling a tool that had never been seeded returned 404 —
which is precisely the tool you would be trying to switch off after adding it. The
row is now created on demand, and an unknown tool name is rejected with
`tool_not_found` instead of silently creating a policy for a tool that does not
exist.

**Verified end to end, through the BFF with real cookies:**

| Scenario | Result |
|---|---|
| Technician approves a destructive change on a ticket they raised | `403 self_approval_denied` — "You raised this ticket. A destructive change on your own ticket needs a different approver." |
| Administrator approves a ticket someone else raised | `200`, `status=approved`, `decided_by=admin@…` |
| Same approval submitted again after it was spent | `409` — an approval authorises exactly one execution |
| Approved run resumes | step 1 `clear_temp_files` executed (`tool_calls=1`), step 2 failed on the provider's 402 |
| Service desk viewing Approvals | no approve button, explicit "your role can see this but not decide it" |
| Tools page as administrator | 17 toggles rendered |

Note on idempotency: a double-click *before* the run consumes the approval returns
`200` (the original decision), but a submission *after* consumption returns `409`.
Both are correct; they are different states.

**Known gap, unchanged from P3:** the resumed run cannot finish while the provider
returns 402, so "approved → executed → concluded" stops at "executed".


---

## 11. P5: pagination, and the two bugs it exposed

**Wired.** `DefaultPagination` applied to `tickets/`, `guardrails/invocations/`,
`guardrails/approvals/`, `evals/runs/`, `directory/employees/`,
`directory/devices/`. The `[:200]` slices are gone — they were a silent truncation
that looked like "we have 200 rows" rather than "there are more".

The pager appears on Tickets, Audit, Directory and Evaluations. Approvals
deliberately has none: a *pending* queue is small by construction, and a pager on
it would be a control nobody needs.

**Bug 1 — the API was never restarted.** Every page 500'd with
`Cannot read properties of undefined (reading 'length')` because daphne was still
serving the pre-pagination code: `results` did not exist yet. Not a code defect,
but a reminder that the two halves are deployed separately.

**Bug 2 — an out-of-range page crashed the page.** DRF answers `?page=99` with
`404 Invalid page`. That is right for an API and wrong for a page: rows get
deleted, links go stale, someone types a number into the URL. `serverFetchPage()`
now retries once at page 1 for exactly that case. Verified:
`?page=2` and `?page=99` both render page 1 instead of erroring.

**Verified:**

| Page | Result |
|---|---|
| `/dashboard/tickets` | `Showing 1–9 of 9`, `Page 1 of 1` |
| `/dashboard/audit` | `Showing 1–25 of 130`, `Page 1 of 6` |
| `/dashboard/audit?page=2` | `Showing 26–50 of 130`, `Page 2 of 6` |
| `/dashboard/audit?outcome=denied` | `Showing 1–1 of 1` — filter and pager coexist |
| `/dashboard/directory` | `Showing 1–8 of 8` |
| `/dashboard/evals` | `Showing 1–3 of 3` |

Filter links strip the `page` parameter, so changing a filter starts at page 1
rather than landing on page 4 of a smaller result set.
