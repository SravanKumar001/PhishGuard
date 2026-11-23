# PhishGuard Phase Progress

## Phase 0 — Environment audit and project initialization

**Status:** Complete.

- Isolated the new project under `phishguard/` to preserve the existing HireLens application.
- Confirmed the workspace provides Python 3.12.10, Node.js 24.18.0, npm 11.16.0, and Git.
- Installed the isolated backend and frontend dependencies.
- Backend tests: **1 passed** (`python -m pytest .\phishguard\backend\tests`).
- Backend lint: **passed** (`python -m ruff check .\phishguard\backend\app .\phishguard\backend\tests`).
- Frontend tests: **1 passed** (`npm run test --prefix phishguard\frontend`).
- Frontend lint: **passed** (`npm run lint --prefix phishguard\frontend`).
- Frontend production build: **passed** (`npm run build --prefix phishguard\frontend`).
- Started Uvicorn and verified `GET /api/health` returned `{"status":"ok","service":"PhishGuard API"}`.

## Phase 1 — Database and backend foundation

**Status:** Complete.

- Added SQLAlchemy entities for users, investigations, submissions, extracted indicators, findings, reports, notes, and audit events.
- Added Alembic initial migration and verified downgrade/upgrade plus `alembic check` against the ORM schema.
- Added health and investigation create/list/read/update/delete API endpoints with validation and audit events.
- Backend tests: **5 passed**.
- Backend Ruff lint: **passed**.
- Live Uvicorn smoke test: health, create, list, update, and delete all passed; the temporary investigation was removed.
- API currently has no authentication; local-only use is documented until Phase 2 is complete.

## Phase 2 — Authentication and user management

**Status:** Complete.

- Added email-validated account registration and profile email updates.
- Passwords use Argon2 hashing via `pwdlib`; raw passwords are not stored or returned.
- Login creates a random opaque, HTTP-only `SameSite=Lax` cookie; only a SHA-256 token hash is stored server-side. Logout deletes that session.
- Added protected current-user and investigation endpoints; every investigation lookup/list/update/delete is owner-scoped.
- Added bounded, per-process login and registration rate limits.
- Backend tests: **10 passed**, including invalid credentials, anonymous rejection, logout revocation, rate limiting, and cross-user isolation.
- Ruff lint: **passed**; Alembic `check`: **passed**.
- Live Uvicorn smoke test verified anonymous 401, register/login/current-user, authenticated investigation create/delete, logout, and post-logout 401.
- Password reset is not implemented. Rate limiting is in-memory per process and is not sufficient for a multi-worker public deployment.

## Phase 3 — Core URL phishing detection engine

**Status:** Complete.

- Added authenticated `POST /api/analyze/url` with URL syntax, HTTP, IP-host, hostname length/depth, IDN/punycode, mixed-script, userinfo, port, encoding, redirect parameter, credential language, brand lookalike, shortener, and combined-signal checks.
- Uses the packaged Public Suffix List offline; no submitted URL is resolved, fetched, or redirected.
- Returns normalized URL (userinfo and sensitive query values redacted), registrable domain, explainable findings/evidence/severity, risk category, recommendations, and explicit uncertainty/limitations. No probability score is claimed.
- Added reusable labeled benign/synthetic fixture data and malformed, IDN, mixed-signal, and no-network tests.
- Backend tests: **18 passed**.
- Ruff lint: **passed**; Alembic `check`: **passed**.
- Live authenticated URL check returned the expected high-risk IP/HTTP findings and uncertainty response.

## Phase 4 — Email phishing analysis engine

**Status:** Complete.

- Added MIME-aware RFC 5322 parsing for pasted messages and `.eml` uploads; both paths enforce a 1 MB content limit.
- Extracts standard sender/recipient/subject/date/message headers, Received chain, plain text, HTML text and links, and inert attachment metadata.
- Detects From/Reply-To/Return-Path mismatches, display-name/domain impersonation, urgency/credential/financial language, suspicious linked URLs, and dangerous attachment extensions.
- HTML is parsed as text; scripts and attachments are not executed or opened. Authentication-Results headers are always marked untrusted for user-submitted messages.
- Tests cover plain and multipart MIME, IDNs/URLs, malformed messages, file type and size handling, and anonymous access rejection.
- Backend tests: **22 passed**; Ruff lint: **passed**.
- Live Uvicorn checks verified pasted-message analysis and `.eml` upload analysis.

## Phase 5 — Unified risk engine

**Status:** Complete.

- Added versioned deterministic finding aggregation (`1.0.0`) shared by URL and email analysis.
- Duplicate findings with identical rule/evidence are suppressed while all evidence references are retained; conflicting duplicate severities preserve the stronger finding.
- Risk points use documented fixed weights (low 1, medium 3, high 7, critical 10), capped at 100; points are explicitly not a probability.
- Empty input is reported as insufficient evidence; a clean local-rule result explicitly does not prove safety.
- Added authenticated `POST /api/analyze` to combine up to 50 URLs and one email into a single assessment.
- Backend tests: **27 passed**; Ruff lint: **passed**.
- Live combined analysis verified a critical result with evidence references, version, points, and scoring disclaimer.

## Phase 6 — Optional threat intelligence and ML

**Status:** Complete — offline-only.

- Core URL/email detection works without external services or API keys.
- No paid intelligence, DNS, webpage fetching, ML model, or third-party submission is enabled. Live reputation/ML capabilities are not present or verified.
- The packaged Public Suffix List is used offline; submitted URLs are not resolved or fetched.

## Phase 7 — Investigation API and workflow

**Status:** Complete.

- Added the full owner-scoped investigation status lifecycle, searchable/filterable paginated listing, dashboard statistics, submissions/findings retrieval, analyst notes, persisted reports, and per-user theme/compact-layout preferences.
- Added case-scoped combined URL/email analysis and `.eml` upload workflows. Findings, evidence references, and extracted domains/IPs are persisted with audit events.
- Added downloadable JSON reports. Persistence omits raw email bodies, headers, and embedded URLs; URL submissions retain only analyzer-normalized/redacted values. Email reports contain evidence summaries, not raw content.
- Replaced the frontend starter with an authenticated React workspace for case setup, status management, URL/email analysis, `.eml` upload, findings, notes, reports, dashboard counts, and preferences.
- Added Vite's local `/api` proxy; no external font or threat-intelligence service is required.
- Backend tests: **30 passed**; Ruff lint: **passed**; Alembic upgrade and schema check: **passed**.
- Frontend tests: **2 passed**; Oxlint: **passed**; production build: **passed**.
- Browser smoke test verified account creation, case creation, URL analysis, saved findings/report, and preferences page against local services.
- PDF reports are implemented.
- Password reset and email verification are implemented behind configured SMTP delivery. Requests fail honestly with 503 until SMTP is configured; verification/reset tokens expire after one hour and are stored only as SHA-256 hashes.
- Added Docker Compose deployment packaging, a GitHub Actions CI workflow, MIT licensing, and container smoke configuration.
- Redis-backed multi-worker rate limiting and full public deployment hardening remain follow-on deployment work.
