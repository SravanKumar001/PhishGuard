# PhishGuard

PhishGuard is a local-first platform for investigating suspicious URLs and email evidence. Its analysis is designed to be deterministic and explainable; submitted URLs and uploaded content are treated as untrusted data and are never fetched or executed.

The authenticated `POST /api/analyze/url` endpoint applies local URL syntax, hostname, IDN, encoding, redirect-parameter, brand-term, and URL-shortener rules. It does not resolve domains, follow redirects, retrieve reputation data, or open pages. Its risk category is a heuristic triage signal, not a probability or proof of safety.

Authentication endpoints are `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`, and `PUT /api/auth/me`. Investigation routes require a valid session and enforce owner scoping.

Email analysis is available at authenticated `POST /api/analyze/email` for pasted RFC 5322 content and `POST /api/analyze/email/file` for `.eml` uploads. Messages are parsed with bounded size, and attachments are inspected only as inert metadata.

Authenticated `POST /api/analyze` accepts up to 50 URLs and/or one pasted email and returns a combined, versioned assessment. Its fixed risk points and categories are explainable triage signals—not probabilities.

## Investigation workflow

The React workspace uses the authenticated API for registration/sign-in, case management, analysis, notes, reports, dashboard counts, and appearance preferences. In development, Vite proxies `/api` to `http://127.0.0.1:8000`.

- `POST /api/investigations` creates an owner-scoped case. Statuses are `new`, `investigating`, `confirmed_phishing`, `benign`, `needs_review`, and `closed`.
- `GET /api/investigations` supports `q`, `status`, `offset`, and `limit` (maximum 100), and returns `{items, total, offset, limit}`.
- `POST /api/investigations/{id}/analyze` analyzes pasted email and/or up to 50 URLs, then persists the result. `POST /api/investigations/{id}/analyze/email/file` does the same for `.eml`.
- `GET /api/investigations/{id}/findings` and `/submissions` retrieve saved evidence; `/notes` supports listing and adding analyst notes.
- `/reports/latest` retrieves the latest JSON report; `/reports/{report_id}/download` downloads JSON and `/download.pdf` downloads a PDF.
- `GET /api/dashboard/stats` returns owner-scoped case and severity counts. `GET/PUT /api/auth/preferences` manage theme and compact layout.
- Password reset and email verification use one-hour, single-use, SHA-256-stored account tokens. Configure `PHISHGUARD_SMTP_HOST`, `PHISHGUARD_SMTP_PORT`, `PHISHGUARD_SMTP_USERNAME`, `PHISHGUARD_SMTP_PASSWORD`, `PHISHGUARD_SMTP_FROM`, and `PHISHGUARD_SMTP_USE_TLS` to enable delivery.

Persistence minimizes submitted content: URL submissions retain only the analyzer's normalized/redacted URL; email submissions retain a marker, not the original message. Stored reports omit raw email bodies, headers, and embedded link URLs while retaining findings, evidence references, sender domains, and counts. API analysis responses include parsed message content for the requesting analyst; the browser UI does not render or save the raw body.

## Requirements

- Python 3.12+
- Node.js 20.19+ and npm

## Windows setup

From the `phishguard` directory:

```powershell
py -3.12 -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
npm ci --prefix frontend
Copy-Item .env.example .env
```

## Run and verify

From the `phishguard` directory, create or upgrade the database before using investigation endpoints:

```powershell
backend\.venv\Scripts\python.exe -m alembic -c backend\alembic.ini upgrade head
```

Start the backend:

```powershell
backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --reload
```

In another terminal, start the frontend:

```powershell
npm run dev --prefix frontend
```

Run backend checks:

```powershell
backend\.venv\Scripts\python.exe -m pytest backend\tests
backend\.venv\Scripts\python.exe -m ruff check backend\app backend\tests backend\alembic
```

Run frontend checks:

```powershell
npm run lint --prefix frontend
npm run test --prefix frontend
npm run build --prefix frontend
```

## Container smoke run

```powershell
docker compose up --build
```

The Compose service binds the API to `127.0.0.1:8000` and persists SQLite data in a Docker volume.

## Project status

See [PHASE_PROGRESS.md](./PHASE_PROGRESS.md) for phase status and verification evidence. This project is under active development and is not represented as production-ready.

Authentication and owner scoping are implemented, but this project is not ready for public deployment. The in-memory rate limiter is per process, password reset and email verification are not implemented, and deployment hardening has not been verified. Keep the API bound to localhost.
