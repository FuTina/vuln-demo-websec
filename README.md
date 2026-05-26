# Database Security Playground

An intentionally vulnerable Express and SQLite demo for a database security presentation.
It shows how common application choices affect data exposure and database risk through safe local simulations.

## What This Demonstrates

- SQL Injection: vulnerable string concatenation compared with safe parameterized queries.
- Cross-Site Scripting: unsafe `innerHTML` compared with safe `textContent`.
- Role-based data masking: guest, app user, analyst, and admin views with RBAC and masking toggles.
- Audit logging: fake security events that build an investigation timeline.
- Network exposure: public database port compared with internal-only access.
- Secure configuration: risky defaults compared with hardened database settings.
- Presentation framing: a dynamic risk score and clickable security controls.

## Local Warning

This project contains intentionally vulnerable endpoints and simulated security scenarios.
Use it only locally or in an isolated lab environment.
Do not expose it to the internet or use it as a production pattern.

## Run Locally

`npm start` loads local environment variables from `.env` automatically.
Copy the example file first if you want to change the default database mode:

```bash
cp .env.example .env
```

The default example uses SQLite:

```bash
npm install
npm start
```

Open:

```text
http://localhost:5173
```

Run the lightweight smoke test:

```bash
npm test
```

To run `npm start` against a local PostgreSQL database, set these values in `.env`:

```dotenv
DB_CLIENT=postgres
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=playground
POSTGRES_USER=app_user
POSTGRES_PASSWORD=change-me
POSTGRES_SSLMODE=disable
```

Use `POSTGRES_SSLMODE=disable` for a typical local Docker or laptop PostgreSQL instance without TLS.
For hosted PostgreSQL providers such as Render, use the provider's SSL requirement instead.

## Docker Database Mode

The app still runs with SQLite by default for the fastest local demo path.
Docker Compose runs the same app with a connected PostgreSQL database service:

- `docker-compose.yml` - isolated app and PostgreSQL services on separate networks.
- `config-examples/postgres/risky` - intentionally risky example files.
- `config-examples/postgres/hardened` - hardened reference files used by the Postgres tab on `/config.html`.
- `secrets.example` - example secret files; copy these to `secrets/` before running Compose.

The PostgreSQL container uses a self-signed demo certificate and `pg_hba.conf` rejects non-TLS TCP connections.
This is suitable for the local security demo, not a production certificate pattern.
When the app runs inside Docker Compose, `docker-compose.yml` sets `POSTGRES_SSLMODE=require` and reads the password through `POSTGRES_PASSWORD_FILE`.

The Compose file also applies demo-friendly container hardening:

- no published Postgres port
- internal backend network
- dropped Linux capabilities
- read-only filesystems
- tmpfs runtime directories
- `no-new-privileges`
- process limits

```bash
mkdir -p secrets
cp secrets.example/* secrets/
docker compose up --build
```

Check the active database client:

```bash
curl http://localhost:5173/healthz
```

Open:

```text
http://localhost:5173/config.html
```

## Render Deployment Notes

Render does not need a `.env` file. Set environment variables in the Render dashboard.
Render-provided environment variables override anything that might exist in a local `.env` file because `dotenv` does not overwrite existing process environment values by default.

For Render PostgreSQL, use:

```dotenv
DB_CLIENT=postgres
DATABASE_URL=<Render internal database URL>
POSTGRES_SSLMODE=require
```

If you do not use `DATABASE_URL`, set `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` in the dashboard.
Never put actual Render passwords in the repository.

## Pages

- `/` - landing page with module cards and a dynamic security control panel.
- `/sqli.html` - SQL Injection module.
- `/users.html` - role-based access and data masking module.
- `/xss.html` - Cross-Site Scripting module.
- `/audit.html` - database audit logging module.
- `/network.html` - database network exposure module.
- `/config.html` - secure database configuration module, including the Postgres runtime and hardening tab.

## 5-Minute Guided Demo Script

Use Guided Mode on `/` as the click path.
It updates the same six controls used by the live risk score, saves the guided-demo state in the browser, and shows a compact Guided Mode panel inside the relevant modules.

1. **0:00 - Start insecure baseline.** Click `Start insecure demo`. Explain that the score is high because SQL input, role boundaries, output handling, audit evidence, network exposure, and configuration are all weak.
2. **0:40 - SQL injection + prepared statements.** Open `/sqli.html`, run a safe bypass example in `Vulnerable`, then use the Guided Mode panel to switch to `Protected` and continue.
3. **1:25 - XSS + output encoding.** Open `/xss.html`, render a harmless demo payload in `Vulnerable`, then use the Guided Mode panel to switch to protected text output.
4. **2:05 - RBAC + data masking.** Open `/users.html`. Switch roles, briefly disable RBAC if needed, then continue with RBAC and masking enabled.
5. **2:45 - Audit logging.** Open `/audit.html`, trigger failed login, export, and privilege events, then continue with audit logging enabled.
6. **3:30 - Network segmentation.** Open `/network.html`, run the risky connection test, then use the Guided Mode panel to apply the secure network baseline.
7. **4:20 - Secure configuration + executive close.** Open `/config.html`, apply the secure checklist, inspect the Postgres runtime tab, finish on `/`, and read the Executive summary panel.

For a presentation-ready checklist with exact pages, payloads, fallback path, and key messages, see [PRESENTATION.md](PRESENTATION.md).

## Notes

- The app intentionally keeps the Express and SQLite structure simple.
- The SQL Injection demo does not include destructive payloads.
- Data masking is not a replacement for authorization.
- XSS examples are harmless formatting examples so the presentation stays focused on rendering behavior.
- This project demonstrates security concepts visually. Some modules are simulated intentionally to keep the demo safe and easy to run.
- The audit, network, and configuration modules do not perform real database administration or network changes.
- Risk scores are illustrative demo heuristics.
  They use practice-inspired weighting and minimum risk floors for critical missing controls, not a measured or universal standardized calculation.
