# Database Security Playground

An intentionally vulnerable Express and SQLite demo for a database security presentation. It shows how common application choices affect data exposure and database risk through safe local simulations.

## What This Demonstrates

- SQL Injection: vulnerable string concatenation compared with safe parameterized queries.
- Cross-Site Scripting: unsafe `innerHTML` compared with safe `textContent`.
- Role-based data masking: guest, app user, analyst, and admin views with RBAC and masking toggles.
- Audit logging: fake security events that build an investigation timeline.
- Network exposure: public database port compared with internal-only access.
- Secure configuration: risky defaults compared with hardened database settings.
- Presentation framing: a dynamic risk score and clickable security controls.

## Local Warning

This project contains intentionally vulnerable endpoints and simulated security scenarios. Use it only locally or in an isolated lab environment. Do not expose it to the internet or use it as a production pattern.

## Run Locally

```bash
npm install
npm start
```

Open:

```text
http://localhost:5173
```

## Docker Database Mode

The app still runs with SQLite by default for the fastest local demo path. Docker Compose runs the same app with a connected PostgreSQL database service:

- `docker-compose.yml` - isolated app and PostgreSQL services on separate networks.
- `config-examples/postgres/risky` - intentionally risky example files.
- `config-examples/postgres/hardened` - hardened reference files used by the Postgres tab on `/config.html`.
- `secrets.example` - example secret files; copy these to `secrets/` before running Compose.

The PostgreSQL container uses a self-signed demo certificate and `pg_hba.conf` rejects non-TLS TCP connections. This is suitable for the local security demo, not a production certificate pattern.
The Compose file also applies demo-friendly container hardening: no published Postgres port, internal backend network, dropped Linux capabilities, read-only filesystems, tmpfs runtime directories, `no-new-privileges`, and process limits.

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

## Pages

- `/` - landing page with module cards and a dynamic security control panel.
- `/sqli.html` - SQL Injection module.
- `/users.html` - role-based access and data masking module.
- `/xss.html` - Cross-Site Scripting module.
- `/audit.html` - database audit logging module.
- `/network.html` - database network exposure module.
- `/config.html` - secure database configuration module, including the Postgres runtime and hardening tab.

## Suggested Demo Flow

1. Start on the landing page.
2. Toggle controls and observe the dynamic risk score.
3. Open the SQL Injection module.
4. Test a payload in vulnerable and protected mode.
5. Open the RBAC module and switch roles.
6. Open the Network module and run connection tests.
7. Finish with the Secure Configuration checklist.

## Suggested Presentation Narrative

1. Start with the risk overview: the score is low while the baseline controls are enabled, then rises sharply when critical controls such as network segmentation or secure configuration are removed.
2. Demonstrate SQL Injection: string concatenation lets input change query logic.
3. Show the safe parameterized query: the SQL structure stays fixed and input becomes a value.
4. Show role-based masking: sensitive data should be authorized first and minimized before rendering.
5. Explain audit logging: investigations need protected, centralized records.
6. Explain network segmentation: the web app should be reachable, not the database.
7. Explain secure configuration: least privilege, TLS, backups, monitoring, and secrets management reduce avoidable risk.

## Notes

- The app intentionally keeps the Express and SQLite structure simple.
- The SQL Injection demo does not include destructive payloads.
- Data masking is not a replacement for authorization.
- XSS examples are harmless formatting examples so the presentation stays focused on rendering behavior.
- This project demonstrates security concepts visually. Some modules are simulated intentionally to keep the demo safe and easy to run.
- The audit, network, and configuration modules do not perform real database administration or network changes.
- Risk scores are illustrative demo heuristics. They use practice-inspired weighting and minimum risk floors for critical missing controls, not a measured or universal standardized calculation.
