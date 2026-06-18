# Presentation Checklist

## Before The Demo

- Open `http://localhost:5173/`.
- Keep browser zoom at 100%.
- Start with a clean Guided Mode state by clicking `Start insecure demo` on the overview.
- If using Docker/Postgres, confirm:

```bash
curl http://localhost:5173/healthz
```

Expected Docker response:

```json
{"ok":true,"client":"postgres","db":true}
```

## Demo Script

1. **Overview: insecure baseline**
   - Page: `/`
   - Action: open Guided Mode, click `Start insecure demo`
   - Message: database risk rises when prevention, containment, visibility, segmentation, and configuration controls are missing.

2. **SQL Injection**
   - Page: `/sqli.html`
   - Start mode: `Vulnerable`
   - Payload: `alice' --`
   - Action: run login check, then switch to `Protected`
   - Message: prepared statements keep user input as a value, so it cannot change query logic.

3. **XSS**
   - Page: `/xss.html`
   - Start mode: `Vulnerable`
   - Payload: `<strong>Injected HTML</strong>`
   - Alternate payload: `<a href='https://www.bsi.bund.de' target='_blank' rel='noopener'>Open BSI website</a>`
   - Action: render once in vulnerable mode, then switch to `Protected`
   - Message: output encoding or safe rendering keeps untrusted content in the intended display context.

4. **RBAC and Data Masking**
   - Page: `/users.html`
   - Action: compare `Guest`, `App User`, `Analyst`, and `Admin`
   - Optional contrast: briefly disable `RBAC enabled`
   - Finish state: `RBAC enabled` and `Data masking enabled`
   - Message: authorization decides what may be returned; masking only reduces visible sensitivity after access is allowed.

5. **Audit Logging**
   - Page: `/audit.html`
   - Action: trigger failed login, export, and privilege events
   - Finish state: audit logging enabled
   - Message: logs do not prevent the first action, but they create evidence for investigation and response.

6. **Network Segmentation**
   - Page: `/network.html`
   - Action: click `Run connection tests`, send an Internet packet, then continue after segmentation is enabled
   - Message: users should reach the application, not a public database listener.

7. **Secure Configuration and Postgres Runtime**
   - Page: `/config.html`
   - Action: complete the configuration checklist
   - Postgres view: click `Open Postgres runtime`
   - Direct link: `/config.html#postgres-runtime`
   - Message: secure defaults make least privilege, TLS, private networking, secrets handling, and container hardening normal.

8. **Executive Close**
   - Page: `/`
   - Action: return to overview and show the Executive summary panel
   - Message: the final posture is stronger because multiple controls work together.

## Backup Path If Docker Or Postgres Fails

Use SQLite mode:

```bash
npm install
npm start
```

Then open:

```text
http://localhost:5173/
```

What changes:

- `/healthz` should show `client=sqlite`.
- All application modules still work.
- On `/config.html`, the Postgres runtime panel will show `SQLite local mode`.
- Keep the Postgres section as an architecture/configuration discussion rather than a live database proof.

## Safe Payloads

SQL Injection:

```text
alice' --
```

SQL Injection alternate:

```text
' OR '1'='1'--
```

XSS formatting payload:

```html
<strong>Injected HTML</strong>
```

XSS link payload:

```html
<a href='https://www.bsi.bund.de' target='_blank' rel='noopener'>Open BSI website</a>
```

XSS fake download payload:

```html
<a download='security-demo.txt' href='data:text/plain,This%20is%20a%20harmless%20fake%20download%20from%20the%20Database%20Security%20Playground.'>Download fake report</a>
```

## Key Security Messages

- SQL Injection: use prepared statements for every database query.
- XSS: encode output or render untrusted content as text.
- RBAC and masking: authorize first, then minimize and mask returned data.
- Audit: preserve evidence for investigation and response.
- Network: expose the application, not the database.
- Config: make secure defaults the normal deployment path.
