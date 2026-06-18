# Roadmap

## Phase 1 - Core Playground

- Implemented: UI/UX improvement.
- Implemented: Better explanations.
- Implemented: Dynamic risk score with concrete missing-control explanation.
- Implemented: Consistent vulnerable/protected badges, colors, and module explanations.

## Phase 2 - Database Security Modules

- Implemented: Add Audit Logging module.
- Implemented: Add Network Exposure module.
- Implemented: Add Secure Configuration module.
- Implemented: Improve SQL Injection, XSS, RBAC/data masking, audit, network, and secure configuration demo flow.
- Implemented: Add executive summary panel for presentation close-out.

## Phase 3 - PostgreSQL Runtime And Presentation Flow

- Implemented: Add Docker Compose with isolated app and PostgreSQL services.
- Implemented: Add real PostgreSQL configuration comparison using example config files.
- Implemented: Add Postgres hardening as a Config page tab.
- Implemented: Add optional PostgreSQL runtime adapter beside SQLite demo mode.
- Implemented: Add TLS-enabled PostgreSQL demo container with internal-only network exposure.
- Implemented: Add container hardening for app and PostgreSQL services.
- Implemented: Add Guided Mode for the presentation path.
- Implemented: Add Start insecure demo, lab reset, and overview return controls.
- Implemented: Persist Guided Mode state across module pages.
- Implemented: Sync Guided Mode completion with direct module controls.
- Implemented: Improve Guided Mode panel layout, progress, and step visibility.
- Implemented: Make the Postgres runtime view easier to find from the Config page.

## Remaining Polish

- Optional: Add browser-level interaction tests for the full Guided Mode path.
- Optional: Add a short screenshot pass before final presentation use.
- Not planned for this presentation: additional modules such as Redis, unless the scope changes.
