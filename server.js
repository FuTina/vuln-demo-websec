// Database Security Playground server.
// Demo/education only: intentionally vulnerable endpoints are marked below.

import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { loadConfigExamples } from "./src/configExamples.js";
import { createDatabase } from "./src/database.js";
import { maskEmail, maskPhone, previewSQL } from "./src/securityDisplay.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const db = createDatabase({ rootDir: __dirname });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Role switch via env for demo purposes: "user" (default) or "admin"
const DEMO_ROLE = process.env.DEMO_ROLE || "user";

// --- Health and configuration metadata ---
app.get("/healthz", async (_req, res) => {
  try {
    const row = await db.get("SELECT 1 as ok");
    res.json({ ok: true, client: db.client, db: Number(row?.ok) === 1 });
  } catch (err) {
    res.status(500).json({ ok: false, client: db.client, error: String(err) });
  }
});

app.get("/api/config-examples", async (_req, res) => {
  try {
    res.json(await loadConfigExamples(__dirname));
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// --- SQLi DEMO ---
// UNSAFE: string concatenation (educational only) – exact match with "="
app.get("/api/sqli/vuln", async (req, res) => {
  const name = (req.query.name ?? "").toString();
  const sql = `SELECT id, name, email FROM users WHERE name = '${name}'`;
  try {
    const rows = await db.all(sql);
    res.json({ mode: "vuln", sql, rows: rows ?? [] });
  } catch (err) {
    res.status(500).json({ error: String(err), sql });
  }
});

// SAFE: parameterized query with preview
app.get("/api/sqli/safe", async (req, res) => {
  const name = (req.query.name ?? "").toString();
  const sql = "SELECT id, name, email FROM users WHERE name = ?";
  const params = [name];

  try {
    const rows = await db.all(sql, params);
    res.json({
      mode: "safe",
      sql: previewSQL(sql, params), // shown in UI
      rows: rows ?? [],
    });
  } catch (err) {
    res.status(500).json({
      error: String(err),
      sql: previewSQL(sql, params),
    });
  }
});

// --- XSS DEMO ---
app.post("/api/xss/vuln", async (req, res) => {
  const { text = "" } = req.body;
  try {
    await db.run("INSERT INTO comments (text) VALUES (?)", [text]);
    res.redirect("/xss.html?vuln=1");
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});
app.get("/api/xss/vuln-list", async (_req, res) => {
  try {
    const rows = await db.all("SELECT id, text FROM comments ORDER BY id DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// Safe flow renders as text (textContent) on the frontend
app.post("/api/xss/safe", async (req, res) => {
  const { text = "" } = req.body;
  try {
    await db.run("INSERT INTO comments (text) VALUES (?)", [text]);
    res.redirect("/xss.html?safe=1");
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});
app.get("/api/xss/safe-list", async (_req, res) => {
  try {
    const rows = await db.all("SELECT id, text FROM comments ORDER BY id DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// --- Users (safe) with masking & role-based view ---
app.get("/api/users/safe", async (_req, res) => {
  try {
    const rows = await db.all("SELECT id, name, email, phone, address FROM users ORDER BY id");
    let out = rows ?? [];
    if (DEMO_ROLE !== "admin") {
      out = out.map((r) => ({
        id: r.id,
        name: r.name,
        email: maskEmail(r.email),
        phone: maskPhone(r.phone),
        address: r.address,
      }));
    }
    res.json({ role: DEMO_ROLE, rows: out });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// --- Start server ---
const PORT = process.env.PORT || 5173;
const HOST = process.env.HOST || "localhost";
try {
  await db.init();
  app.listen(PORT, HOST, () => {
    console.log(`Vuln demo running on http://${HOST}:${PORT}`);
    console.log(`Database client: ${db.client}`);
    console.log("⚠️  Demo/education only. Do NOT expose to the internet for production use.");
  });
} catch (err) {
  console.error("Failed to initialize database:", err);
  process.exit(1);
}

// Graceful shutdown (Render sends SIGTERM on redeploy)
process.once("SIGTERM", async () => {
  console.log("Shutting down...");
  await db.close();
  process.exit(0);
});
