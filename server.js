// Minimal demo server for SQLi & XSS (intentionally vulnerable endpoints)
// For demo/education only.

import express from "express";
import sqlite3 from "sqlite3";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

sqlite3.verbose();

// --- Use a file-backed DB for cloud stability (works locally, too)
const DB_FILE = process.env.SQLITE_FILE || path.join(__dirname, "data.db");
// ensure directory exists if SQLITE_FILE points into a subfolder
try {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
} catch (_) {}

const db = new sqlite3.Database(DB_FILE);

// --- Create tables (idempotent) & seed if empty
function initDb() {
  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        name TEXT,
        email TEXT,
        phone TEXT,
        address TEXT
      )
    `);
    db.run(`
      CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY,
        text TEXT
      )
    `);

    // Seed users only if table is empty
    db.get(`SELECT COUNT(*) AS cnt FROM users`, (err, row) => {
      if (err) {
        console.error("DB count error:", err);
        return;
      }
      if ((row?.cnt ?? 0) === 0) {
        const u = db.prepare(
          "INSERT INTO users (name, email, phone, address) VALUES (?, ?, ?, ?)"
        );
        [
          ["Alice", "alice@example.com", "+49 151 000000", "Dresden"],
          ["Bob", "bob@example.com", "+49 160 111111", "Leipzig"],
          ["Charlie", "charlie@example.com", "+49 171 222222", "Berlin"],
        ].forEach(([n, e, p, a]) => u.run(n, e, p, a));
        u.finalize();
        console.log("Seeded users table.");
      }
    });
  });
}
initDb();

// --- Helpers ---
function maskEmail(email) {
  const [user, domain] = String(email).split("@");
  if (!domain) return String(email);
  const head = user.slice(0, 2);
  const masked = head + "*".repeat(Math.max(1, user.length - 2));
  return `${masked}@${domain}`;
}

function maskPhone(phone) {
  // Mask all digits except the last two, ignoring non-digits (+, spaces, dashes)
  return String(phone).replace(/\d(?=(?:\D*\d){2,}\D*$)/g, "•");
}

// Build a readable preview of a parameterized SQL (only for UI display!)
function previewSQL(sql, params = []) {
  let i = 0;
  return sql.replace(/\?/g, () => {
    const v = params[i++];
    const s = String(v ?? "").replace(/'/g, "''"); // naive escape for preview
    return `'${s}'`;
  });
}

// Role switch via env for demo purposes: "user" (default) or "admin"
const DEMO_ROLE = process.env.DEMO_ROLE || "user";

// --- Health (for Render debugging) ---
app.get("/healthz", (_req, res) => {
  db.get("SELECT 1 as ok", (err, row) => {
    if (err) return res.status(500).json({ ok: false, error: String(err) });
    res.json({ ok: true, db: row?.ok === 1 });
  });
});

// --- SQLi DEMO ---
// UNSAFE: string concatenation (educational only) – exact match with "="
app.get("/api/sqli/vuln", (req, res) => {
  const name = (req.query.name ?? "").toString();
  const sql = `SELECT id, name, email FROM users WHERE name = '${name}'`;
  db.all(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: String(err), sql });
    res.json({ mode: "vuln", sql, rows: rows ?? [] });
  });
});

// SAFE: parameterized query with preview
app.get("/api/sqli/safe", (req, res) => {
  const name = (req.query.name ?? "").toString();
  const sql = "SELECT id, name, email FROM users WHERE name = ?";
  const params = [name];

  db.all(sql, params, (err, rows) => {
    if (err) {
      return res.status(500).json({
        error: String(err),
        sql: previewSQL(sql, params),
      });
    }
    res.json({
      mode: "safe",
      sql: previewSQL(sql, params), // shown in UI
      rows: rows ?? [],
    });
  });
});

// --- XSS DEMO ---
app.post("/api/xss/vuln", (req, res) => {
  const { text = "" } = req.body;
  db.run("INSERT INTO comments (text) VALUES (?)", [text], function (err) {
    if (err) return res.status(500).json({ error: String(err) });
    res.redirect("/xss.html?vuln=1");
  });
});
app.get("/api/xss/vuln-list", (_req, res) => {
  db.all("SELECT id, text FROM comments ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: String(err) });
    res.json(rows);
  });
});

// Safe flow renders as text (textContent) on the frontend
app.post("/api/xss/safe", (req, res) => {
  const { text = "" } = req.body;
  db.run("INSERT INTO comments (text) VALUES (?)", [text], function (err) {
    if (err) return res.status(500).json({ error: String(err) });
    res.redirect("/xss.html?safe=1");
  });
});
app.get("/api/xss/safe-list", (_req, res) => {
  db.all("SELECT id, text FROM comments ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: String(err) });
    res.json(rows);
  });
});

// --- Users (safe) with masking & role-based view ---
app.get("/api/users/safe", (_req, res) => {
  db.all("SELECT id, name, email, phone, address FROM users ORDER BY id", (err, rows) => {
    if (err) return res.status(500).json({ error: String(err) });

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
  });
});

// --- Start server ---
const PORT = process.env.PORT || 5173;
app.listen(PORT, () => {
  console.log(`Vuln demo running on http://localhost:${PORT}`);
  console.log("⚠️  Demo/education only. Do NOT expose to the internet for production use.");
});

// Graceful shutdown (Render sends SIGTERM on redeploy)
process.on("SIGTERM", () => {
  console.log("Shutting down...");
  db.close(() => process.exit(0));
});
