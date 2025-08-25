// Minimal demo server for SQLi & XSS (intentionally vulnerable endpoints)
// Run locally only. Do NOT expose to the internet.

import express from "express";
import sqlite3 from "sqlite3";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

sqlite3.verbose();
const db = new sqlite3.Database(":memory:");

// --- Seed in-memory database ---
db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      name TEXT,
      email TEXT,
      phone TEXT,
      address TEXT
    )
  `);
  const u = db.prepare("INSERT INTO users (name, email, phone, address) VALUES (?, ?, ?, ?)");
  [
    ["Alice", "alice@example.com", "+49 151 000000", "Dresden"],
    ["Bob", "bob@example.com", "+49 160 111111", "Leipzig"],
    ["Charlie", "charlie@example.com", "+49 171 222222", "Berlin"]
  ].forEach(([n, e, p, a]) => u.run(n, e, p, a));
  u.finalize();

  db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, text TEXT)");
});

// --- Helpers for masking PII (for non-admin view) ---
function maskEmail(email) {
  const [user, domain] = email.split("@");
  if (!domain) return email;
  const head = user.slice(0, 2);
  const masked = head + "*".repeat(Math.max(1, user.length - 2));
  return `${masked}@${domain}`;
}
// server.js
function maskPhone(phone) {
  // Mask all digits except the last two, ignoring non-digits like +, spaces, dashes
  // "+49 151 000000" -> "+•• ••• ••••00"
  // "(030) 123-456"  -> "(•••) •••-•56"
  return String(phone).replace(/\d(?=(?:\D*\d){2,}\D*$)/g, "•");
}


// Role switch via env for demo purposes: "user" (default) or "admin"
const DEMO_ROLE = process.env.DEMO_ROLE || "user";

// --- SQLi DEMO ---
// INTENTIONALLY VULNERABLE: string concatenation (educational only)
app.get("/api/sqli/vuln", (req, res) => {
  const name = req.query.name ?? "";
  const sql = `SELECT id, name, email FROM users WHERE name = '${name}'`;
  db.all(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: String(err) });
    res.json({ mode: "vuln", sql, rows });
  });
});

// SAFE: parameterized query (mitigation)
app.get("/api/users/safe", (_req, res) => {
  db.all("SELECT id, name, email, phone, address FROM users ORDER BY id", (err, rows) => {
    if (err) return res.status(500).json({ error: String(err) });

    let out = rows;
    if (DEMO_ROLE !== "admin") {
      out = rows.map(r => ({
        id: r.id,
        name: r.name,
        email: maskEmail(r.email),
        phone: maskPhone(r.phone),   // ← hier wird’s angewandt
        address: r.address
      }));
    }
    res.json({ role: DEMO_ROLE, rows: out });
  });
});


// --- XSS DEMO ---
// Vulnerable flow stores raw text and the frontend renders via innerHTML
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
    res.json(rows); // frontend renders with innerHTML (unsafe)
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

    let out = rows;
    if (DEMO_ROLE !== "admin") {
      out = rows.map(r => ({
        id: r.id,
        name: r.name,
        email: maskEmail(r.email),
        phone: maskPhone(r.phone),
        address: r.address // could be reduced to city only, if desired
      }));
    }
    res.json({ role: DEMO_ROLE, rows: out });
  });
});

// --- Start server ---
const PORT = process.env.PORT || 5173;
app.listen(PORT, () => {
  console.log(`Vuln demo running on http://localhost:${PORT}`);
  console.log("⚠️  Run locally/isolated only. Do NOT expose to the internet.");
});
