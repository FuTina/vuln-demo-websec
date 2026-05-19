// Minimal demo server for SQLi & XSS (intentionally vulnerable endpoints)
// For demo/education only.

import express from "express";
import sqlite3 from "sqlite3";
import pg from "pg";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const { Pool } = pg;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const CONFIG_EXAMPLES = {
  env: {
    label: "Environment",
    risky: "config-examples/postgres/risky/.env",
    hardened: "config-examples/postgres/hardened/.env.example",
  },
  compose: {
    label: "Docker Compose",
    risky: "config-examples/postgres/risky/docker-compose.yml",
    hardened: "config-examples/postgres/hardened/docker-compose.yml",
  },
  postgres: {
    label: "Database config",
    risky: "config-examples/postgres/risky/postgresql.conf",
    hardened: "config-examples/postgres/hardened/postgresql.conf",
  },
  grants: {
    label: "Database grants",
    risky: "config-examples/postgres/risky/grants.sql",
    hardened: "config-examples/postgres/hardened/grants.sql",
  },
};

sqlite3.verbose();

const DB_CLIENT = process.env.DB_CLIENT || "sqlite";
const DB_FILE = process.env.SQLITE_FILE || path.join(__dirname, "data.db");
let sqliteDb = null;
let pgPool = null;

function readSecret(fileEnv, valueEnv) {
  if (process.env[valueEnv]) return process.env[valueEnv];
  const file = process.env[fileEnv];
  if (!file) return undefined;
  return fs.readFileSync(file, "utf8").trim();
}

function toPgParams(sql) {
  let index = 0;
  return sql.replace(/\?/g, () => `$${++index}`);
}

async function dbAll(sql, params = []) {
  if (DB_CLIENT === "postgres") {
    const result = await pgPool.query(toPgParams(sql), params);
    return result.rows;
  }
  return new Promise((resolve, reject) => {
    sqliteDb.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows ?? [])));
  });
}

async function dbGet(sql, params = []) {
  if (DB_CLIENT === "postgres") {
    const result = await pgPool.query(toPgParams(sql), params);
    return result.rows[0];
  }
  return new Promise((resolve, reject) => {
    sqliteDb.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}

async function dbRun(sql, params = []) {
  if (DB_CLIENT === "postgres") {
    await pgPool.query(toPgParams(sql), params);
    return;
  }
  return new Promise((resolve, reject) => {
    sqliteDb.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function initConnection() {
  if (DB_CLIENT === "postgres") {
    pgPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      host: process.env.POSTGRES_HOST,
      port: Number(process.env.POSTGRES_PORT || 5432),
      database: process.env.POSTGRES_DB || "playground",
      user: process.env.POSTGRES_USER || "app_user",
      password: readSecret("POSTGRES_PASSWORD_FILE", "POSTGRES_PASSWORD"),
      options: "-c search_path=app,public",
    });
    return;
  }

  try {
    const dir = path.dirname(DB_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  } catch (_) {}
  sqliteDb = new sqlite3.Database(DB_FILE);
}

// --- Create tables (idempotent) & seed if empty
async function initDb() {
  const idType = DB_CLIENT === "postgres" ? "SERIAL PRIMARY KEY" : "INTEGER PRIMARY KEY";
  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id ${idType},
      name TEXT,
      email TEXT,
      phone TEXT,
      address TEXT
    )
  `);
  await dbRun(`
    CREATE TABLE IF NOT EXISTS comments (
      id ${idType},
      text TEXT
    )
  `);

  const row = await dbGet("SELECT COUNT(*) AS cnt FROM users");
  if (Number(row?.cnt ?? 0) === 0) {
    await Promise.all([
      dbRun("INSERT INTO users (name, email, phone, address) VALUES (?, ?, ?, ?)", ["Alice", "alice@example.com", "+49 151 000000", "Dresden"]),
      dbRun("INSERT INTO users (name, email, phone, address) VALUES (?, ?, ?, ?)", ["Bob", "bob@example.com", "+49 160 111111", "Leipzig"]),
      dbRun("INSERT INTO users (name, email, phone, address) VALUES (?, ?, ?, ?)", ["Charlie", "charlie@example.com", "+49 171 222222", "Berlin"]),
    ]);
    console.log(`Seeded users table using ${DB_CLIENT}.`);
  }
}

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
  dbGet("SELECT 1 as ok")
    .then((row) => res.json({ ok: true, client: DB_CLIENT, db: Number(row?.ok) === 1 }))
    .catch((err) => res.status(500).json({ ok: false, client: DB_CLIENT, error: String(err) }));
});

app.get("/api/config-examples", async (_req, res) => {
  try {
    const files = await Promise.all(
      Object.entries(CONFIG_EXAMPLES).map(async ([id, item]) => {
        const [risky, hardened] = await Promise.all([
          fs.promises.readFile(path.join(__dirname, item.risky), "utf8"),
          fs.promises.readFile(path.join(__dirname, item.hardened), "utf8"),
        ]);
        return {
          id,
          label: item.label,
          riskyPath: item.risky,
          hardenedPath: item.hardened,
          risky,
          hardened,
        };
      })
    );
    res.json({ engine: "Config examples", files });
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
    const rows = await dbAll(sql);
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
    const rows = await dbAll(sql, params);
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
    await dbRun("INSERT INTO comments (text) VALUES (?)", [text]);
    res.redirect("/xss.html?vuln=1");
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});
app.get("/api/xss/vuln-list", async (_req, res) => {
  try {
    const rows = await dbAll("SELECT id, text FROM comments ORDER BY id DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// Safe flow renders as text (textContent) on the frontend
app.post("/api/xss/safe", async (req, res) => {
  const { text = "" } = req.body;
  try {
    await dbRun("INSERT INTO comments (text) VALUES (?)", [text]);
    res.redirect("/xss.html?safe=1");
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});
app.get("/api/xss/safe-list", async (_req, res) => {
  try {
    const rows = await dbAll("SELECT id, text FROM comments ORDER BY id DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// --- Users (safe) with masking & role-based view ---
app.get("/api/users/safe", async (_req, res) => {
  try {
    const rows = await dbAll("SELECT id, name, email, phone, address FROM users ORDER BY id");
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
initConnection();
try {
  await initDb();
  app.listen(PORT, HOST, () => {
    console.log(`Vuln demo running on http://${HOST}:${PORT}`);
    console.log(`Database client: ${DB_CLIENT}`);
    console.log("⚠️  Demo/education only. Do NOT expose to the internet for production use.");
  });
} catch (err) {
  console.error("Failed to initialize database:", err);
  process.exit(1);
}

// Graceful shutdown (Render sends SIGTERM on redeploy)
process.on("SIGTERM", () => {
  console.log("Shutting down...");
  if (DB_CLIENT === "postgres") {
    pgPool.end().finally(() => process.exit(0));
  } else {
    sqliteDb.close(() => process.exit(0));
  }
});
