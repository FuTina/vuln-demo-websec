import fs from "fs";
import path from "path";
import pg from "pg";
import sqlite3 from "sqlite3";

sqlite3.verbose();

const { Pool } = pg;

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

export function createDatabase({ rootDir }) {
  const client = process.env.DB_CLIENT || "sqlite";
  const sqliteFile = process.env.SQLITE_FILE || path.join(rootDir, "data.db");
  let sqliteDb = null;
  let pgPool = null;

  async function all(sql, params = []) {
    if (client === "postgres") {
      const result = await pgPool.query(toPgParams(sql), params);
      return result.rows;
    }

    return new Promise((resolve, reject) => {
      sqliteDb.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows ?? [])));
    });
  }

  async function get(sql, params = []) {
    if (client === "postgres") {
      const result = await pgPool.query(toPgParams(sql), params);
      return result.rows[0];
    }

    return new Promise((resolve, reject) => {
      sqliteDb.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
    });
  }

  async function run(sql, params = []) {
    if (client === "postgres") {
      await pgPool.query(toPgParams(sql), params);
      return;
    }

    return new Promise((resolve, reject) => {
      sqliteDb.run(sql, params, function onRun(err) {
        if (err) reject(err);
        else resolve(this);
      });
    });
  }

  function connect() {
    if (client === "postgres") {
      const sslMode = process.env.POSTGRES_SSLMODE || "disable";
      pgPool = new Pool({
        connectionString: process.env.DATABASE_URL,
        host: process.env.POSTGRES_HOST,
        port: Number(process.env.POSTGRES_PORT || 5432),
        database: process.env.POSTGRES_DB || "playground",
        user: process.env.POSTGRES_USER || "app_user",
        password: readSecret("POSTGRES_PASSWORD_FILE", "POSTGRES_PASSWORD"),
        options: "-c search_path=app,public",
        ssl: sslMode === "disable" ? false : { rejectUnauthorized: false },
      });
      return;
    }

    const dir = path.dirname(sqliteFile);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    sqliteDb = new sqlite3.Database(sqliteFile);
  }

  async function initSchema() {
    const idType = client === "postgres" ? "SERIAL PRIMARY KEY" : "INTEGER PRIMARY KEY";

    await run(`
      CREATE TABLE IF NOT EXISTS users (
        id ${idType},
        name TEXT,
        email TEXT,
        phone TEXT,
        address TEXT
      )
    `);

    await run(`
      CREATE TABLE IF NOT EXISTS comments (
        id ${idType},
        text TEXT
      )
    `);

    const row = await get("SELECT COUNT(*) AS cnt FROM users");
    if (Number(row?.cnt ?? 0) === 0) {
      await Promise.all([
        run("INSERT INTO users (name, email, phone, address) VALUES (?, ?, ?, ?)", ["Alice", "alice@example.com", "+49 151 000000", "Dresden"]),
        run("INSERT INTO users (name, email, phone, address) VALUES (?, ?, ?, ?)", ["Bob", "bob@example.com", "+49 160 111111", "Leipzig"]),
        run("INSERT INTO users (name, email, phone, address) VALUES (?, ?, ?, ?)", ["Charlie", "charlie@example.com", "+49 171 222222", "Berlin"]),
      ]);
      console.log(`Seeded users table using ${client}.`);
    }
  }

  async function init() {
    connect();
    await initSchema();
  }

  async function close() {
    if (client === "postgres") {
      await pgPool?.end();
      return;
    }

    await new Promise((resolve) => {
      if (!sqliteDb) {
        resolve();
        return;
      }
      sqliteDb.close(() => resolve());
    });
  }

  return {
    all,
    client,
    close,
    get,
    init,
    run,
  };
}
