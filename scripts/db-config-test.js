import assert from "assert";
import fs from "fs";
import os from "os";
import path from "path";
import { createPostgresPoolConfig, resolvePostgresPassword } from "../src/database.js";

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dbsec-config-"));
const passwordFile = path.join(tmpDir, "postgres-password.txt");
fs.writeFileSync(passwordFile, "from-file\n", "utf8");

try {
  assert.equal(resolvePostgresPassword({ POSTGRES_PASSWORD: "direct" }), "direct");
  assert.equal(resolvePostgresPassword({ POSTGRES_PASSWORD_FILE: passwordFile }), "from-file");
  assert.equal(
    resolvePostgresPassword({ POSTGRES_PASSWORD: "direct", POSTGRES_PASSWORD_FILE: passwordFile }),
    "direct",
  );

  const dockerStyleConfig = createPostgresPoolConfig({
    POSTGRES_HOST: "postgres",
    POSTGRES_PORT: "5432",
    POSTGRES_DB: "playground",
    POSTGRES_USER: "app_user",
    POSTGRES_PASSWORD_FILE: passwordFile,
    POSTGRES_SSLMODE: "require",
  });
  assert.equal(dockerStyleConfig.host, "postgres");
  assert.equal(dockerStyleConfig.database, "playground");
  assert.equal(dockerStyleConfig.user, "app_user");
  assert.equal(dockerStyleConfig.password, "from-file");
  assert.deepEqual(dockerStyleConfig.ssl, { rejectUnauthorized: false });

  const renderStyleConfig = createPostgresPoolConfig({
    DATABASE_URL: "postgresql://render_user:render_pw@render-host:5432/render_db",
    POSTGRES_PASSWORD: "direct-render-password",
    POSTGRES_SSLMODE: "require",
  });
  assert.equal(renderStyleConfig.connectionString, "postgresql://render_user:render_pw@render-host:5432/render_db");
  assert.equal(renderStyleConfig.password, "direct-render-password");
  assert.equal("database" in renderStyleConfig, false);
  assert.deepEqual(renderStyleConfig.ssl, { rejectUnauthorized: false });

  const sqliteDefaultConfig = createPostgresPoolConfig({});
  assert.equal(sqliteDefaultConfig.database, "playground");
  assert.equal(sqliteDefaultConfig.user, "app_user");

  console.log("Database config tests passed");
} finally {
  fs.rmSync(tmpDir, { recursive: true, force: true });
}
