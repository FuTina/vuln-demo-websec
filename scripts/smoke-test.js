import { spawn } from "child_process";
import fs from "fs";
import net from "net";
import os from "os";
import path from "path";

const pages = [
  "/",
  "/sqli.html",
  "/users.html",
  "/xss.html",
  "/audit.html",
  "/network.html",
  "/config.html",
];

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function waitForHealth(baseUrl, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/healthz`);
      if (response.ok) return response.json();
      lastError = new Error(`HTTP ${response.status}`);
    } catch (err) {
      lastError = err;
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }

  throw lastError || new Error("Server did not become healthy");
}

async function expectHtml(baseUrl, page) {
  const response = await fetch(`${baseUrl}${page}`);
  if (!response.ok) throw new Error(`${page} returned HTTP ${response.status}`);

  const body = await response.text();
  if (!body.includes("<!doctype html>")) {
    throw new Error(`${page} did not return an HTML document`);
  }
}

async function stopServer(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;

  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 3000)),
  ]);

  if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
}

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dbsec-smoke-"));
const port = await getFreePort();
const baseUrl = `http://127.0.0.1:${port}`;

const child = spawn(process.execPath, ["server.js"], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    DB_CLIENT: "sqlite",
    HOST: "127.0.0.1",
    PORT: String(port),
    SQLITE_FILE: path.join(tmpDir, "data.db"),
  },
  stdio: ["ignore", "pipe", "pipe"],
});

let output = "";
child.stdout.on("data", (chunk) => {
  output += chunk.toString();
});
child.stderr.on("data", (chunk) => {
  output += chunk.toString();
});

try {
  const health = await waitForHealth(baseUrl);
  if (!health.ok || health.client !== "sqlite" || health.db !== true) {
    throw new Error(`Unexpected health response: ${JSON.stringify(health)}`);
  }

  for (const page of pages) {
    await expectHtml(baseUrl, page);
  }

  console.log(`Smoke tests passed on ${baseUrl}`);
} catch (err) {
  console.error(output.trim());
  console.error(`Smoke tests failed: ${err.message}`);
  process.exitCode = 1;
} finally {
  await stopServer(child);
  fs.rmSync(tmpDir, { recursive: true, force: true });
}
