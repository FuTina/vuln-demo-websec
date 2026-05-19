import fs from "fs";
import path from "path";

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
  hba: {
    label: "Connection policy",
    risky: "config-examples/postgres/risky/pg_hba.conf",
    hardened: "config-examples/postgres/hardened/pg_hba.conf",
  },
};

export async function loadConfigExamples(rootDir) {
  const files = await Promise.all(
    Object.entries(CONFIG_EXAMPLES).map(async ([id, item]) => {
      const [risky, hardened] = await Promise.all([
        fs.promises.readFile(path.join(rootDir, item.risky), "utf8"),
        fs.promises.readFile(path.join(rootDir, item.hardened), "utf8"),
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

  return {
    engine: "Config examples",
    files,
  };
}
