import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const DOCS = join(ROOT, "docs");

mkdirSync(DOCS, { recursive: true });
const rules = JSON.parse(readFileSync(join(ROOT, "boar_rules.json"), "utf8"));
writeFileSync(
  join(DOCS, "rules.js"),
  `globalThis.BOAR_RULES = ${JSON.stringify(rules)};\n`,
);
console.log(`wrote docs/rules.js (${rules.rules.length} rules)`);
