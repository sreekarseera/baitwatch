// Node harness that runs the extension's JS inference outside Chrome.
//
// extension/engine/model.js expects `chrome.runtime.getURL` + `fetch`; both
// are stubbed here so the exact shipped code — not a copy of it — is what
// gets tested. Reads newline-delimited JSON strings on stdin, writes one
// probability per line to stdout.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const weightsPath = join(here, "..", "extension", "engine", "model-weights.json");

globalThis.chrome = { runtime: { getURL: () => weightsPath } };
globalThis.fetch = async (path) => ({
  ok: true,
  json: async () => JSON.parse(readFileSync(path, "utf-8")),
});

const { classify } = await import(join(here, "..", "extension", "engine", "model.js"));

const stdin = readFileSync(0, "utf-8");
const lines = stdin.split("\n").filter((l) => l.trim().length > 0);

const out = [];
for (const line of lines) {
  const { probability } = await classify(JSON.parse(line));
  out.push(probability.toFixed(10));
}
process.stdout.write(out.join("\n") + "\n");
