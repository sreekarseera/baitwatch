// Node harness that runs the extension's JS inference outside Chrome.
//
// extension/engine/model.js expects `chrome.runtime.getURL` + `fetch`; both
// are stubbed here so the exact shipped code — not a copy of it — is what
// gets tested. Reads newline-delimited JSON strings on stdin, writes one
// probability per line to stdout.
//
// With --tokens it writes the token list instead. Probabilities alone cannot
// prove the tokenizers agree: a term the model has no weight for contributes
// nothing to the vector, so two tokenizers that disagree about every
// Devanagari word still return the same number. Comparing the tokens directly
// is what makes a script the vocabulary does not cover testable at all.

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
const { tokenize } = await import(join(here, "..", "extension", "lib", "text.js"));

const tokensOnly = process.argv.includes("--tokens");

const stdin = readFileSync(0, "utf-8");
const lines = stdin.split("\n").filter((l) => l.trim().length > 0);

const out = [];
for (const line of lines) {
  const text = JSON.parse(line);
  out.push(tokensOnly ? JSON.stringify(tokenize(text)) : (await classify(text)).probability.toFixed(10));
}
process.stdout.write(out.join("\n") + "\n");
