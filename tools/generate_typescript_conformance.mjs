#!/usr/bin/env node
/** Deterministic B11.1 TypeScript conformance artifact generator. */
import { readFileSync, mkdirSync, writeFileSync, lstatSync } from "node:fs";
import { resolve, join } from "node:path";
import { createHash } from "node:crypto";

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) throw new Error(`${name} is required`);
  return process.argv[index + 1];
}

function bytes(path, label) {
  const target = resolve(path);
  const stat = lstatSync(target);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${label} must be a regular file`);
  return readFileSync(target);
}

const contract = bytes(argument("--contract"), "--contract");
const schema = bytes(argument("--schema-manifest"), "--schema-manifest");
const output = resolve(argument("--output-root"));
const root = join(output, "clients", "typescript", "generated");
mkdirSync(root, { recursive: true });
const digest = (value) => createHash("sha256").update(value).digest("hex");
const text = contract.toString("utf8");
const operations = [...text.matchAll(/operationId:\s*([^\s#]+)/g)].map((match) => match[1]).sort();
const contractDigest = digest(contract);
const schemaDigest = digest(schema);
writeFileSync(join(root, "contract-metadata.ts"), [
  "/** Generated B11.1 TypeScript conformance metadata; do not edit. */",
  `export const GENERATOR = "GENERATOR-TYPESCRIPT-CONFORMANCE" as const;`,
  `export const CONTRACT_SHA256 = "${contractDigest}" as const;`,
  `export const SCHEMA_MANIFEST_SHA256 = "${schemaDigest}" as const;`,
  `export const OPERATIONS = ${JSON.stringify(operations)} as const;`,
  "",
].join("\n"), "utf8");
writeFileSync(join(root, "manifest.json"), JSON.stringify({ generator: "GENERATOR-TYPESCRIPT-CONFORMANCE", protocol: "workspace.v1", contract_sha256: contractDigest, schema_manifest_sha256: schemaDigest, operations }, null, 2) + "\n", "utf8");
