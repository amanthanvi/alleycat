import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const npmRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(npmRoot, "..");

async function readJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

const launcher = await readJson(path.join(npmRoot, "remora-link", "package.json"));
const cargo = await readFile(path.join(repoRoot, "crates", "remora-link", "Cargo.toml"), "utf8");
const crateVersion = cargo.match(/^version = "([^"]+)"$/m)?.[1];
assert.equal(launcher.version, crateVersion, "npm and Remora Link crate versions must match");
if (process.env.EXPECTED_VERSION) {
  assert.equal(launcher.version, process.env.EXPECTED_VERSION, "release tag and package versions must match");
}

assert.equal(launcher.dependencies, undefined, "launcher must have zero runtime dependencies");
assert.equal(launcher.devDependencies, undefined, "published launcher must have no dev dependencies");
assert.equal(launcher.scripts, undefined, "published launcher must have no lifecycle scripts");
assert.deepEqual(Object.keys(launcher.bin), ["remora-link"]);
assert.equal(launcher.engines.node, ">=22", "launcher supports the tested Node LTS range only");

const platformRoot = path.join(npmRoot, "platforms");
const directories = (await readdir(platformRoot, { withFileTypes: true }))
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();
assert.deepEqual(directories, ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "win32-x64"]);

const expectedOptionalDependencies = {};
for (const directory of directories) {
  const platformPackage = await readJson(path.join(platformRoot, directory, "package.json"));
  assert.equal(platformPackage.version, launcher.version, `${directory} version must match launcher`);
  assert.equal(platformPackage.dependencies, undefined, `${directory} must have zero dependencies`);
  assert.equal(platformPackage.devDependencies, undefined, `${directory} must have zero dev dependencies`);
  assert.equal(platformPackage.scripts, undefined, `${directory} must have no lifecycle scripts`);
  assert.deepEqual(platformPackage.publishConfig, { access: "public", provenance: true });
  expectedOptionalDependencies[platformPackage.name] = launcher.version;
}
assert.deepEqual(launcher.optionalDependencies, expectedOptionalDependencies, "optional native packages must be exact-version pins");

console.log(`verified Remora Link npm package graph at exact version ${launcher.version}`);
