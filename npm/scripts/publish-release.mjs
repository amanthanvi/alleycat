import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const npmRoot = path.resolve(scriptDirectory, "..");

async function readJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

export function tarballFilename(name, version) {
  assert.match(name, /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/);
  assert.match(version, /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/);
  const stem = name.startsWith("@") ? name.slice(1).replace("/", "-") : name;
  return `${stem}-${version}.tgz`;
}

export async function sha512Integrity(file) {
  const stat = await lstat(file);
  assert(stat.isFile() && !stat.isSymbolicLink(), `release tarball must be a regular file: ${file}`);
  return `sha512-${createHash("sha512").update(await readFile(file)).digest("base64")}`;
}

export function publicationDecision({ name, version, localIntegrity, publishedIntegrity }) {
  if (publishedIntegrity === undefined) {
    return "publish";
  }
  assert.equal(
    publishedIntegrity,
    localIntegrity,
    `${name}@${version} already exists with different immutable bytes`,
  );
  return "skip";
}

function runNpm(args, { allowNotFound = false } = {}) {
  const result = spawnSync("npm", args, {
    encoding: "utf8",
    env: process.env,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status === 0) {
    return result.stdout.trim();
  }
  if (allowNotFound && /(?:E404|404 Not Found)/.test(`${result.stdout}\n${result.stderr}`)) {
    return undefined;
  }
  const detail = `${result.stdout}\n${result.stderr}`.trim();
  throw new Error(`npm ${args[0]} failed with exit ${result.status ?? "unknown"}: ${detail}`);
}

function remoteIntegrity(name, version) {
  const output = runNpm(["view", `${name}@${version}`, "dist.integrity", "--json"], {
    allowNotFound: true,
  });
  if (output === undefined) {
    return undefined;
  }
  const integrity = JSON.parse(output);
  assert.equal(typeof integrity, "string", `${name}@${version} has no registry dist.integrity`);
  return integrity;
}

async function packageDirectories() {
  const platformRoot = path.join(npmRoot, "platforms");
  const nativeDirectories = (await readdir(platformRoot, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(platformRoot, entry.name))
    .sort();
  return [...nativeDirectories, path.join(npmRoot, "remora-link")];
}

async function publishRelease(tarballDirectory) {
  for (const packageDirectory of await packageDirectories()) {
    const manifest = await readJson(path.join(packageDirectory, "package.json"));
    const tarball = path.resolve(
      tarballDirectory,
      tarballFilename(manifest.name, manifest.version),
    );
    const localIntegrity = await sha512Integrity(tarball);
    const publishedIntegrity = remoteIntegrity(manifest.name, manifest.version);
    const decision = publicationDecision({
      name: manifest.name,
      version: manifest.version,
      localIntegrity,
      publishedIntegrity,
    });
    if (decision === "skip") {
      console.log(`${manifest.name}@${manifest.version} already exists with matching integrity`);
      continue;
    }

    process.stdout.write(`publishing ${manifest.name}@${manifest.version} from ${path.basename(tarball)}\n`);
    const output = runNpm(["publish", tarball, "--access", "public", "--provenance"]);
    if (output) {
      process.stdout.write(`${output}\n`);
    }
  }
}

const invokedDirectly = process.argv[1]
  ? import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
  : false;
if (invokedDirectly) {
  const tarballDirectory = process.argv[2];
  assert(tarballDirectory, "usage: publish-release.mjs <tarball-directory>");
  await publishRelease(tarballDirectory);
}
