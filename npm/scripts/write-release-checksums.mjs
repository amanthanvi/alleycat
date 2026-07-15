import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

export async function writeReleaseChecksums(tarballDirectory, releaseDirectory) {
  const files = [];
  for (const directory of [tarballDirectory, releaseDirectory]) {
    for (const name of await readdir(directory)) {
      if (name === "SHA256SUMS") {
        continue;
      }
      const file = path.join(directory, name);
      const stat = await lstat(file);
      if (stat.isFile() && !stat.isSymbolicLink()) {
        files.push({ file, name });
      }
    }
  }
  files.sort((left, right) => left.name.localeCompare(right.name));
  assert.equal(
    new Set(files.map(({ name }) => name)).size,
    files.length,
    "release assets must have unique basenames",
  );
  const lines = [];
  for (const { file, name } of files) {
    const digest = createHash("sha256").update(await readFile(file)).digest("hex");
    lines.push(`${digest}  ${name}`);
  }
  assert(lines.length > 0, "no release assets found to checksum");
  await writeFile(path.join(releaseDirectory, "SHA256SUMS"), `${lines.join("\n")}\n`);
  return lines;
}

const invokedDirectly = process.argv[1]
  ? import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
  : false;
if (invokedDirectly) {
  const [, , tarballDirectory, releaseDirectory] = process.argv;
  assert(
    tarballDirectory && releaseDirectory,
    "usage: write-release-checksums.mjs <tarball-directory> <release-directory>",
  );
  const lines = await writeReleaseChecksums(tarballDirectory, releaseDirectory);
  console.log(`checksummed ${lines.length} downloadable release assets`);
}
