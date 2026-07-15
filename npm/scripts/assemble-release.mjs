import assert from "node:assert/strict";
import { copyFile, cp, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const [, , downloadsDirectory, outputDirectory] = process.argv;
assert(downloadsDirectory && outputDirectory, "usage: assemble-release.mjs <downloads-dir> <output-dir>");

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const npmRoot = path.resolve(scriptDirectory, "..");
const repoRoot = path.resolve(npmRoot, "..");
const platformRoot = path.join(npmRoot, "platforms");
const platforms = (await readdir(platformRoot, { withFileTypes: true }))
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();

await mkdir(outputDirectory, { recursive: true });
await copyFile(path.join(repoRoot, "LICENSE"), path.join(npmRoot, "remora-link", "LICENSE"));

const checksumLines = [];
for (const platform of platforms) {
  const artifactRoot = path.join(downloadsDirectory, `remora-link-${platform}`);
  const packageRoot = path.join(platformRoot, platform);
  await cp(path.join(artifactRoot, "bin"), path.join(packageRoot, "bin"), { recursive: true, force: true });
  await copyFile(path.join(repoRoot, "LICENSE"), path.join(packageRoot, "LICENSE"));
  await copyFile(
    path.join(artifactRoot, `${platform}.spdx.json`),
    path.join(outputDirectory, `${platform}.spdx.json`),
  );
  const files = await readdir(path.join(packageRoot, "bin"));
  for (const file of files.sort()) {
    const bytes = await readFile(path.join(packageRoot, "bin", file));
    const digest = createHash("sha256").update(bytes).digest("hex");
    checksumLines.push(`${digest}  ${platform}/${file}`);
  }
}
await writeFile(
  path.join(outputDirectory, "BINARIES_SHA256SUMS"),
  `${checksumLines.join("\n")}\n`,
);
console.log(`assembled ${platforms.length} native npm packages`);
