import assert from "node:assert/strict";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const [, , platform, buildDirectory, outputDirectory] = process.argv;
assert(platform && buildDirectory && outputDirectory, "usage: stage-binary.mjs <platform> <build-dir> <output-dir>");

const windows = platform === "win32-x64";
const binaries = windows
  ? ["remora-link.exe", "remora-link-startup.exe"]
  : ["remora-link"];
const binDirectory = path.join(outputDirectory, "bin");
await mkdir(binDirectory, { recursive: true });

const checksums = [];
for (const binary of binaries) {
  const source = path.join(buildDirectory, binary);
  const destination = path.join(binDirectory, binary);
  await copyFile(source, destination);
  const digest = createHash("sha256").update(await readFile(destination)).digest("hex");
  checksums.push(`${digest}  bin/${binary}`);
}

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
await copyFile(path.resolve(scriptDirectory, "..", "..", "LICENSE"), path.join(outputDirectory, "LICENSE"));
await writeFile(path.join(outputDirectory, "SHA256SUMS"), `${checksums.join("\n")}\n`);
console.log(`staged ${platform}: ${binaries.join(", ")}`);
