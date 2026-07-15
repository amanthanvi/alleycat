import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cp, lstat, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

import {
  PLATFORM_SPECS,
  stableInstallDirectory,
} from "../remora-link/lib/launcher.mjs";

const [, , platform, artifactDirectory] = process.argv;
assert(platform && artifactDirectory, "usage: smoke-launcher.mjs <platform> <artifact-dir>");

const platformSpecKeys = {
  "darwin-arm64": "darwin-arm64",
  "darwin-x64": "darwin-x64",
  "linux-arm64": "linux-arm64",
  "linux-x64": "linux-x64",
  "win32-x64": "win32-x64",
};
const spec = PLATFORM_SPECS[platformSpecKeys[platform]];
assert(spec, `unsupported smoke-test platform ${platform}`);

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const npmRoot = path.resolve(scriptDirectory, "..");
const nativeSource = path.join(npmRoot, "platforms", platform);
const launcherSource = path.join(npmRoot, "remora-link");
const nativeManifest = JSON.parse(await readFile(path.join(nativeSource, "package.json"), "utf8"));
const launcherManifest = JSON.parse(await readFile(path.join(launcherSource, "package.json"), "utf8"));
assert.equal(nativeManifest.name, spec.packageName);
assert.equal(nativeManifest.version, launcherManifest.version);

const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "remora-link-npm-smoke-"));
try {
  const nodeModules = path.join(temporaryRoot, "node_modules");
  const launcherPackage = path.join(nodeModules, "remora-link");
  const [scope, packageName] = nativeManifest.name.split("/");
  const nativePackage = path.join(nodeModules, scope, packageName);
  await mkdir(path.dirname(nativePackage), { recursive: true });
  await cp(launcherSource, launcherPackage, { recursive: true });
  await cp(nativeSource, nativePackage, { recursive: true });
  await cp(path.join(artifactDirectory, "bin"), path.join(nativePackage, "bin"), {
    recursive: true,
    force: true,
  });

  const stableRoot = path.join(temporaryRoot, "stable");
  const launcher = path.join(launcherPackage, "bin", "remora-link.js");
  const launched = spawnSync(process.execPath, [launcher, "install", "--help"], {
    encoding: "utf8",
    env: { ...process.env, REMORA_LINK_HOME: stableRoot },
    shell: false,
  });
  assert.equal(
    launched.status,
    0,
    `packaged launcher failed\nstdout:\n${launched.stdout}\nstderr:\n${launched.stderr}`,
  );

  const stableDirectory = stableInstallDirectory({
    root: stableRoot,
    version: launcherManifest.version,
    spec,
  });
  const expectedFiles = [spec.binaryRelativePath, ...spec.sidecarRelativePaths].map((entry) =>
    path.basename(entry),
  );
  for (const file of expectedFiles) {
    const source = path.join(artifactDirectory, "bin", file);
    const installed = path.join(stableDirectory, file);
    const installedStat = await lstat(installed);
    assert(installedStat.isFile() && !installedStat.isSymbolicLink(), `${installed} is not regular`);
    const [sourceBytes, installedBytes] = await Promise.all([readFile(source), readFile(installed)]);
    const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
    assert.equal(digest(installedBytes), digest(sourceBytes), `${file} stable copy differs`);
  }

  const stableBinary = path.join(stableDirectory, path.basename(spec.binaryRelativePath));
  const nativeSmoke = spawnSync(stableBinary, ["--version"], {
    encoding: "utf8",
    shell: false,
  });
  assert.equal(
    nativeSmoke.status,
    0,
    `stable native binary failed\nstdout:\n${nativeSmoke.stdout}\nstderr:\n${nativeSmoke.stderr}`,
  );
  assert(
    nativeSmoke.stdout.includes(`remora-link ${launcherManifest.version}`),
    `unexpected native version output: ${nativeSmoke.stdout}`,
  );
  console.log(`smoked npm launcher and stable install for ${platform}`);
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
