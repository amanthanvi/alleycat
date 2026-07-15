import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { EventEmitter } from "node:events";

import {
  commandNeedsStableInstall,
  installStableBundle,
  resolvePlatformBundle,
  resolvePlatformSpec,
  runStableBinary,
  stableDataRoot,
  stableInstallDirectory,
} from "../remora-link/lib/launcher.mjs";
import {
  publicationDecision,
  sha512Integrity,
  tarballFilename,
} from "../scripts/publish-release.mjs";
import { writeReleaseChecksums } from "../scripts/write-release-checksums.mjs";

const tempRoots = [];

async function tempRoot() {
  const root = await mkdtemp(path.join(os.tmpdir(), "remora-link-launcher-"));
  tempRoots.push(root);
  return root;
}

test.after(async () => {
  await Promise.all(tempRoots.map((root) => rm(root, { recursive: true, force: true })));
});

test("resolves every supported platform to its exact native package", () => {
  const glibc = { header: { glibcVersionRuntime: "2.39" } };
  assert.equal(resolvePlatformSpec({ platform: "darwin", arch: "arm64" }).packageName, "@remora/link-darwin-arm64");
  assert.equal(resolvePlatformSpec({ platform: "darwin", arch: "x64" }).packageName, "@remora/link-darwin-x64");
  assert.equal(resolvePlatformSpec({ platform: "linux", arch: "arm64", report: glibc }).packageName, "@remora/link-linux-arm64-gnu");
  assert.equal(resolvePlatformSpec({ platform: "linux", arch: "x64", report: glibc }).packageName, "@remora/link-linux-x64-gnu");
  assert.equal(resolvePlatformSpec({ platform: "win32", arch: "x64" }).packageName, "@remora/link-win32-x64-msvc");
});

test("stabilizes daemon-capable and unknown commands while exempting proven transient commands", () => {
  for (const args of [
    [],
    ["install"],
    ["upgrade"],
    ["restart"],
    ["pair"],
    ["rotate"],
    ["devices", "list"],
    ["devices", "revoke", "device-1"],
    ["probe"],
    ["probe", "--node-id", "remote-node"],
    ["future-command"],
  ]) {
    assert.equal(commandNeedsStableInstall(args), true, `${args[0] ?? "onboarding"} must stabilize`);
  }
  for (const args of [
    ["status"],
    ["agents", "list"],
    ["logs"],
    ["serve"],
    ["uninstall"],
    ["stop"],
    ["reload"],
    ["--help"],
    ["-h"],
    ["--version"],
    ["-V"],
    ["help", "pair"],
  ]) {
    assert.equal(commandNeedsStableInstall(args), false, `${args[0]} must remain non-installing`);
  }
});

test("rejects unsupported architectures and musl instead of running a wrong binary", () => {
  assert.throws(
    () => resolvePlatformSpec({ platform: "darwin", arch: "ia32" }),
    /unsupported platform darwin\/ia32/,
  );
  assert.throws(
    () => resolvePlatformSpec({ platform: "linux", arch: "x64", report: { header: {} } }),
    /glibc binaries only/,
  );
  assert.throws(
    () =>
      resolvePlatformSpec({
        platform: "linux",
        arch: "x64",
        report: { header: { glibcVersionRuntime: "2.34" } },
      }),
    /requires glibc 2\.35 or newer/,
  );
  assert.equal(
    resolvePlatformSpec({
      platform: "linux",
      arch: "x64",
      report: { header: { glibcVersionRuntime: "2.35" } },
    }).packageName,
    "@remora/link-linux-x64-gnu",
  );
});

test("derives stable per-user roots using native platform conventions", () => {
  assert.equal(
    stableDataRoot({ platform: "darwin", env: {}, home: "/Users/remora" }),
    "/Users/remora/Library/Application Support/Remora Link",
  );
  assert.equal(
    stableDataRoot({ platform: "linux", env: { XDG_DATA_HOME: "/data/remora" }, home: "/home/remora" }),
    "/data/remora/remora-link",
  );
  assert.equal(
    stableDataRoot({ platform: "win32", env: { LOCALAPPDATA: "C:\\Users\\remora\\AppData\\Local" }, home: "C:\\Users\\remora" }),
    "C:\\Users\\remora\\AppData\\Local\\Remora Link",
  );
  assert.throws(
    () => stableDataRoot({ platform: "linux", env: { REMORA_LINK_HOME: "relative" }, home: "/home/remora" }),
    /must be an absolute path/,
  );
});

test("stable install paths include the exact version and target", () => {
  const linuxSpec = resolvePlatformSpec({
    platform: "linux",
    arch: "arm64",
    report: { header: { glibcVersionRuntime: "2.39" } },
  });
  assert.equal(
    stableInstallDirectory({
      root: "/data/remora-link",
      version: "1.2.3",
      spec: linuxSpec,
    }),
    "/data/remora-link/bin/1.2.3/linux-arm64-gnu",
  );
  const windowsSpec = resolvePlatformSpec({ platform: "win32", arch: "x64" });
  assert.equal(
    stableInstallDirectory({
      root: "C:\\Remora Link",
      version: "1.2.3-beta.1",
      spec: windowsSpec,
    }),
    "C:\\Remora Link\\bin\\1.2.3-beta.1\\win32-x64-msvc",
  );
});

test("atomically installs, reuses, and repairs a stable binary bundle", async () => {
  const root = await tempRoot();
  const packageBin = path.join(root, "package", "bin");
  await mkdir(packageBin, { recursive: true });
  const sourceBinary = path.join(packageBin, "remora-link");
  const sourceSidecar = path.join(packageBin, "remora-link-helper");
  await writeFile(sourceBinary, "main-v1");
  await writeFile(sourceSidecar, "helper-v1");
  await chmod(sourceBinary, 0o755);
  await chmod(sourceSidecar, 0o755);

  const spec = { key: "darwin-arm64" };
  const bundle = { sourceBinary, sourceSidecars: [sourceSidecar] };
  const stableRoot = path.join(root, "stable");
  const installed = await installStableBundle({ bundle, root: stableRoot, version: "1.0.0", spec });
  const firstStat = await lstat(installed);
  assert.equal(await readFile(installed, "utf8"), "main-v1");
  assert.equal(await readFile(path.join(path.dirname(installed), "remora-link-helper"), "utf8"), "helper-v1");
  assert.notEqual(firstStat.mode & 0o111, 0);

  const installedAgain = await installStableBundle({ bundle, root: stableRoot, version: "1.0.0", spec });
  const secondStat = await lstat(installedAgain);
  assert.equal(installedAgain, installed);
  assert.equal(secondStat.ino, firstStat.ino, "identical binaries should not be replaced");

  await writeFile(installed, "tampered");
  await installStableBundle({ bundle, root: stableRoot, version: "1.0.0", spec });
  assert.equal(await readFile(installed, "utf8"), "main-v1");
});

test("refuses a symlinked packaged binary", async (t) => {
  if (process.platform === "win32") {
    t.skip("creating symlinks is privilege-dependent on Windows");
    return;
  }
  const root = await tempRoot();
  const target = path.join(root, "real-binary");
  const source = path.join(root, "package-binary");
  await writeFile(target, "binary");
  await symlink(target, source);
  await assert.rejects(
    installStableBundle({
      bundle: { sourceBinary: source, sourceSidecars: [] },
      root: path.join(root, "stable"),
      version: "1.0.0",
      spec: { key: "darwin-arm64" },
    }),
    /regular, non-symlink file/,
  );
});

test("requires the native package version to match the launcher exactly", async () => {
  const root = await tempRoot();
  const packageRoot = path.join(root, "native");
  await mkdir(path.join(packageRoot, "bin"), { recursive: true });
  await writeFile(path.join(packageRoot, "bin", "remora-link"), "native");
  const packageFile = path.join(packageRoot, "package.json");
  await writeFile(packageFile, JSON.stringify({ name: "@remora/link-darwin-arm64", version: "1.0.0" }));
  const spec = {
    key: "darwin-arm64",
    packageName: "@remora/link-darwin-arm64",
    binaryRelativePath: "bin/remora-link",
    sidecarRelativePaths: [],
  };
  const resolved = await resolvePlatformBundle({ spec, version: "1.0.0", resolvePackageJson: () => packageFile });
  assert.equal(resolved.sourceBinary, path.join(packageRoot, "bin", "remora-link"));
  await assert.rejects(
    resolvePlatformBundle({ spec, version: "1.0.1", resolvePackageJson: () => packageFile }),
    /native package version mismatch/,
  );
});

test("rejects a native package path whose real target escapes the package", async (t) => {
  if (process.platform === "win32") {
    t.skip("creating symlinks is privilege-dependent on Windows");
    return;
  }
  const root = await tempRoot();
  const packageRoot = path.join(root, "native");
  await mkdir(path.join(packageRoot, "bin"), { recursive: true });
  const outside = path.join(root, "outside-remora-link");
  await writeFile(outside, "native");
  await symlink(outside, path.join(packageRoot, "bin", "remora-link"));
  const packageFile = path.join(packageRoot, "package.json");
  await writeFile(packageFile, JSON.stringify({ name: "@remora/link-darwin-arm64", version: "1.0.0" }));
  await assert.rejects(
    resolvePlatformBundle({
      spec: {
        key: "darwin-arm64",
        packageName: "@remora/link-darwin-arm64",
        binaryRelativePath: "bin/remora-link",
        sidecarRelativePaths: [],
      },
      version: "1.0.0",
      resolvePackageJson: () => packageFile,
    }),
    /escapes its package root/,
  );
});

test("executes the native binary with literal argv and no shell", async () => {
  let invocation;
  const exitCode = await runStableBinary("/stable/remora-link", ["probe", "$(touch nope)"], {
    spawnImpl(binary, args, options) {
      invocation = { binary, args, options };
      const child = new EventEmitter();
      child.kill = () => true;
      queueMicrotask(() => child.emit("exit", 7, null));
      return child;
    },
  });
  assert.equal(exitCode, 7);
  assert.equal(invocation.binary, "/stable/remora-link");
  assert.deepEqual(invocation.args, ["probe", "$(touch nope)"]);
  assert.equal(invocation.options.shell, false);
  assert.equal(invocation.options.stdio, "inherit");
});

test("derives npm tarball names and registry-compatible sha512 integrity", async () => {
  assert.equal(tarballFilename("remora-link", "1.2.3"), "remora-link-1.2.3.tgz");
  assert.equal(
    tarballFilename("@remora/link-linux-x64-gnu", "1.2.3-beta.1"),
    "remora-link-linux-x64-gnu-1.2.3-beta.1.tgz",
  );
  const root = await tempRoot();
  const tarball = path.join(root, "package.tgz");
  await writeFile(tarball, "immutable npm bytes");
  assert.equal(
    await sha512Integrity(tarball),
    "sha512-Jnkbbawvz0wR/Ig9e9NLi5z5Vgt+4WIwKlhejJ1r6LcX9ir8n/tZKo2+NwxDZIRzzNtJs6hrAVd+6aZ1yUbI9Q==",
  );
  assert.equal(
    publicationDecision({
      name: "remora-link",
      version: "1.2.3",
      localIntegrity: "sha512-same",
      publishedIntegrity: undefined,
    }),
    "publish",
  );
  assert.equal(
    publicationDecision({
      name: "remora-link",
      version: "1.2.3",
      localIntegrity: "sha512-same",
      publishedIntegrity: "sha512-same",
    }),
    "skip",
  );
  assert.throws(
    () =>
      publicationDecision({
        name: "remora-link",
        version: "1.2.3",
        localIntegrity: "sha512-new",
        publishedIntegrity: "sha512-existing",
      }),
    /different immutable bytes/,
  );
});

test("writes checksums for the actual downloadable release assets", async () => {
  const root = await tempRoot();
  const tarballs = path.join(root, "npm");
  const release = path.join(root, "release");
  await mkdir(tarballs, { recursive: true });
  await mkdir(release, { recursive: true });
  await writeFile(path.join(tarballs, "remora-link-1.2.3.tgz"), "tarball");
  await writeFile(path.join(release, "linux-x64.spdx.json"), "sbom");
  await writeFile(path.join(release, "BINARIES_SHA256SUMS"), "inner checksums");
  const lines = await writeReleaseChecksums(tarballs, release);
  assert.deepEqual(
    lines.map((line) => line.split("  ")[1]),
    ["BINARIES_SHA256SUMS", "linux-x64.spdx.json", "remora-link-1.2.3.tgz"],
  );
  assert.equal(await readFile(path.join(release, "SHA256SUMS"), "utf8"), `${lines.join("\n")}\n`);
});
