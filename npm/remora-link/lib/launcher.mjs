import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  rm,
} from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { spawn } from "node:child_process";

const require = createRequire(import.meta.url);
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const MINIMUM_GLIBC = Object.freeze({ major: 2, minor: 35, display: "2.35" });

export const PLATFORM_SPECS = Object.freeze({
  "darwin-arm64": Object.freeze({
    key: "darwin-arm64",
    packageName: "@remora/link-darwin-arm64",
    binaryRelativePath: "bin/remora-link",
    sidecarRelativePaths: [],
  }),
  "darwin-x64": Object.freeze({
    key: "darwin-x64",
    packageName: "@remora/link-darwin-x64",
    binaryRelativePath: "bin/remora-link",
    sidecarRelativePaths: [],
  }),
  "linux-arm64": Object.freeze({
    key: "linux-arm64-gnu",
    packageName: "@remora/link-linux-arm64-gnu",
    binaryRelativePath: "bin/remora-link",
    sidecarRelativePaths: [],
  }),
  "linux-x64": Object.freeze({
    key: "linux-x64-gnu",
    packageName: "@remora/link-linux-x64-gnu",
    binaryRelativePath: "bin/remora-link",
    sidecarRelativePaths: [],
  }),
  "win32-x64": Object.freeze({
    key: "win32-x64-msvc",
    packageName: "@remora/link-win32-x64-msvc",
    binaryRelativePath: "bin/remora-link.exe",
    sidecarRelativePaths: ["bin/remora-link-startup.exe"],
  }),
});

function currentReport() {
  try {
    return process.report?.getReport?.();
  } catch {
    return undefined;
  }
}

export function resolvePlatformSpec({
  platform = process.platform,
  arch = process.arch,
  report = currentReport(),
} = {}) {
  const key = `${platform}-${arch}`;
  const spec = PLATFORM_SPECS[key];
  if (!spec) {
    throw new Error(
      `unsupported platform ${platform}/${arch}; supported targets: ${Object.keys(PLATFORM_SPECS).join(", ")}`,
    );
  }
  if (platform === "linux") {
    const runtime = report?.header?.glibcVersionRuntime;
    if (!runtime) {
      throw new Error(
        `unsupported Linux libc for ${arch}; Remora Link currently publishes glibc binaries only`,
      );
    }
    const match = /^(\d+)\.(\d+)/.exec(runtime);
    if (!match) {
      throw new Error(`could not parse the host glibc version ${JSON.stringify(runtime)}`);
    }
    const major = Number(match[1]);
    const minor = Number(match[2]);
    if (
      major < MINIMUM_GLIBC.major ||
      (major === MINIMUM_GLIBC.major && minor < MINIMUM_GLIBC.minor)
    ) {
      throw new Error(
        `unsupported glibc ${runtime}; Remora Link requires glibc ${MINIMUM_GLIBC.display} or newer`,
      );
    }
  }
  return spec;
}

function pathApiFor(platform) {
  return platform === "win32" ? path.win32 : path.posix;
}

function requireAbsolute(candidate, label, pathApi) {
  if (!pathApi.isAbsolute(candidate)) {
    throw new Error(`${label} must be an absolute path: ${candidate}`);
  }
  return pathApi.normalize(candidate);
}

export function stableDataRoot({
  platform = process.platform,
  env = process.env,
  home = homedir(),
} = {}) {
  const pathApi = pathApiFor(platform);
  if (env.REMORA_LINK_HOME) {
    return requireAbsolute(env.REMORA_LINK_HOME, "REMORA_LINK_HOME", pathApi);
  }
  const normalizedHome = requireAbsolute(home, "home directory", pathApi);
  if (platform === "darwin") {
    return pathApi.join(normalizedHome, "Library", "Application Support", "Remora Link");
  }
  if (platform === "win32") {
    const local = env.LOCALAPPDATA
      ? requireAbsolute(env.LOCALAPPDATA, "LOCALAPPDATA", pathApi)
      : pathApi.join(normalizedHome, "AppData", "Local");
    return pathApi.join(local, "Remora Link");
  }
  const data = env.XDG_DATA_HOME
    ? requireAbsolute(env.XDG_DATA_HOME, "XDG_DATA_HOME", pathApi)
    : pathApi.join(normalizedHome, ".local", "share");
  return pathApi.join(data, "remora-link");
}

function assertVersion(version) {
  if (!VERSION_PATTERN.test(version)) {
    throw new Error(`invalid Remora Link version ${JSON.stringify(version)}`);
  }
}

export function stableInstallDirectory({ root, version, spec }) {
  assertVersion(version);
  const platform = spec.key.split("-", 1)[0];
  return pathApiFor(platform).join(root, "bin", version, spec.key);
}

async function readJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

export async function readLauncherPackage() {
  const packageFile = new URL("../package.json", import.meta.url);
  return readJson(packageFile);
}

async function insidePackage(packageRoot, relativePath) {
  const candidate = path.resolve(packageRoot, relativePath);
  const prefix = `${path.resolve(packageRoot)}${path.sep}`;
  if (!candidate.startsWith(prefix)) {
    throw new Error(`platform package contains an invalid path: ${relativePath}`);
  }
  const [resolvedRoot, resolvedCandidate] = await Promise.all([
    realpath(packageRoot),
    realpath(candidate),
  ]);
  if (!resolvedCandidate.startsWith(`${resolvedRoot}${path.sep}`)) {
    throw new Error(`platform package path escapes its package root: ${relativePath}`);
  }
  return candidate;
}

export async function resolvePlatformBundle({
  spec,
  version,
  resolvePackageJson = (name) => require.resolve(`${name}/package.json`),
}) {
  assertVersion(version);
  let packageFile;
  try {
    packageFile = resolvePackageJson(spec.packageName);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(
      `native package ${spec.packageName}@${version} is unavailable; retry with \`npx --yes --prefer-online remora-link@${version}\` without omitting optional dependencies (${detail})`,
    );
  }
  const platformPackage = await readJson(packageFile);
  if (platformPackage.version !== version) {
    throw new Error(
      `native package version mismatch: remora-link is ${version}, but ${spec.packageName} is ${platformPackage.version ?? "unknown"}`,
    );
  }
  const packageRoot = path.dirname(packageFile);
  return {
    sourceBinary: await insidePackage(packageRoot, spec.binaryRelativePath),
    sourceSidecars: await Promise.all(
      spec.sidecarRelativePaths.map((entry) => insidePackage(packageRoot, entry)),
    ),
  };
}

async function regularFile(file, label) {
  let stat;
  try {
    stat = await lstat(file);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`${label} is missing at ${file} (${detail})`);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`${label} must be a regular, non-symlink file: ${file}`);
  }
  return stat;
}

export async function sha256File(file) {
  const hash = createHash("sha256");
  await new Promise((resolve, reject) => {
    const stream = createReadStream(file);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", resolve);
  });
  return hash.digest("hex");
}

async function filesMatch(source, destination) {
  try {
    const [sourceStat, destinationStat] = await Promise.all([
      regularFile(source, "packaged binary"),
      lstat(destination),
    ]);
    if (!destinationStat.isFile() || destinationStat.isSymbolicLink()) {
      return false;
    }
    if (sourceStat.size !== destinationStat.size) {
      return false;
    }
    const [sourceHash, destinationHash] = await Promise.all([
      sha256File(source),
      sha256File(destination),
    ]);
    return sourceHash === destinationHash;
  } catch {
    return false;
  }
}

async function installFileAtomically(source, destination) {
  await regularFile(source, "packaged binary");
  if (await filesMatch(source, destination)) {
    await chmod(destination, 0o755);
    return false;
  }

  await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  const temporary = `${destination}.tmp-${process.pid}-${randomUUID()}`;
  try {
    await copyFile(source, temporary);
    await chmod(temporary, 0o755);
    const handle = await open(temporary, "r");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await rename(temporary, destination);
    } catch (error) {
      if (error?.code !== "EEXIST" && error?.code !== "EPERM") {
        throw error;
      }
      if (await filesMatch(source, destination)) {
        return false;
      }
      await rm(destination, { force: true });
      await rename(temporary, destination);
    }
  } finally {
    await rm(temporary, { force: true });
  }

  if (!(await filesMatch(source, destination))) {
    throw new Error(`stable binary verification failed after installing ${destination}`);
  }
  return true;
}

export async function installStableBundle({ bundle, root, version, spec }) {
  const directory = stableInstallDirectory({ root, version, spec });
  await mkdir(directory, { recursive: true, mode: 0o700 });

  for (const sidecar of bundle.sourceSidecars) {
    await installFileAtomically(sidecar, path.join(directory, path.basename(sidecar)));
  }
  const stableBinary = path.join(directory, path.basename(bundle.sourceBinary));
  await installFileAtomically(bundle.sourceBinary, stableBinary);
  return stableBinary;
}

export async function runStableBinary(binary, args, { spawnImpl = spawn } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawnImpl(binary, args, { stdio: "inherit", env: process.env, shell: false });
    const forward = new Map();
    for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
      const handler = () => {
        try {
          child.kill(signal);
        } catch {
          // The child has already exited.
        }
      };
      forward.set(signal, handler);
      process.on(signal, handler);
    }
    const cleanup = () => {
      for (const [signal, handler] of forward) {
        process.off(signal, handler);
      }
    };
    child.once("error", (error) => {
      cleanup();
      reject(error);
    });
    child.once("exit", (code, signal) => {
      cleanup();
      if (signal) {
        const signalExitCodes = { SIGHUP: 129, SIGINT: 130, SIGTERM: 143 };
        resolve(signalExitCodes[signal] ?? 1);
      } else {
        resolve(code ?? 1);
      }
    });
  });
}

export function commandNeedsStableInstall(args) {
  const command = args[0];
  if (command === undefined) {
    return true;
  }

  // Fail safe: new native commands stabilize unless they are proven not to
  // install, refresh, or respawn a daemon. In particular, keep `serve` here
  // only while it remains an explicitly foreground process with no durable
  // service registration.
  const transientSafeCommands = new Set([
    "--help",
    "-h",
    "--version",
    "-V",
    "help",
    "serve",
    "uninstall",
    "status",
    "agents",
    "logs",
    "stop",
    "reload",
  ]);
  return !transientSafeCommands.has(command);
}

export async function launch(args) {
  const launcherPackage = await readLauncherPackage();
  const version = launcherPackage.version;
  assertVersion(version);
  const spec = resolvePlatformSpec();
  const bundle = await resolvePlatformBundle({ spec, version });
  const binary = commandNeedsStableInstall(args)
    ? await installStableBundle({ bundle, root: stableDataRoot(), version, spec })
    : bundle.sourceBinary;
  return runStableBinary(binary, args);
}
