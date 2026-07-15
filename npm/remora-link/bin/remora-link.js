#!/usr/bin/env node

import { launch } from "../lib/launcher.mjs";

try {
  const code = await launch(process.argv.slice(2));
  process.exitCode = code;
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`remora-link: ${message}`);
  process.exitCode = 1;
}
