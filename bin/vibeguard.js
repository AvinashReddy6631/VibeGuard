#!/usr/bin/env node

const { spawnSync } = require("child_process");
const path = require("path");

const args = process.argv.slice(2);

if (args.length === 0) {
    console.log(`
VibeGuard Security Scanner

Usage:
  vibeguard scan <project>

Example:
  vibeguard scan .
`);
    process.exit(0);
}

const command = args[0];

if (command !== "scan") {
    console.error(`Unknown command: ${command}`);
    console.log("Use: vibeguard scan <project>");
    process.exit(1);
}

const target = args[1] || ".";

const scanner = path.join(
    __dirname,
    "..",
    "security-check.js"
);

const result = spawnSync(
    process.execPath,
    [scanner, target],
    {
        stdio: "inherit"
    }
);

process.exit(
    result.status ?? 1
);