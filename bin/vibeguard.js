#!/usr/bin/env node

const { spawnSync } = require("child_process");
const path = require("path");

const VERSION = "0.1.0";

const args = process.argv.slice(2);

function showHelp() {
    console.log(`
VibeGuard v${VERSION}

Lightweight security baseline and automated security auditor
for AI-generated and vibe-coded web applications.

Usage:
  vibeguard scan <project>
  vibeguard --help
  vibeguard --version

Commands:
  scan <project>    Scan a project for security issues

Options:
  -h, --help        Show this help message
  -v, --version     Show VibeGuard version

Examples:
  vibeguard scan .
  vibeguard scan ./my-project
`);
}

function showVersion() {
    console.log(`VibeGuard v${VERSION}`);
}

if (args.length === 0) {
    showHelp();
    process.exit(0);
}

const command = args[0];

if (
    command === "--help" ||
    command === "-h"
) {
    showHelp();
    process.exit(0);
}

if (
    command === "--version" ||
    command === "-v"
) {
    showVersion();
    process.exit(0);
}

if (command !== "scan") {
    console.error(`Unknown command: ${command}`);
    console.error("Run 'vibeguard --help' for usage information.");
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