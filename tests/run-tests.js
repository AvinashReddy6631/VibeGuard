const { spawnSync } = require("child_process");
const path = require("path");

const scanner = path.join(__dirname, "..", "security-check.js");

const tests = [
    {
        name: "Clean project",
        target: path.join(__dirname, "clean"),
        expected: "PASSED"
    },
    {
        name: "Vulnerable project",
        target: path.join(__dirname, "vulnerable"),
        expected: "FAILED"
    }
];

let passed = 0;
let failed = 0;

console.log("\n🧪 VibeGuard Automated Tests\n");

for (const test of tests) {
    console.log(`▶ ${test.name}`);

    const result = spawnSync(
        process.execPath,
        [scanner, test.target],
        {
            encoding: "utf8"
        }
    );

    const output = `${result.stdout || ""}${result.stderr || ""}`;

    if (output.includes(`VibeGuard status: ${test.expected}`)) {
        console.log(`  ✅ ${test.expected}`);
        passed++;
    } else {
        console.log(`  ❌ Expected ${test.expected}`);
        failed++;
    }
}

console.log("\n================================");
console.log(`Tests passed: ${passed}`);
console.log(`Tests failed: ${failed}`);
console.log("================================\n");

process.exit(failed > 0 ? 1 : 0);