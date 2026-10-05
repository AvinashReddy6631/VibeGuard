const { spawnSync } = require("child_process");
const path = require("path");

const scanner = path.join(__dirname, "..", "security-check.js");

const tests = [
    {
        name: "Clean project",
        target: path.join(__dirname, "clean"),
        expectedStatus: "PASSED",
        expectedFindings: []
    },
    {
        name: "Vulnerable project",
        target: path.join(__dirname, "vulnerable"),
        expectedStatus: "FAILED",
        expectedFindings: [
            "VG-CODE-EXEC-001",
            "VG-SQL-001",
            "VG-CMD-001"
        ]
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

    let testPassed = true;

    if (!output.includes(`VibeGuard status: ${test.expectedStatus}`)) {
        console.log(`  ❌ Status mismatch`);
        testPassed = false;
    }

    for (const finding of test.expectedFindings) {
        if (!output.includes(`[${finding}]`)) {
            console.log(`  ❌ Missing finding: ${finding}`);
            testPassed = false;
        }
    }

    if (testPassed) {
        console.log("  ✅ PASSED");
        passed++;
    } else {
        failed++;
    }
}

console.log("\n================================");
console.log(`Tests passed: ${passed}`);
console.log(`Tests failed: ${failed}`);
console.log("================================\n");

process.exit(failed > 0 ? 1 : 0);