const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const ROOT = path.resolve(process.argv[2] || ".");
const IS_TARGET_SCAN = process.argv.length > 2;
const DEFAULT_CONFIG = {
    projectName: "VibeGuard Project",

    checks: {
        secrets: true,
        environmentFiles: true,
        dependencies: true,
        cors: true,
        securityHeaders: true,
        authentication: true,
        authorization: true,
        codeExecution: true,
        xss: true,
        sqlInjection: true,
        commandInjection: true,
        pathTraversal: true,
        ssrf: true,
        sensitiveConfiguration: true,
        unsafeUserInput: true,
        errorExposure: true,
        supplyChain: true,
        openRedirect: true,
        insecureTransport: true,
        cookieSecurity: true,
        jwtSecurity: true
    },

    ignore: {
        directories: [
            "node_modules",
            ".git",
            ".next",
            "dist",
            "build"
        ],
        files: [
            ".env.example"
        ]
    },

    thresholds: {
        maximumCritical: 0,
        maximumHigh: 0,
        maximumMedium: 5
    }
};
const PROJECT_NAME = path.basename(ROOT);

let config = DEFAULT_CONFIG;

const targetConfigPath = path.join(
    ROOT,
    "security.config.json"
);

if (fs.existsSync(targetConfigPath)) {
    try {
        const targetConfig = JSON.parse(
            fs.readFileSync(targetConfigPath, "utf8")
        );

        config = {
            ...DEFAULT_CONFIG,
            ...targetConfig,

            checks: {
                ...DEFAULT_CONFIG.checks,
                ...(targetConfig.checks || {})
            },

            ignore: {
                ...DEFAULT_CONFIG.ignore,
                ...(targetConfig.ignore || {})
            },

            thresholds: {
                ...DEFAULT_CONFIG.thresholds,
                ...(targetConfig.thresholds || {})
            }
        };

    } catch (error) {
        console.error(
            "❌ Could not read target security.config.json"
        );

        process.exit(1);
    }
}
const findings = [];

const ignoredDirectories = new Set(
    config.ignore?.directories || []
);

const ignoredFiles = new Set([
    ...(config.ignore?.files || []),
    "security-check.js",
    "security.config.json"
]);

const allowedExtensions = new Set([
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".env",
    ".yml",
    ".yaml",
    ".config",
    ".mjs",
    ".cjs",
    ".py",
    ".java",
    ".php",
    ".rb",
    ".go",
    ".cs",
    ".html",
    ".htm"
]);

function addFinding({
    id,
    severity,
    title,
    file,
    line,
    description,
    recommendation
}) {
    const findingKey = [
        id,
        file,
        line
    ].join("|");

    const alreadyExists = findings.some(finding => {
        const existingKey = [
            finding.id,
            finding.file,
            finding.line
        ].join("|");

        return existingKey === findingKey;
    });

    if (alreadyExists) {
        return;
    }

    findings.push({
        id,
        severity,
        title,
        file,
        line,
        description,
        recommendation
    });
}
function shouldIgnore(filePath) {
    const relative = path.relative(ROOT, filePath);
    const parts = relative.split(path.sep);

    for (const part of parts) {
        if (ignoredDirectories.has(part)) {
            return true;
        }
    }

    if (ignoredFiles.has(path.basename(filePath))) {
        return true;
    }

    return false;
}

function getFiles(directory) {
    let results = [];

    let entries;

    try {
        entries = fs.readdirSync(directory, {
            withFileTypes: true
        });
    } catch {
        return results;
    }

    for (const entry of entries) {
        const fullPath = path.join(directory, entry.name);

        if (shouldIgnore(fullPath)) {
            continue;
        }

        if (entry.isDirectory()) {
            results = results.concat(getFiles(fullPath));
        } else {
            results.push(fullPath);
        }
    }

    return results;
}

function getLineNumber(content, index) {
    return content.substring(0, index).split("\n").length;
}

function isTextFile(file) {
    const extension = path.extname(file).toLowerCase();

    return allowedExtensions.has(extension) ||
        path.basename(file).startsWith(".env");
}

function readFileSafe(file) {
    try {
        const stats = fs.statSync(file);

        // Skip files larger than 2 MB
        if (stats.size > 2 * 1024 * 1024) {
            return null;
        }

        return fs.readFileSync(file, "utf8");
    } catch {
        return null;
    }
}

/*
==================================================
1. ENVIRONMENT FILE CHECK
==================================================
*/

function checkEnvironmentFiles(files) {
    if (!config.checks?.environmentFiles) {
        return;
    }

    for (const file of files) {
        const name = path.basename(file);

        if (
            name === ".env" ||
            name === ".env.local" ||
            name === ".env.production" ||
            name === ".env.development"
        ) {
            addFinding({
                id: "VG-ENV-001",
                severity: "HIGH",
                title: "Environment file detected",
                file: path.relative(ROOT, file),
                line: 1,
                description:
                    "A potentially sensitive environment file exists inside the project.",
                recommendation:
                    "Keep secrets outside source control and ensure sensitive .env files are ignored by Git."
            });
        }
    }
}

/*
==================================================
2. SECRET DETECTION
==================================================
*/

function checkSecrets(files) {
    if (!config.checks?.secrets) {
        return;
    }

    const patterns = [
        {
            name: "API key",
            regex: /\b(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN)\s*[:=]\s*["']?[^"'\s]{8,}["']?/i
        },
        {
            name: "JWT secret",
            regex: /\bJWT_SECRET\s*[:=]\s*["']?[^"'\s]{8,}["']?/i
        },
        {
            name: "Database credential",
            regex: /\b(?:DATABASE_URL|MONGODB_URI|DB_PASSWORD)\s*[:=]\s*["']?[^"'\s]{8,}["']?/i
        },
        {
            name: "AWS access key",
            regex: /\bAKIA[0-9A-Z]{16}\b/
        },
        {
            name: "OpenAI-style key",
            regex: /\bsk-[A-Za-z0-9_-]{20,}\b/
        },
        {
            name: "Private key",
            regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/
        }
    ];

    for (const file of files) {
        if (!isTextFile(file)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        for (const pattern of patterns) {
            const match = content.match(pattern.regex);

            if (match) {
                const line = getLineNumber(
                    content,
                    match.index
                );

                addFinding({
                    id: "VG-SECRET-001",
                    severity: "CRITICAL",
                    title: `Potential ${pattern.name} detected`,
                    file: path.relative(ROOT, file),
                    line,
                    description:
                        "A value matching a sensitive credential pattern was detected.",
                    recommendation:
                        "Remove the secret from source code, rotate it if real, and use environment variables or a dedicated secret manager."
                });

                break;
            }
        }
    }
}

/*
==================================================
3. CORS CHECK
==================================================
*/

function checkCors(files) {
    if (!config.checks?.cors) {
        return;
    }

    const patterns = [
        /origin\s*:\s*["']\*["']/i,
        /Access-Control-Allow-Origin["']?\s*[:=]\s*["']\*["']/i,
        /cors\s*\(\s*\{\s*origin\s*:\s*["']\*["']/i
    ];

    for (const file of files) {
        if (!isTextFile(file)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        for (const pattern of patterns) {
            const match = content.match(pattern);

            if (match) {
                addFinding({
                    id: "VG-CORS-001",
                    severity: "MEDIUM",
                    title: "Permissive CORS configuration detected",
                    file: path.relative(ROOT, file),
                    line: getLineNumber(content, match.index),
                    description:
                        "The application appears to allow requests from any origin.",
                    recommendation:
                        "Restrict CORS to trusted application origins."
                });

                break;
            }
        }
    }
}

/*
==================================================
4. SECURITY HEADER CHECK
==================================================
*/

function checkSecurityHeaders(files) {
    if (!config.checks?.securityHeaders) {
        return;
    }

    let headerFound = false;

    const headerPatterns = [
        /Content-Security-Policy/i,
        /Strict-Transport-Security/i,
        /X-Content-Type-Options/i,
        /X-Frame-Options/i,
        /Referrer-Policy/i
    ];

    for (const file of files) {
        if (!isTextFile(file)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        for (const pattern of headerPatterns) {
            if (pattern.test(content)) {
                headerFound = true;
                break;
            }
        }

        if (headerFound) {
            break;
        }
    }

    if (!headerFound) {
        addFinding({
            id: "VG-HEADER-001",
            severity: "LOW",
            title: "Security headers were not detected",
            file: "Project-wide",
            line: "-",
            description:
                "No common HTTP security header configuration was detected.",
            recommendation:
                "Review and configure appropriate security headers for your application."
        });
    }
}

/*
==================================================
5. AUTHENTICATION CHECK
==================================================
*/
/*
==================================================
5. AUTHENTICATION CHECK
==================================================
*/

function checkAuthentication(files) {
    if (!config.checks?.authentication) {
        return;
    }

    const authKeywords = [
        "jsonwebtoken",
        "bcrypt",
        "bcryptjs",
        "passport",
        "session",
        "authenticate",
        "login",
        "signin"
    ];

    let found = false;

    for (const file of files) {
        if (!isTextFile(file)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        const lowerContent = content.toLowerCase();

        if (
            authKeywords.some(keyword =>
                lowerContent.includes(keyword.toLowerCase())
            )
        ) {
            found = true;
            break;
        }
    }

    if (!found) {
        addFinding({
            id: "VG-AUTH-001",
            severity: "INFO",
            title: "Authentication implementation not detected",
            file: "Project-wide",
            line: "-",
            description:
                "No obvious authentication implementation was detected.",
            recommendation:
                "Review whether protected resources require authentication."
        });
    }
}
/*
==================================================
6. DANGEROUS CODE EXECUTION CHECK
==================================================
*/

function checkCodeExecution(files) {
    if (!config.checks?.codeExecution) {
        return;
    }

    const sourceExtensions = new Set([
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs"
    ]);

    const dangerousPatterns = [
        {
            name: "eval()",
            regex: /\beval\s*\(/i
        },
        {
            name: "Function() constructor",
            regex: /\bnew\s+Function\s*\(/i
        }
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        if (!sourceExtensions.has(extension)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        for (const pattern of dangerousPatterns) {
            const match = content.match(pattern.regex);

            if (!match) {
                continue;
            }

            addFinding({
                id: "VG-CODE-EXEC-001",
                severity: "HIGH",
                title: `Dangerous ${pattern.name} detected`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The project contains dynamic code execution that may allow untrusted input to execute as code.",
                recommendation:
                    "Avoid dynamic code execution. Remove eval() or Function() where possible and never pass untrusted input into dynamic execution."
            });

            break;
        }
    }
}
/*
==================================================
7. XSS CHECK
==================================================
*/

function checkXSS(files) {
    if (!config.checks?.xss) {
        return;
    }

    const sourceExtensions = new Set([
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs"
    ]);

    const dangerousPatterns = [
        {
            name: "innerHTML",
            regex: /\.innerHTML\s*=/i
        },
        {
            name: "outerHTML",
            regex: /\.outerHTML\s*=/i
        },
        {
            name: "dangerouslySetInnerHTML",
            regex: /\bdangerouslySetInnerHTML\b/i
        },
        {
            name: "document.write()",
            regex: /\bdocument\.write\s*\(/i
        }
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        if (!sourceExtensions.has(extension)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        for (const pattern of dangerousPatterns) {
            const match = content.match(pattern.regex);

            if (!match) {
                continue;
            }

            addFinding({
                id: "VG-XSS-001",
                severity: "HIGH",
                title: `Potential XSS sink detected: ${pattern.name}`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The project contains a potentially unsafe HTML or DOM injection sink.",
                recommendation:
                    "Avoid inserting untrusted data into HTML or DOM sinks. Prefer safe text APIs, framework escaping, and explicit sanitization where HTML is required."
            });

            break;
        }
    }
}
/*
==================================================
8. SQL INJECTION CHECK
==================================================
*/

function checkSQLInjection(files) {
    if (!config.checks?.sqlInjection) {
        return;
    }

    const sourceExtensions = new Set([
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs"
    ]);

    const dangerousPatterns = [
        {
            name: "SQL query with string concatenation",
            regex: /\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,200}\+\s*[a-zA-Z_$][\w$]*/i
        },
        {
            name: "SQL query with template interpolation",
            regex: /\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,200}\$\{[^}]+\}/i
        }
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        if (!sourceExtensions.has(extension)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        for (const pattern of dangerousPatterns) {
            const match = content.match(pattern.regex);

            if (!match) {
                continue;
            }

            addFinding({
                id: "VG-SQL-001",
                severity: "HIGH",
                title: `Potential SQL injection: ${pattern.name}`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The project contains a SQL query that may incorporate dynamic input without safe parameterization.",
                recommendation:
                    "Use parameterized queries or prepared statements. Never concatenate or directly interpolate untrusted input into SQL queries."
            });

            break;
        }
    }
}
/*
==================================================
9. COMMAND INJECTION CHECK
==================================================
*/

function checkCommandInjection(files) {
    if (!config.checks?.commandInjection) {
        return;
    }

    const sourceExtensions = new Set([
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs"
    ]);

    const dangerousPatterns = [
        {
            name: "child_process.exec()",
            regex: /\b(?:child_process\.)?exec\s*\(/i
        },
        {
            name: "child_process.execSync()",
            regex: /\b(?:child_process\.)?execSync\s*\(/i
        },
        
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        if (!sourceExtensions.has(extension)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        for (const pattern of dangerousPatterns) {
            const match = content.match(pattern.regex);

            if (!match) {
                continue;
            }

            addFinding({
                id: "VG-CMD-001",
                severity: "HIGH",
                title: `Potential command injection: ${pattern.name}`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The project executes operating system commands and may be vulnerable if untrusted input reaches the command.",
                recommendation:
                    "Avoid shell command execution where possible. Prefer safe APIs and never pass untrusted user input directly into system commands."
            });

            break;
        }
    }
}
/*
==================================================
10. PATH TRAVERSAL CHECK
==================================================
*/

function checkPathTraversal(files) {
    if (!config.checks?.pathTraversal) {
        return;
    }

    const sourceExtensions = new Set([
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs"
    ]);

    const dangerousPatterns = [
        {
            name: "path.join() with request input",
            regex: /\bpath\.join\s*\([^)]*(?:req\.|request\.|query\.|params\.)/i
        },
        {
            name: "path.resolve() with request input",
            regex: /\bpath\.resolve\s*\([^)]*(?:req\.|request\.|query\.|params\.)/i
        },
        {
            name: "filesystem operation with request input",
            regex: /\b(?:readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync)\s*\([^)]*(?:req\.|request\.|query\.|params\.)/i
        }
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        if (!sourceExtensions.has(extension)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        for (const pattern of dangerousPatterns) {
            const match = content.match(pattern.regex);

            if (!match) {
                continue;
            }

            addFinding({
                id: "VG-PATH-001",
                severity: "HIGH",
                title: `Potential path traversal: ${pattern.name}`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The project appears to use request-controlled input in a filesystem path, which may allow access to unintended files.",
                recommendation:
                    "Validate and constrain user-controlled paths. Prefer allowlists, normalize paths, and ensure resolved paths remain inside the intended directory."
            });

            break;
        }
    }
}
/*
==================================================
11. SSRF CHECK
==================================================
*/

function checkSSRF(files) {
    if (!config.checks?.ssrf) {
        return;
    }

    const sourceExtensions = new Set([
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs"
    ]);

    const dangerousPatterns = [
        {
            name: "fetch() with request input",
            regex: /\bfetch\s*\(\s*(?:req\.|request\.|req\.(?:query|params|body)\.)/i
        },
        {
            name: "axios request with request input",
            regex: /\baxios\.(?:get|post|put|delete|request)\s*\(\s*(?:req\.|request\.|req\.(?:query|params|body)\.)/i
        },
        {
            name: "http request with request input",
            regex: /\bhttps?\.(?:get|request)\s*\(\s*(?:req\.|request\.|req\.(?:query|params|body)\.)/i
        }
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        if (!sourceExtensions.has(extension)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        for (const pattern of dangerousPatterns) {
            const match = content.match(pattern.regex);

            if (!match) {
                continue;
            }

            addFinding({
                id: "VG-SSRF-001",
                severity: "HIGH",
                title: `Potential SSRF: ${pattern.name}`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The application appears to make an outbound request using user-controlled input, which may allow requests to unintended internal or external resources.",
                recommendation:
                    "Validate and restrict destination URLs. Prefer an allowlist of trusted hosts and block access to internal, loopback, link-local, and cloud metadata addresses."
            });

            break;
        }
    }
}
/*
==================================================
12. SENSITIVE CONFIGURATION CHECK
==================================================
*/

function checkSensitiveConfiguration(files) {
    if (!config.checks?.sensitiveConfiguration) {
        return;
    }

    const sensitiveExtensions = new Set([
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".json",
        ".yml",
        ".yaml",
        ".env",
        ".config",
        ".mjs",
        ".cjs"
    ]);

    const sensitivePatterns = [
        {
            name: "Private key",
            regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i
        },
        {
            name: "Basic authentication credentials",
            regex: /\b(?:username|user)\s*[:=]\s*["'][^"']+["'][\s\S]{0,100}\bpassword\s*[:=]/i
        },
        {
            name: "Database connection string",
            regex: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql):\/\/[^"'\s]+/i
        },
        {
            name: "Cloud access credential",
            regex: /\b(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS)\s*[:=]/i
        }
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        if (!sensitiveExtensions.has(extension)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        for (const pattern of sensitivePatterns) {
            const match = content.match(pattern.regex);

            if (!match) {
                continue;
            }

            addFinding({
                id: "VG-CONFIG-001",
                severity: "HIGH",
                title: `Sensitive configuration detected: ${pattern.name}`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The project appears to contain sensitive credentials or connection information that should not be exposed in source code.",
                recommendation:
                    "Move sensitive values to a secure secret manager or protected environment variables. Never commit real credentials or private keys to source control."
            });

            break;
        }
    }
}
/*
==================================================
13. UNSAFE USER INPUT CHECK
==================================================
*/

function checkUnsafeUserInput(files) {
    if (!config.checks?.unsafeUserInput) {
        return;
    }

    const sourceExtensions = new Set([
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs"
    ]);

    const dangerousPatterns = [
        {
            name: "Request input passed directly to redirect()",
            regex: /\bredirect\s*\(\s*(?:req\.|request\.|req\.(?:query|params|body)\.)/i
        },
        {
            name: "Request input passed directly to response redirect",
            regex: /\bres\.(?:redirect|location)\s*\(\s*(?:req\.|request\.|req\.(?:query|params|body)\.)/i
        },
        {
            name: "Request input passed directly to JSON.parse()",
            regex: /\bJSON\.parse\s*\(\s*(?:req\.|request\.|req\.(?:query|params|body)\.)/i
        }
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        if (!sourceExtensions.has(extension)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        for (const pattern of dangerousPatterns) {
            const match = content.match(pattern.regex);

            if (!match) {
                continue;
            }

            addFinding({
                id: "VG-INPUT-001",
                severity: "MEDIUM",
                title: `Potential unsafe user input: ${pattern.name}`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The application appears to pass request-controlled input directly into a sensitive operation without visible validation.",
                recommendation:
                    "Validate, sanitize, and constrain user-controlled input before using it in redirects, parsing operations, or other security-sensitive functionality."
            });

            break;
        }
    }
}
/*
==================================================
14. ERROR EXPOSURE CHECK
==================================================
*/

function checkErrorExposure(files) {
    if (!config.checks?.errorExposure) {
        return;
    }

    const sourceExtensions = new Set([
        ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"
    ]);

    const dangerousPatterns = [
        {
            name: "Stack trace sent in response",
            regex: /\bres\.(?:send|json)\s*\(\s*(?:err|error)\.(?:stack|message)\b/i
        },
        {
            name: "Error stack printed to response",
            regex: /\bres\.(?:send|json)\s*\([^)]*\.(?:stack|message)\b/i
        }
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        if (!sourceExtensions.has(extension)) continue;

        const content = readFileSafe(file);
        if (!content) continue;

        for (const pattern of dangerousPatterns) {
            const match = content.match(pattern.regex);

            if (!match) continue;

            addFinding({
                id: "VG-ERROR-001",
                severity: "MEDIUM",
                title: `Potential error information exposure: ${pattern.name}`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The application may expose internal error details to clients.",
                recommendation:
                    "Return generic error messages to clients and log detailed errors securely on the server."
            });

            break;
        }
    }
}
/*
==================================================
15. SUPPLY CHAIN CHECK
==================================================
*/

function checkSupplyChain(files) {
    if (!config.checks?.supplyChain) {
        return;
    }

    for (const file of files) {
        if (path.basename(file) !== "package.json") {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        let packageData;

        try {
            packageData = JSON.parse(content);
        } catch {
            continue;
        }

        const scripts = packageData.scripts || {};

        const dangerousScripts = [
            "preinstall",
            "install",
            "postinstall"
        ];

        for (const scriptName of dangerousScripts) {
            if (!scripts[scriptName]) {
                continue;
            }

            addFinding({
                id: "VG-SUPPLY-001",
                severity: "MEDIUM",
                title: `Package install script detected: ${scriptName}`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, scripts[scriptName]),
                description:
                    "The package defines an installation lifecycle script that executes automatically during package installation.",
                recommendation:
                    "Review installation scripts carefully and remove unnecessary lifecycle scripts. Only execute trusted package installation code."
            });

            break;
        }
    }
}
/*
==================================================
16. OPEN REDIRECT CHECK
==================================================
*/

function checkOpenRedirect(files) {
    if (!config.checks?.openRedirect) {
        return;
    }

    const sourceExtensions = new Set([
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs"
    ]);

    const dangerousPatterns = [
        {
            name: "res.redirect() with request input",
            regex: /\bres\.redirect\s*\(\s*(?:req\.|request\.|req\.(?:query|params|body)\.)/i
        },
        {
            name: "redirect() with request input",
            regex: /\bredirect\s*\(\s*(?:req\.|request\.|req\.(?:query|params|body)\.)/i
        }
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        if (!sourceExtensions.has(extension)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        for (const pattern of dangerousPatterns) {
            const match = content.match(pattern.regex);

            if (!match) {
                continue;
            }

            addFinding({
                id: "VG-REDIRECT-001",
                severity: "MEDIUM",
                title: `Potential open redirect: ${pattern.name}`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The application appears to redirect users using request-controlled input.",
                recommendation:
                    "Validate redirect destinations and allow only trusted paths or domains. Avoid redirecting directly to arbitrary user-provided URLs."
            });

            break;
        }
    }
}
/*
==================================================
17. INSECURE HTTP / TLS CHECK
==================================================
*/

function checkInsecureTransport(files) {
    if (!config.checks?.insecureTransport) {
        return;
    }

    const sourceExtensions = new Set([
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".json",
        ".yml",
        ".yaml"
    ]);

    const dangerousPatterns = [
        {
            name: "HTTP URL",
            regex: /https?:\/\/(?!localhost\b|127\.0\.0\.1\b)[^\s"'`]+/i
        },
        {
            name: "TLS certificate validation disabled",
            regex: /\brejectUnauthorized\s*:\s*false\b/i
        }
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        if (!sourceExtensions.has(extension)) continue;

        const content = readFileSafe(file);
        if (!content) continue;

        for (const pattern of dangerousPatterns) {
            const match = content.match(pattern.regex);

            if (!match) continue;

            addFinding({
                id: "VG-TLS-001",
                severity: "MEDIUM",
                title: `Potential insecure transport: ${pattern.name}`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The project appears to use an insecure transport configuration that may expose data or weaken TLS protection.",
                recommendation:
                    "Use HTTPS/TLS for network communication and never disable certificate validation in production."
            });

            break;
        }
    }
}
/*
==================================================
18. COOKIE SECURITY CHECK
==================================================
*/

function checkCookieSecurity(files) {
    if (!config.checks?.cookieSecurity) {
        return;
    }

    const sourceExtensions = new Set([
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs"
    ]);

    const dangerousPatterns = [
        {
            name: "Cookie without HttpOnly",
            regex: /res\.cookie\s*\(\s*[^,]+,\s*[^,)]*(?!\bhttpOnly\s*:\s*true\b)/i
        },
        {
            name: "Cookie with secure disabled",
            regex: /secure\s*:\s*false\b/i
        },
        {
            name: "Cookie with SameSite disabled",
            regex: /sameSite\s*:\s*["']?none["']?/i
        }
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        if (!sourceExtensions.has(extension)) continue;

        const content = readFileSafe(file);
        if (!content) continue;

        for (const pattern of dangerousPatterns) {
            const match = content.match(pattern.regex);

            if (!match) continue;

            addFinding({
                id: "VG-COOKIE-001",
                severity: "MEDIUM",
                title: `Potential cookie security issue: ${pattern.name}`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The application may configure cookies without appropriate security protections.",
                recommendation:
                    "Use HttpOnly, Secure, and an appropriate SameSite policy for sensitive cookies."
            });

            break;
        }
    }
}
/*
==================================================
19. JWT SECURITY CHECK
==================================================
*/

function checkJWTSecurity(files) {
    if (!config.checks?.jwtSecurity) {
        return;
    }

    const sourceExtensions = new Set([
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs"
    ]);

    const dangerousPatterns = [
        {
            name: "JWT algorithm set to none",
            regex: /\balgorithm\s*:\s*["']none["']/i
        },
        {
            name: "JWT verification with disabled signature validation",
            regex: /\b(?:ignoreExpiration|ignoreNotBefore)\s*:\s*true\b/i
        },
        {
            name: "JWT signed with hardcoded secret",
            regex: /\b(?:jwt|jsonwebtoken)\.(?:sign|verify)\s*\([^)]*["'][^"']{8,}["']/i
        }
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        if (!sourceExtensions.has(extension)) continue;

        const content = readFileSafe(file);
        if (!content) continue;

        for (const pattern of dangerousPatterns) {
            const match = content.match(pattern.regex);

            if (!match) continue;

            addFinding({
                id: "VG-JWT-001",
                severity: "HIGH",
                title: `Potential JWT security issue: ${pattern.name}`,
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The project appears to use a potentially unsafe JWT configuration.",
                recommendation:
                    "Use strong secrets stored outside source code, explicitly allow secure algorithms, and validate JWT claims and signatures."
            });

            break;
        }
    }
}
/*
==================================================
6. AUTHORIZATION CHECK
==================================================
*/
function checkAuthorization(files) {
    if (!config.checks?.authorization) {
        return;
    }

    const sourceExtensions = new Set([
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".py",
        ".java",
        ".php",
        ".rb",
        ".go",
        ".cs"
    ]);

    const dangerousPatterns = [
        /\/admin\b/i,
        /\/users\/:id/i,
        /req\.params\.id/i,
        /deleteUser\s*\(/i,
        /isAdmin\s*=/i
    ];

    for (const file of files) {
        const extension = path.extname(file).toLowerCase();

        // Only analyze source-code files.
        // Do not analyze .env, JSON, YAML, etc.
        if (!sourceExtensions.has(extension)) {
            continue;
        }

        const content = readFileSafe(file);

        if (!content) {
            continue;
        }

        for (const pattern of dangerousPatterns) {
            const match = content.match(pattern);

            if (!match) {
                continue;
            }

            addFinding({
                id: "VG-AUTHZ-001",
                severity: "MEDIUM",
                title: "Potential authorization-sensitive code detected",
                file: path.relative(ROOT, file),
                line: getLineNumber(content, match.index),
                description:
                    "The project contains code that may require resource-level authorization.",
                recommendation:
                    "Verify that users can access or modify only resources they are authorized to access."
            });

            break;
        }
    }
}

/*
==================================================
7. DEPENDENCY CHECK
==================================================
*/

function checkDependencies() {
    if (!config.checks?.dependencies) {
        return;
    }

    const packageJson = path.join(ROOT, "package.json");

    if (!fs.existsSync(packageJson)) {
        return;
    }

    console.log("\n🔍 Running npm audit...\n");

    try {
        const result = execSync("npm audit --json", {
            cwd: ROOT,
            encoding: "utf8",
            stdio: ["ignore", "pipe", "pipe"]
        });

        const data = JSON.parse(result);

        const vulnerabilities =
            data.metadata?.vulnerabilities;

        if (vulnerabilities) {
            const total =
                (vulnerabilities.critical || 0) +
                (vulnerabilities.high || 0) +
                (vulnerabilities.moderate || 0) +
                (vulnerabilities.low || 0);

            if (total > 0) {
                addFinding({
                    id: "VG-DEP-001",
                    severity:
                        vulnerabilities.critical > 0
                            ? "CRITICAL"
                            : vulnerabilities.high > 0
                                ? "HIGH"
                                : "MEDIUM",
                    title: "Dependency vulnerabilities detected",
                    file: "package.json",
                    line: "-",
                    description:
                        `${total} dependency vulnerability/vulnerabilities reported by npm audit.`,
                    recommendation:
                        "Review npm audit results and update or replace vulnerable dependencies."
                });
            }
        }
    } catch (error) {
        try {
            const output = error.stdout?.toString();

            if (output) {
                const data = JSON.parse(output);
                const vulnerabilities =
                    data.metadata?.vulnerabilities;

                if (vulnerabilities) {
                    const total =
                        (vulnerabilities.critical || 0) +
                        (vulnerabilities.high || 0) +
                        (vulnerabilities.moderate || 0) +
                        (vulnerabilities.low || 0);

                    if (total > 0) {
                        addFinding({
                            id: "VG-DEP-001",
                            severity:
                                vulnerabilities.critical > 0
                                    ? "CRITICAL"
                                    : vulnerabilities.high > 0
                                        ? "HIGH"
                                        : "MEDIUM",
                            title: "Dependency vulnerabilities detected",
                            file: "package.json",
                            line: "-",
                            description:
                                `${total} dependency vulnerability/vulnerabilities reported by npm audit.`,
                            recommendation:
                                "Run npm audit and review the vulnerable packages."
                        });
                    }
                }
            }
        } catch {
            console.log("⚠️ npm audit could not be completed.");
        }
    }
}

/*
==================================================
SCORING
==================================================
*/
function calculateScore() {
    const counts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0
    };

    for (const finding of findings) {
        counts[finding.severity]++;
    }

    let score = 100;

    score -= counts.CRITICAL * 20;
    score -= counts.HIGH * 12;
    score -= counts.MEDIUM * 6;
    score -= counts.LOW * 2;

    return Math.max(0, Math.min(100, score));
}
/*
==================================================
REPORT
==================================================
*/
function writeJsonReport(files) {
    const counts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0
    };

    for (const finding of findings) {
        counts[finding.severity]++;
    }

    const report = {
        tool: "VibeGuard",
        version: "0.1.0",
        timestamp: new Date().toISOString(),

        project: {
            name: path.basename(ROOT),
            target: ROOT,
            filesScanned: files.length
            
        },
        
    

        summary: counts,

        score: calculateScore(),

        findings: findings
    };

    const outputPath = path.join(
        process.cwd(),
        "vibeguard-report.json"
    );

    fs.writeFileSync(
        outputPath,
        JSON.stringify(report, null, 2),
        "utf8"
    );

    console.log(`\n📄 JSON report: ${outputPath}`);
}

function printReport(files) {
    const counts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0
    };

    for (const finding of findings) {
        counts[finding.severity]++;
    }

    const score = calculateScore();

    console.log("\n");
    console.log("==================================================");
    console.log("                 VIBEGUARD");
    console.log("           SECURITY AUDIT REPORT");
    console.log("==================================================");

    console.log(`\nProject: ${PROJECT_NAME}`);
    console.log(`Target: ${ROOT}`);
    console.log(`Files scanned: ${files.length}`);

    console.log("\n--------------------------------------------------");
    console.log("SUMMARY");
    console.log("--------------------------------------------------");

    console.log(`Critical : ${counts.CRITICAL}`);
    console.log(`High     : ${counts.HIGH}`);
    console.log(`Medium   : ${counts.MEDIUM}`);
    console.log(`Low      : ${counts.LOW}`);
    console.log(`Info     : ${counts.INFO}`);

    console.log("\n--------------------------------------------------");
    console.log("SECURITY SCORE");
    console.log("--------------------------------------------------");

    console.log(`${score} / 100`);

    if (findings.length === 0) {
        console.log("\n✅ No findings detected by the current rules.");
    }

    for (const severity of [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO"
    ]) {
        const matching = findings.filter(
            finding => finding.severity === severity
        );

        if (matching.length === 0) {
            continue;
        }

        console.log("\n--------------------------------------------------");
        console.log(`${severity} FINDINGS`);
        console.log("--------------------------------------------------");

        for (const finding of matching) {
            console.log(`\n[${finding.id}]`);
            console.log(finding.title);
            console.log(`File: ${finding.file}`);
            console.log(`Line: ${finding.line}`);
            console.log(`Description: ${finding.description}`);
            console.log(`Recommendation: ${finding.recommendation}`);
        }
    }

    console.log("\n==================================================");
    console.log("VIBEGUARD SCAN COMPLETE");
    console.log("==================================================\n");
}

/*
==================================================
MAIN
==================================================
*/

console.log("\n🛡️ Starting VibeGuard...\n");
console.log(`Target: ${ROOT}`);

const files = getFiles(ROOT);

console.log(`Files discovered: ${files.length}`);
if (files.length === 0) {
    console.error(
        "\n❌ VibeGuard could not discover any scannable files."
    );

    console.error(
        "Check that the target path exists and contains supported project files."
    );

    process.exitCode = 1;
    process.exit();
}
checkEnvironmentFiles(files);
checkSecrets(files);
checkCors(files);
checkSecurityHeaders(files);
checkAuthentication(files);
checkCodeExecution(files);
checkXSS(files);
checkSQLInjection(files);
checkCommandInjection(files);
checkPathTraversal(files);
checkSSRF(files);
checkSensitiveConfiguration(files);
checkUnsafeUserInput(files);
checkErrorExposure(files);
checkSupplyChain(files);
checkOpenRedirect(files);
checkInsecureTransport(files);
checkCookieSecurity(files);
checkJWTSecurity(files);
checkAuthorization(files);
checkDependencies();
writeJsonReport(files);
printReport(files);
const criticalCount = findings.filter(
    finding => finding.severity === "CRITICAL"
).length;

const highCount = findings.filter(
    finding => finding.severity === "HIGH"
).length;

if (
    criticalCount > 0 ||
    highCount > 0
) {
    console.log(
        "\n❌ VibeGuard status: FAILED"
    );

    process.exitCode = 1;
} else {
    console.log(
        "\n✅ VibeGuard status: PASSED"
    );

    process.exitCode = 0;
}