/* Builds the test fixture at runtime so no secret literal is ever committed to
 * git (which would trip GitHub push protection). Every value is fake/synthetic;
 * the tokens are concatenated so the contiguous secret string only exists in
 * memory / the generated temp file, never in this source file.
 *
 * Usage: node test/make-fixture.js [outDir]   → writes <outDir>/leaky-config.txt
 * Also exports getFixtureText() for the unit tests.
 */
"use strict";
var fs = require("fs");
var path = require("path");

function getFixtureText() {
  var lines = [
    "# Synthetic fixture — every value below is fake, for detection testing only.",
    "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE",
    'aws_secret_access_key = "' + "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY" + '"',
    "GITHUB_TOKEN=" + "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz",
    "STRIPE_KEY=" + "sk_live_" + "0123456789abcdefghijABCDEFG",
    'OPENAI_API_KEY="' + "sk-" + 'abcdefghijklmnopqrstuvwxyz0123"',
    "SLACK_TOKEN=" + "xoxb-" + "1111111111-2222222222-aBcDeFgHiJkLmNoPqRsTuVwX",
    "DATABASE_URL=" + "postgres://admin:" + "hunter2pwd@db.internal.example.com:5432/app",
    'MY_SERVICE_SECRET = "' + "kJ8wQz3pL9xR2mN7vB4tY6cF1sD0aG5h" + '"'
  ];
  return lines.join("\n") + "\n";
}

if (require.main === module) {
  var outDir = process.argv[2] || path.join(__dirname, ".tmp-fixtures");
  fs.mkdirSync(outDir, { recursive: true });
  var outFile = path.join(outDir, "leaky-config.txt");
  fs.writeFileSync(outFile, getFixtureText());
  console.log("Wrote fixture: " + outFile);
}

module.exports = { getFixtureText: getFixtureText };
