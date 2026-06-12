/* Minimal zero-dependency test runner for the LeakCheck engine. */
"use strict";
var engine = require("../src/detectors.js");
var makeFixture = require("./make-fixture.js");

var failures = 0;
function assert(cond, msg) {
  if (cond) { console.log("  ok  - " + msg); }
  else { console.log("  FAIL- " + msg); failures++; }
}

var fixture = makeFixture.getFixtureText();
var findings = engine.scan(fixture);
var names = findings.map(function (f) { return f.name; });

console.log("Detected " + findings.length + " findings: " + names.join(", "));

// Each known-format secret in the fixture must be detected.
[
  "AWS Access Key ID",
  "AWS Secret Access Key",
  "GitHub Personal Access Token",
  "Stripe Secret Key (live)",
  "OpenAI API Key",
  "Slack Token",
  "Database URI with credentials"
].forEach(function (n) {
  assert(names.indexOf(n) !== -1, "detects " + n);
});

// Masking must never expose the full secret.
assert(findings.every(function (f) { return /•/.test(f.masked) || f.masked.length <= 8; }),
  "every finding is masked");
assert(findings.every(function (f) { return f.masked.indexOf("EXAMPLEKEY") === -1; }),
  "full secret value never appears in the masked preview");

// Clean text must yield zero findings (no false positives on ordinary prose/code).
var clean = "function add(a, b) {\n  return a + b; // just math, no secrets here\n}\nconst name = 'hello world';\n";
assert(engine.scan(clean).length === 0, "no false positives on clean code");

// Low-entropy placeholder assignments must be filtered out.
assert(engine.scan('password = "changeme"').length === 0, "filters low-entropy placeholder 'changeme'");

if (failures) { console.error("\n" + failures + " test(s) failed."); process.exit(1); }
console.log("\nAll tests passed.");
