/* LeakCheck GitHub Action — entry point.
 *
 * Walks the workspace (or the paths given), runs the LeakCheck detection engine
 * over every text file, and reports any hard-coded secrets as GitHub
 * annotations + a job summary. Zero dependencies: talks to the runner purely
 * through Actions workflow commands on stdout and the $GITHUB_* files.
 *
 * Secret values are never printed — only masked previews — because Action logs
 * are public on open-source repositories.
 */
"use strict";

var fs = require("fs");
var path = require("path");
var engine = require("./detectors.js");

var LEAKCHECK_URL = "https://labs.copperbaytech.com/leakcheck/";
var AGENCY_URL = "https://copperbaytech.com";

/* ---- inputs ------------------------------------------------------- */
function input(name, fallback) {
  // GitHub exposes inputs as INPUT_<NAME> (uppercased, spaces→_). Hyphens are
  // kept, so read both the hyphen and underscore forms to be safe.
  var upper = name.toUpperCase();
  var v = process.env["INPUT_" + upper];
  if (v == null) v = process.env["INPUT_" + upper.replace(/-/g, "_")];
  if (v == null || v === "") return fallback;
  return v;
}

var SCAN_PATHS = input("paths", ".").split(/[\n,]+/).map(function (s) { return s.trim(); }).filter(Boolean);
var FAIL_ON = input("fail-on", "high").toLowerCase().trim();          // critical|high|medium|low|none
var MAX_BYTES = parseInt(input("max-file-kb", "1024"), 10) * 1024;     // skip files larger than this
var EXTRA_IGNORE = input("ignore", "").split(/[\n,]+/).map(function (s) { return s.trim(); }).filter(Boolean);

var SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

/* ---- traversal ---------------------------------------------------- */
var IGNORE_DIRS = {
  ".git": 1, "node_modules": 1, "vendor": 1, "dist": 1, "build": 1,
  ".next": 1, ".nuxt": 1, "out": 1, "coverage": 1, ".turbo": 1,
  ".cache": 1, "__pycache__": 1, ".venv": 1, "venv": 1, ".terraform": 1
};
// Files that are noisy or huge and rarely the source of a real leak we should fail on.
var IGNORE_FILES = {
  "package-lock.json": 1, "yarn.lock": 1, "pnpm-lock.yaml": 1,
  "composer.lock": 1, "Gemfile.lock": 1, "poetry.lock": 1, "cargo.lock": 1
};
var BINARY_EXT = /\.(png|jpe?g|gif|webp|ico|bmp|tiff?|svg|pdf|zip|gz|tgz|bz2|xz|7z|rar|mp[34]|mov|avi|mkv|webm|wav|flac|ogg|woff2?|ttf|otf|eot|exe|dll|so|dylib|class|jar|wasm|bin|dat|db|sqlite3?|node|psd|ai|sketch)$/i;

function matchesIgnore(rel) {
  var norm = rel.split(path.sep).join("/"); // forward slashes so globs are cross-platform
  for (var i = 0; i < EXTRA_IGNORE.length; i++) {
    var g = EXTRA_IGNORE[i];
    if (!g) continue;
    // crude glob: '*' → '.*'. Substring match against the (normalized) relative path.
    var re = new RegExp(g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*"));
    if (re.test(norm)) return true;
  }
  return false;
}

function looksBinary(buf) {
  var n = Math.min(buf.length, 8000);
  for (var i = 0; i < n; i++) {
    if (buf[i] === 0) return true; // NUL byte → treat as binary
  }
  return false;
}

var ROOT = process.env.GITHUB_WORKSPACE || process.cwd();
var files = [];

function walk(abs) {
  var rel = path.relative(ROOT, abs) || ".";
  var stat;
  try { stat = fs.statSync(abs); } catch (e) { return; }
  if (stat.isDirectory()) {
    var base = path.basename(abs);
    if (IGNORE_DIRS[base]) return;
    if (matchesIgnore(rel + "/")) return;
    var entries;
    try { entries = fs.readdirSync(abs); } catch (e) { return; }
    for (var i = 0; i < entries.length; i++) walk(path.join(abs, entries[i]));
    return;
  }
  if (!stat.isFile()) return;
  var name = path.basename(abs);
  if (IGNORE_FILES[name]) return;
  if (BINARY_EXT.test(name)) return;
  if (stat.size > MAX_BYTES) return;
  if (matchesIgnore(rel)) return;
  files.push(abs);
}

SCAN_PATHS.forEach(function (p) {
  var abs = path.isAbsolute(p) ? p : path.join(ROOT, p);
  walk(abs);
});

/* ---- scan --------------------------------------------------------- */
var allFindings = [];
files.forEach(function (abs) {
  var buf;
  try { buf = fs.readFileSync(abs); } catch (e) { return; }
  if (looksBinary(buf)) return;
  var text = buf.toString("utf8");
  var findings = engine.scan(text);
  if (!findings.length) return;
  var rel = path.relative(ROOT, abs).split(path.sep).join("/");
  findings.forEach(function (f) {
    f.file = rel;
    allFindings.push(f);
  });
});

/* ---- report ------------------------------------------------------- */
function esc(s) { // escape for workflow-command messages
  return String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

var counts = { critical: 0, high: 0, medium: 0, low: 0 };
allFindings.forEach(function (f) { counts[f.severity] = (counts[f.severity] || 0) + 1; });

var failRank = FAIL_ON === "none" ? -1 : (SEVERITY_RANK[FAIL_ON] != null ? SEVERITY_RANK[FAIL_ON] : 1);
var blocking = 0;

allFindings.forEach(function (f) {
  var isBlocking = failRank >= 0 && SEVERITY_RANK[f.severity] <= failRank;
  if (isBlocking) blocking++;
  var level = isBlocking ? "error" : "warning";
  var title = "LeakCheck: " + f.name + " (" + f.severity + ")";
  var msg = f.name + " [" + f.severity + "] — preview " + f.masked + ". " + f.why + " Rotate it in " + f.rotate + ".";
  process.stdout.write(
    "::" + level + " file=" + esc(f.file) + ",line=" + f.line + ",title=" + esc(title) + "::" + esc(msg) + "\n"
  );
});

/* ---- job summary -------------------------------------------------- */
var lines = [];
lines.push("## 🔍 LeakCheck — secret scan");
lines.push("");
if (!allFindings.length) {
  lines.push("✅ **No hard-coded secrets detected** in " + files.length + " scanned files.");
  lines.push("");
  lines.push("_A clean scan is not a guarantee — entropy detection can miss custom token formats. Keep credentials in env vars / a secret manager and add a pre-commit hook._");
} else {
  lines.push("Found **" + allFindings.length + "** potential secret" + (allFindings.length === 1 ? "" : "s") +
    " across " + files.length + " scanned files — " +
    counts.critical + " critical, " + counts.high + " high, " + counts.medium + " medium, " + counts.low + " low.");
  lines.push("");
  lines.push("| Severity | Type | File | Line | Preview |");
  lines.push("|---|---|---|---|---|");
  allFindings.forEach(function (f) {
    lines.push("| " + f.severity + " | " + f.name + " | `" + f.file + "` | " + f.line + " | `" + f.masked + "` |");
  });
  lines.push("");
  lines.push("**What to do:** rotate every flagged credential now (assume it is compromised the moment it hit a commit), remove it from source, load it from an environment variable, and scrub it from git history with `git filter-repo` or BFG.");
}
lines.push("");
lines.push("---");
lines.push("Scanned by [**LeakCheck**](" + LEAKCHECK_URL + ") — paste a file to scan in your browser (nothing is uploaded).  ");
lines.push("Want a human to rotate these and lock the app down properly? → [**Copper Bay Tech**](" + AGENCY_URL + ") does it for you.");

var summary = lines.join("\n") + "\n";
if (process.env.GITHUB_STEP_SUMMARY) {
  try { fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary); } catch (e) { /* ignore */ }
}

/* ---- outputs ------------------------------------------------------ */
if (process.env.GITHUB_OUTPUT) {
  var out =
    "findings-count=" + allFindings.length + "\n" +
    "critical-count=" + counts.critical + "\n" +
    "high-count=" + counts.high + "\n" +
    "blocking-count=" + blocking + "\n";
  try { fs.appendFileSync(process.env.GITHUB_OUTPUT, out); } catch (e) { /* ignore */ }
}

/* ---- console + exit ----------------------------------------------- */
if (!allFindings.length) {
  console.log("LeakCheck: no secrets detected in " + files.length + " files. (" + LEAKCHECK_URL + ")");
  process.exit(0);
}
console.log("LeakCheck: " + allFindings.length + " potential secret(s) found in " + files.length + " files — " +
  counts.critical + " critical / " + counts.high + " high / " + counts.medium + " medium / " + counts.low + " low.");
console.log("Full browser scanner: " + LEAKCHECK_URL + "  •  Get them fixed for you: " + AGENCY_URL);

if (blocking > 0) {
  console.log("Failing the build: " + blocking + " finding(s) at or above fail-on='" + FAIL_ON + "'.");
  process.exit(1);
}
process.exit(0);
