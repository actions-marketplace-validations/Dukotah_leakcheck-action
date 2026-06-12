/* LeakCheck detection engine — Node port of the client-side scanner that powers
 * https://labs.copperbaytech.com/leakcheck/ . The detector definitions, entropy
 * gating, masking, and dedupe logic are kept byte-for-byte in sync with the web
 * app so a finding in CI matches a finding in the browser tool.
 *
 * SAFETY: full secret values are never returned. Every finding carries only a
 * masked preview (first 4 + last 4 chars) so secrets are not echoed into CI logs,
 * which are frequently public on open-source repositories.
 */
"use strict";

var SEVERITIES = ["critical", "high", "medium", "low"];

/* ------------------------------------------------------------------ *
 * Masking — show only first 4 + last 4 chars; collapse the middle.
 * ------------------------------------------------------------------ */
function maskSecret(raw) {
  var s = String(raw).replace(/\s+/g, "");
  if (s.length <= 8) {
    var head = s.slice(0, Math.min(2, s.length));
    return head + repeat("•", Math.max(4, s.length - head.length));
  }
  var first = s.slice(0, 4);
  var last = s.slice(-4);
  var midLen = s.length - 8;
  var bullets = repeat("•", Math.min(midLen, 18));
  return first + bullets + last;
}

function repeat(ch, n) {
  var out = "";
  for (var i = 0; i < n; i++) out += ch;
  return out;
}

/* Shannon entropy (bits per char) — filters generic/entropy hits so we only
 * flag values that actually look random rather than ordinary words. */
function shannonEntropy(str) {
  if (!str.length) return 0;
  var freq = Object.create(null);
  for (var i = 0; i < str.length; i++) {
    var c = str[i];
    freq[c] = (freq[c] || 0) + 1;
  }
  var entropy = 0;
  var len = str.length;
  for (var k in freq) {
    var p = freq[k] / len;
    entropy -= p * (Math.log(p) / Math.LN2);
  }
  return entropy;
}

/* ------------------------------------------------------------------ *
 * Named, high-confidence detectors (kept in sync with leakcheck/app.js).
 * ------------------------------------------------------------------ */
var DETECTORS = [
  {
    name: "AWS Access Key ID",
    severity: "high",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    why: "An AWS access key ID identifies an IAM principal and, paired with its secret, grants programmatic access to your AWS account.",
    rotate: "the AWS IAM console (deactivate then delete the key pair)"
  },
  {
    name: "AWS Secret Access Key",
    severity: "critical",
    regex: /(?:aws.{0,20})?(?:secret|SECRET)[^\n]{0,20}?["'=:\s]+([A-Za-z0-9\/+]{40})\b/g,
    group: 1,
    why: "The AWS secret access key is the password half of an AWS credential pair and lets an attacker fully control your AWS resources and bill.",
    rotate: "the AWS IAM console (rotate the access key pair immediately)"
  },
  {
    name: "GitHub Personal Access Token",
    severity: "critical",
    regex: /\bghp_[0-9A-Za-z]{36}\b/g,
    why: "A GitHub PAT can read and push to your repositories and act on your behalf across GitHub.",
    rotate: "GitHub → Settings → Developer settings → Personal access tokens (revoke it)"
  },
  {
    name: "GitHub Fine-grained PAT",
    severity: "critical",
    regex: /\bgithub_pat_[0-9A-Za-z_]{22,}\b/g,
    why: "A fine-grained GitHub PAT grants scoped repo/org access and can be replayed by anyone who finds it.",
    rotate: "GitHub → Settings → Developer settings → Fine-grained tokens (revoke it)"
  },
  {
    name: "GitHub OAuth / App Token",
    severity: "critical",
    regex: /\b(?:gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/g,
    why: "GitHub OAuth, user-to-server, server-to-server, and refresh tokens authenticate GitHub API calls and can hijack a session or app installation.",
    rotate: "GitHub (revoke the OAuth app authorization / regenerate the app token)"
  },
  {
    name: "GitLab Personal Access Token",
    severity: "critical",
    regex: /\bglpat-[0-9A-Za-z_\-]{20,}\b/g,
    why: "A GitLab PAT can clone, push, and administer your GitLab projects depending on its scopes.",
    rotate: "GitLab → Preferences → Access Tokens (revoke it)"
  },
  {
    name: "OpenAI API Key (project)",
    severity: "critical",
    regex: /\bsk-proj-[A-Za-z0-9_\-]{20,}\b/g,
    why: "An OpenAI project key bills your account for API usage and can be abused to run up large charges.",
    rotate: "the OpenAI dashboard → API keys (revoke it)"
  },
  {
    name: "OpenAI API Key",
    severity: "critical",
    regex: /\bsk-(?!proj-|ant-)[A-Za-z0-9]{20,}\b/g,
    why: "An OpenAI API key bills your account for model usage and can be drained by anyone who obtains it.",
    rotate: "the OpenAI dashboard → API keys (revoke it)"
  },
  {
    name: "Anthropic API Key",
    severity: "critical",
    regex: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g,
    why: "An Anthropic API key bills your account for Claude usage and can be abused for unauthorized requests.",
    rotate: "the Anthropic console → API keys (revoke it)"
  },
  {
    name: "Stripe Secret Key (live)",
    severity: "critical",
    regex: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/g,
    why: "A live Stripe secret key can create charges, issue refunds, and read customer/payment data on your real account.",
    rotate: "the Stripe dashboard → Developers → API keys (roll the key immediately)"
  },
  {
    name: "Stripe Secret Key (test)",
    severity: "high",
    regex: /\b(?:sk|rk)_test_[0-9A-Za-z]{20,}\b/g,
    why: "A Stripe test secret key exposes your test environment and signals a secret-in-code habit that often repeats with live keys.",
    rotate: "the Stripe dashboard → Developers → API keys (roll the test key)"
  },
  {
    name: "Stripe Publishable Live Key",
    severity: "low",
    regex: /\bpk_live_[0-9A-Za-z]{20,}\b/g,
    why: "A Stripe publishable key is meant to be public, but its presence often means secret keys are nearby in the same file.",
    rotate: "the Stripe dashboard (publishable keys are public, but review the file for secret keys)"
  },
  {
    name: "Google API Key",
    severity: "high",
    regex: /AIza[0-9A-Za-z_\-]{35,}/g,
    why: "A Google API key can call billable Google/Firebase/Maps APIs on your project and rack up charges if unrestricted.",
    rotate: "Google Cloud Console → APIs & Services → Credentials (regenerate and add restrictions)"
  },
  {
    name: "Slack Token",
    severity: "critical",
    regex: /\bxox[baprs]-[0-9A-Za-z\-]{10,}\b/g,
    why: "A Slack token can read and post messages and access files across your workspace depending on its scopes.",
    rotate: "the Slack app config / workspace admin (revoke the token)"
  },
  {
    name: "Twilio API Key SID",
    severity: "high",
    regex: /\bSK[0-9a-f]{32}\b/g,
    why: "A Twilio API key SID, paired with its secret, can send SMS/voice and incur charges on your Twilio account.",
    rotate: "the Twilio console → API keys (delete the key)"
  },
  {
    name: "SendGrid API Key",
    severity: "critical",
    regex: /\bSG\.[\w\-]{22}\.[\w\-]{43}\b/g,
    why: "A SendGrid API key can send email as your domain, enabling spam or phishing from your reputation.",
    rotate: "the SendGrid dashboard → API Keys (delete the key)"
  },
  {
    name: "Mailgun API Key",
    severity: "high",
    regex: /\bkey-[0-9a-f]{32}\b/g,
    why: "A Mailgun API key can send email through your account and read sending logs.",
    rotate: "the Mailgun dashboard → API security (regenerate the key)"
  },
  {
    name: "npm Access Token",
    severity: "critical",
    regex: /\bnpm_[0-9A-Za-z]{36}\b/g,
    why: "An npm token can publish packages under your account, a vector for supply-chain attacks.",
    rotate: "npmjs.com → Access Tokens (revoke it)"
  },
  {
    name: "Shopify Access Token",
    severity: "critical",
    regex: /\b(?:shpat|shpss|shpca|shppa)_[0-9a-fA-F]{32}\b/g,
    why: "A Shopify access token can read/modify store data including orders and customers.",
    rotate: "the Shopify admin / partner dashboard (revoke the app token)"
  },
  {
    name: "Discord Bot Token",
    severity: "high",
    regex: /\b[MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b/g,
    why: "A Discord bot token gives full control of the bot account, including reading and sending messages in every server it joined.",
    rotate: "the Discord developer portal → Bot (reset the token)"
  },
  {
    name: "JSON Web Token (JWT)",
    severity: "medium",
    regex: /\beyJ[\w\-]+\.eyJ[\w\-]+\.[\w\-]+\b/g,
    why: "A JWT can carry session identity or claims and may grant access until it expires if it is a live token.",
    rotate: "your auth provider / app (invalidate the session and rotate signing keys if it is a server secret)"
  },
  {
    name: "Private Key (PEM)",
    severity: "critical",
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    why: "A PEM private key is the cryptographic identity behind TLS, SSH, or signing — whoever holds it can impersonate your service.",
    rotate: "the system that issued it (generate a new key pair and revoke/replace the old one everywhere)"
  },
  {
    name: "Database URI with credentials",
    severity: "critical",
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^\s:@\/]+:[^\s:@\/]+@[^\s\/"']+/g,
    why: "A database connection string with an inline username and password grants direct read/write access to your data.",
    rotate: "your database (rotate the database user's password and restrict network access)"
  },
  {
    name: "Authorization / Bearer header",
    severity: "high",
    regex: /(?:Authorization|authorization)\s*[:=]\s*["']?(?:Bearer|Basic|Token)\s+([A-Za-z0-9_\-\.=+\/]{12,})/g,
    group: 1,
    why: "A hard-coded Authorization header embeds a live credential that authenticates requests to a protected API.",
    rotate: "the issuing service (revoke the token and inject it from an env var at runtime)"
  },
  {
    name: "Generic API key / secret assignment",
    severity: "medium",
    regex: /(?:^|[^\w])([A-Za-z][A-Za-z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CLIENT[_-]?SECRET|AUTH))\s*[:=]\s*["'`]([^"'`\n]{8,})["'`]/gi,
    group: 2,
    why: "A secret-looking variable is assigned a value directly in source, so anyone with the code has the credential.",
    rotate: "the owning service (rotate the value and load it from an environment variable instead)",
    entropyMin: 2.6
  }
];

/* Entropy fallback: long high-entropy value assigned to a secret-looking key
 * that the named/generic detectors did not already catch. */
var ENTROPY_RE = /(?:^|[^\w])([A-Za-z][A-Za-z0-9_]*(?:key|secret|token|password|passwd|auth|credential|api)[A-Za-z0-9_]*)\s*[:=]\s*["'`]?([A-Za-z0-9_\-\.+\/=]{24,})["'`]?/gi;
var ENTROPY_THRESHOLD = 4.0;

function buildLineIndex(text) {
  var starts = [0];
  for (var i = 0; i < text.length; i++) {
    if (text[i] === "\n") starts.push(i + 1);
  }
  return starts;
}
function lineAt(starts, offset) {
  var lo = 0, hi = starts.length - 1, ans = 0;
  while (lo <= hi) {
    var mid = (lo + hi) >> 1;
    if (starts[mid] <= offset) { ans = mid; lo = mid + 1; }
    else hi = mid - 1;
  }
  return ans + 1;
}

/* Core scan: run every detector + entropy fallback over the text. Returns an
 * array of findings carrying only a masked preview of each secret. */
function scan(text) {
  var findings = [];
  var lineIndex = buildLineIndex(text);
  var seen = Object.create(null);

  function push(name, severity, why, rotate, secretRaw, offset) {
    if (!secretRaw) return;
    var line = lineAt(lineIndex, offset);
    var masked = maskSecret(secretRaw);
    var key = name + "|" + masked + "|" + line;
    if (seen[key]) return;
    seen[key] = true;
    findings.push({
      name: name,
      severity: severity,
      why: why,
      rotate: rotate,
      masked: masked,
      line: line
    });
  }

  for (var d = 0; d < DETECTORS.length; d++) {
    var det = DETECTORS[d];
    var re = det.regex;
    re.lastIndex = 0;
    var m;
    while ((m = re.exec(text)) !== null) {
      if (m.index === re.lastIndex) re.lastIndex++;
      var secret = det.group != null ? m[det.group] : m[0];
      if (!secret) continue;
      var secretOffset = m.index;
      if (det.group != null) {
        var gi = m[0].indexOf(secret);
        if (gi >= 0) secretOffset = m.index + gi;
      }
      if (det.entropyMin != null) {
        var clean = secret.replace(/\s+/g, "");
        if (shannonEntropy(clean) < det.entropyMin) continue;
      }
      push(det.name, det.severity, det.why, det.rotate, secret, secretOffset);
    }
  }

  ENTROPY_RE.lastIndex = 0;
  var em;
  while ((em = ENTROPY_RE.exec(text)) !== null) {
    if (em.index === ENTROPY_RE.lastIndex) ENTROPY_RE.lastIndex++;
    var val = em[2];
    if (!val) continue;
    var ent = shannonEntropy(val);
    if (ent < ENTROPY_THRESHOLD) continue;
    var gidx = em[0].indexOf(val);
    var off = em.index + (gidx >= 0 ? gidx : 0);
    var ln = lineAt(lineIndex, off);
    var already = false;
    for (var f = 0; f < findings.length; f++) {
      if (findings[f].line === ln) { already = true; break; }
    }
    if (already) continue;
    push(
      "High-entropy secret (heuristic)",
      "medium",
      "This value is long and highly random, the signature of an API key or token even though it matches no known provider format.",
      "the owning service (rotate it and move it to an environment variable or secret manager)",
      val,
      off
    );
  }

  findings.sort(function (a, b) {
    var sa = SEVERITIES.indexOf(a.severity);
    var sb = SEVERITIES.indexOf(b.severity);
    if (sa !== sb) return sa - sb;
    return a.line - b.line;
  });

  return findings;
}

module.exports = { scan: scan, maskSecret: maskSecret, shannonEntropy: shannonEntropy, SEVERITIES: SEVERITIES };
