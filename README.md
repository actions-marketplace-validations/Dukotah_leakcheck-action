# 🔍 LeakCheck — Secret Scanner Action

Catch hard-coded **API keys, tokens, and secrets before they reach production.**
Drop this into any GitHub repo and it scans every push and pull request for
exposed credentials — AWS, GitHub, Stripe, OpenAI, Slack, database URIs, private
keys, and more — then annotates the exact file and line.

- **Zero dependencies, zero config** — one step, runs in seconds.
- **Secrets are never printed** — findings show only a masked preview (`ghp_••••…wxyz`), because Action logs are public on open-source repos.
- **Same engine as the free browser scanner** at **[labs.copperbaytech.com/leakcheck](https://labs.copperbaytech.com/leakcheck/)** — paste a file and scan it locally (nothing uploaded) when you want a one-off check.

> ~28 million secrets were leaked to public GitHub in 2025 — up 34% year over year. The cheapest one to catch is the one that never lands in a commit.

## Usage

Create `.github/workflows/leakcheck.yml`:

```yaml
name: LeakCheck
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Dukotah/leakcheck-action@v1
```

That's it. The job fails if a **high** or **critical** secret is found, and writes
a summary table to the run's **Summary** tab.

## Inputs

| Input | Default | Description |
|---|---|---|
| `paths` | `.` | Comma/newline-separated paths to scan, relative to the repo root. |
| `fail-on` | `high` | Minimum severity that fails the build: `critical`, `high`, `medium`, `low`, or `none` (report only). |
| `ignore` | _(none)_ | Comma/newline-separated path globs to skip, e.g. `test/fixtures/*, *.snap`. `*` is a wildcard. |
| `max-file-kb` | `1024` | Skip files larger than this many KB. |

Binary files, `.git`, `node_modules`, build output, and lockfiles are skipped automatically.

## Outputs

| Output | Description |
|---|---|
| `findings-count` | Total potential secrets found. |
| `critical-count` | Critical-severity findings. |
| `high-count` | High-severity findings. |
| `blocking-count` | Findings at or above the `fail-on` threshold. |

### Report-only mode

To surface findings without ever failing the build:

```yaml
      - uses: Dukotah/leakcheck-action@v1
        with:
          fail-on: none
```

### Scan only changed code paths

```yaml
      - uses: Dukotah/leakcheck-action@v1
        with:
          paths: src, config
          ignore: "**/__snapshots__/*, *.test.js"
```

## What to do when it flags something

1. **Rotate the credential now** — assume it is compromised the moment it touched a commit, even a private one.
2. **Remove it from source** and load it from an environment variable or secret manager.
3. **Scrub git history** with [`git filter-repo`](https://github.com/newren/git-filter-repo) or [BFG](https://rtyley.github.io/bfg-repo-cleaner/) so the secret isn't recoverable from old commits.

**Want a human to do all of that for you and harden the app properly?**
[**Copper Bay Tech**](https://copperbaytech.com) fixes exposed secrets, dependency
risks, and security-header gaps as a service — send us your scan results for a free fix quote.

## What it detects

AWS access keys & secrets · GitHub PATs / OAuth / app tokens · GitLab PATs ·
OpenAI & Anthropic keys · Stripe live/test keys · Google API keys · Slack tokens ·
Twilio · SendGrid · Mailgun · npm tokens · Shopify tokens · Discord bot tokens ·
JWTs · PEM private keys · database connection strings with inline credentials ·
hard-coded Authorization headers · generic high-entropy secret assignments.

Detection is heuristic — a clean scan is not a guarantee, and entropy detection can
miss bespoke token formats. Pair it with a pre-commit hook like
[gitleaks](https://github.com/gitleaks/gitleaks) for defense in depth.

## Privacy & safety

This Action runs entirely inside your runner. It makes **no network calls** — your
code never leaves GitHub's infrastructure, and full secret values are never written
to logs, outputs, or the job summary (only masked previews).

## License

MIT © [Copper Bay Tech](https://copperbaytech.com). Part of [Copper Bay Labs](https://labs.copperbaytech.com/).
