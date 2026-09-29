# Copilot CLI security baseline (Windows)

A reference configuration that blocks high-risk shell commands and keeps secrets out of the model, using GitHub's documented enterprise controls. Scoped to **Windows** for the initial proof of value.

> **Not an official or supported GitHub or Microsoft configuration.** Built from GitHub's published documentation (September 2026) and confirmed working against a live Copilot CLI 1.0.89 on Windows 11 — hook loading, command blocking and secret redaction were each observed in a real session. GitHub does not publish an official baseline; they document the building blocks and each organisation assembles its own policy from them. Validate on your standard image before relying on it.

## What it does

**1. Blocks high-risk shell commands before they run** — privilege escalation, destructive deletes, `curl | sh` and other download-and-execute patterns, reverse shells, credential and token extraction.

**2. Keeps secrets out of the model** — blocks access to `.ssh`, `.aws`, `.azure`, `.kube` and `.env` files, and redacts secrets from command output *and* pasted prompt text before either reaches the model.

## Contents

| Path | Purpose |
|---|---|
| `managed-settings/managed-settings.json` | Deny/ask/allow rules, allow-all ("YOLO") disabled, sandbox policy, remote control off, third-party MCP servers blocked |
| `policy-hooks/10-security-baseline.windows.json` | Registers the guard script against four Copilot CLI hook events |
| `policy-hooks/90-payload-capture.pilot-only.json` | **Pilot diagnostics only.** Logs raw hook payloads. Remove before fleet rollout |
| `scripts/copilot_policy_guard.py` | The enforcement logic — 27 command rules, 12 secret patterns. Python 3.8+, standard library only |
| `INSTALL.md` | Deployment guide — prerequisites, install, verification, troubleshooting |

## How it works

Two layers, neither of which a developer can switch off.

**Managed settings** — rules the GitHub platform enforces. Blunt but unbreakable: they work on command names, so they can block `curl` entirely but cannot distinguish `curl | sh` from `curl -o file.json`.

**Policy hooks** — a local script Copilot CLI calls at four moments:

| Moment | What the script does |
|---|---|
| Before any shell command | Inspects the full command; allows, prompts, or **denies** |
| After a command returns | Redacts secrets from the output before the model sees it |
| When a prompt is submitted | Redacts secrets from the prompt text |
| On a sandbox-escape request | Denies it |

The hooks catch dangerous *combinations* that managed settings cannot express, and provide the only mechanism for redaction.

## Install

See **[INSTALL.md](./INSTALL.md)**.

In short: two files land on each machine (the guard script and the hook config), and the guard needs Python 3.8+ at a fixed, admin-owned path. `managed-settings.json` can either be copied locally or published once to your enterprise `.github-private` repository — the central route needs no machine access and no local admin rights.

## What it does not do

Be explicit about these when presenting the baseline.

- **Prompts are redacted, not blocked.** A pasted secret is masked before the model receives it, but the CLI cannot refuse the prompt itself.
- **Detection is pattern-based.** A secret with no recognisable format — an unlabelled high-entropy string — will not be caught.
- **The command rules are a speed bump, not a boundary.** Aliases, scripts written to disk and then run, or unusual encodings can defeat pattern matching. The managed deny rules and the OS sandbox are the real boundary.
- **This is not DLP.** Nothing here prevents data leaving the machine by other routes. Endpoint and network DLP remain the controlling measures.
