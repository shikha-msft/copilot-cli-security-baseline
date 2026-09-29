# Copilot CLI security baseline

A reference configuration for running **GitHub Copilot CLI** under enterprise guardrails on Windows. It blocks high-risk shell commands before they execute, and keeps secrets out of the model.

Built entirely from GitHub's documented controls — enterprise managed permissions, policy hooks and sandboxing — and confirmed working against a live Copilot CLI (1.0.89, Windows 11).

> **Not an official or supported GitHub or Microsoft configuration.** GitHub does not publish a baseline for Copilot CLI policy hooks or managed settings; they document the building blocks and each organisation assembles its own policy from them. This is one such assembly. Validate it on your own standard image, and have your security team review it, before relying on it.

## What problem it solves

Enabling Copilot CLI fleet-wide usually raises two questions from security:

1. **Can it run dangerous shell commands?** — privilege escalation, destructive deletes, `curl | sh`, reverse shells, credential extraction.
2. **Can it leak secrets to the model?** — SSH keys, cloud credentials, `.env` files, tokens pasted into prompts.

This baseline provides a concrete, testable answer to both.

## What's here

**[`copilot-cli-baseline/`](./copilot-cli-baseline/)** — the pack. Start with its [README](./copilot-cli-baseline/README.md) for what it does, or [INSTALL.md](./copilot-cli-baseline/INSTALL.md) to deploy it.

| Path | Purpose |
|---|---|
| `managed-settings/` | Platform-enforced deny/ask/allow rules, allow-all ("YOLO") disabled, sandbox policy |
| `policy-hooks/` | Registers the guard script against four Copilot CLI hook events |
| `scripts/` | The enforcement logic — 27 command rules, 12 secret patterns. Python 3.8+, standard library only |

## How it works

Two layers, neither of which a developer can switch off.

**Managed settings** are rules the GitHub platform enforces. Unbreakable, but blunt: they match on command names, so they can block `curl` entirely but cannot distinguish `curl | sh` from `curl -o file.json`.

**Policy hooks** are a local script the CLI calls before a command runs, after it returns, and when a prompt is submitted. They catch dangerous *combinations* that managed settings cannot express, and provide the only mechanism for redacting secrets before the model sees them.

Managed settings can be published centrally from your enterprise `.github-private` repository — no machine access required. Policy hooks are machine-local by design and need software distribution.

## Scope and limits

Targets **Windows** for the initial proof of value. The guard script is cross-platform; extending to macOS or Linux needs a POSIX hook config and re-confirmation of the payload shape.

These are strong guardrails, not a complete DLP solution:

- Prompts are **redacted, not blocked** — a pasted secret is masked before the model receives it, but the CLI cannot refuse the prompt itself.
- Detection is **pattern-based** — a secret with no recognisable format will not be caught.
- The command rules are a **speed bump, not a boundary** — the managed deny rules and the OS sandbox are the real boundary.
- Pair this with endpoint and network DLP for any guarantee about data leaving the machine.

## Reference

- [Enterprise managed settings](https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings)
- [Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
- [Allowing and denying tool use](https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/allowing-tools)
