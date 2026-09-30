# Installing the baseline (Windows)

For what the baseline does, see [README.md](./README.md).

## Prerequisites

- **Python 3.8+ at a fixed, admin-owned path.** Confirm with `(Get-Command python).Source`. The hook config expects `C:\Program Files\Python312\python.exe` — if the interpreter sits elsewhere, all four `exec` values in `10-security-baseline.windows.json` must be edited first. **A wrong path denies every shell command.** No pip packages needed.
- **Local administrator rights**, or Intune for fleet delivery.

## Three decisions before rollout

Each is disruptive to change after rollout.

| Decision | Why it matters | Action |
|---|---|---|
| **Tune `permissions.allow`** | Defining any deny/ask rule makes *unmatched* operations prompt — including normally auto-approved file reads | Add the organisation's standard toolchain to the starter allow list. `deny`/`ask` still take precedence, so this doesn't weaken anything |
| **Set `sandbox.failIfUnavailable`** | Sandboxing is an experimental Copilot CLI feature whose host requirements vary. `true` stops the CLI running whenever the sandbox can't be enforced | Confirm sandbox behaviour on the standard image before enabling. Until confirmed, `false` avoids blocking sessions |
| **Pin the CLI version** | The CLI auto-updates on startup. `npm install -g @github/copilot@VERSION` alone does **not** hold — the updater overrides it | Pin *and* set `COPILOT_AUTO_UPDATE=false` at machine scope. Note `copilot update stable` won't move a machine back from a prerelease build |

The first is the biggest factor in whether developers accept the tool or work around it.

## Install

Elevated PowerShell, from the pack root.

```powershell
# 1. Guard script
New-Item -ItemType Directory -Force 'C:\Program Files\GitHubCopilotPolicy' | Out-Null
Copy-Item .\scripts\copilot_policy_guard.py 'C:\Program Files\GitHubCopilotPolicy\' -Force

# 2. Hook config
New-Item -ItemType Directory -Force 'C:\ProgramData\GitHub\Copilot\policy.d' | Out-Null
Copy-Item .\policy-hooks\10-security-baseline.windows.json 'C:\ProgramData\GitHub\Copilot\policy.d\' -Force

# 3. Lock permissions — without this, users can edit or delete the policy
icacls 'C:\ProgramData\GitHub\Copilot\policy.d' /inheritance:r `
  /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' /grant 'Users:(OI)(CI)RX'
```

> Steps 1 and 2 must ship **together**. The config points at the script by absolute path — if the script is missing, every shell command is denied.

**Managed settings** — either copy locally:

```powershell
New-Item -ItemType Directory -Force "$env:ProgramFiles\GitHubCopilot" | Out-Null
Copy-Item .\managed-settings\managed-settings.json "$env:ProgramFiles\GitHubCopilot\" -Force
```

Or publish centrally — committed to an enterprise `.github-private` repository at `copilot/managed-settings.json`. Clients pick it up at sign-in. **This needs no machine access or admin rights**, so the deny/ask/allow rules can be enforced immediately with the hooks following later. Policy hooks cannot be delivered this way — they are machine-local by design.

### Fleet (Intune)

The three steps above can be packaged as a script and deployed as a **Win32 app** — install behaviour **System**, detection rule on `C:\Program Files\GitHubCopilotPolicy\copilot_policy_guard.py`, assigned to the device group receiving Copilot CLI. A platform script works too but has no detection or remediation.

`managed-settings.json` is delivered via MDM under `HKLM\SOFTWARE\Policies\GitHubCopilot`, or published centrally as above.

## Verification

Verification should not stop at "the file copied" — the guard must be confirmed to decide.

**1. Blocking works**

```powershell
'{"sessionId":"t","timestamp":0,"cwd":"C:\\","toolName":"powershell","toolArgs":{"command":"cat .env"}}' |
  & 'C:\Program Files\Python312\python.exe' 'C:\Program Files\GitHubCopilotPolicy\copilot_policy_guard.py' pre-tool
```

Expect `{"permissionDecision": "deny", "permissionDecisionReason": "[dotenv-files] ..."}`. No output means the rule didn't match; an error means the Python path is wrong.

**2. Redaction works** — same command with `post-tool` and a payload containing `"textResultForLlm":"db_password = hunter2SuperSecret"`. Expect `[REDACTED:generic-secret-assignment]`.

**3. End to end** — Copilot is asked to run `cat .env` in a folder containing one:

```
✗ Denied by preToolUse hook: [dotenv-files] Reading .env files is not permitted.
```

**4. Users can't disable it** — with `disableAllHooks: true` set in `%USERPROFILE%\.copilot\settings.json`, test 3 is repeated. The denial must still occur.

## Operating it

**Audit log** — setting `COPILOT_POLICY_AUDIT_LOG` in each hook entry's `env` block writes a JSONL record per decision (timestamp, event, decision, rule ID, session ID — no command text or file content):

```json
"env": { "COPILOT_POLICY_AUDIT_LOG": "C:\\ProgramData\\GitHub\\Copilot\\policy-audit.jsonl" }
```

**Changing rules** — both sets are plain lists at the top of `copilot_policy_guard.py`: `_RAW_SHELL_RULES` (`id`, `deny`/`ask`, reason, regex — deny beats ask) and `_RAW_SECRET_PATTERNS` (label, regex, capture group). There's no auto-update or upstream, so any change requires re-verification and redeployment.

**Before fleet rollout** — `90-payload-capture.pilot-only.json` and its log must be removed. It captures raw prompts and tool output, including any secrets.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Every shell command denied | Wrong Python path, or script missing — see verify test 1 |
| Hooks do nothing | Config not in `policy.d`, or invalid JSON |
| Developers prompted constantly | `permissions.allow` not tuned |
| Sandboxed commands fail unexpectedly | Sandbox policy doesn't cover a path the shell needs. One known cause: redirected profile folders (for example OneDrive Known Folder Move) place the PowerShell config outside the sandbox's allowed paths — grant that path or relocate the config |
| Behaviour differs between machines | CLI versions have drifted |
