# Installing the Copilot CLI security baseline (Windows)

Deployment instructions for administrators. For what the baseline does, see [README.md](./README.md).

---

## What gets installed

| # | File | Goes to |
|---|---|---|
| 1 | `scripts\copilot_policy_guard.py` | `C:\Program Files\GitHubCopilotPolicy\` |
| 2 | `policy-hooks\10-security-baseline.windows.json` | `C:\ProgramData\GitHub\Copilot\policy.d\` |
| 3 | `managed-settings\managed-settings.json` | `%ProgramFiles%\GitHubCopilot\` — or publish centrally, see [Step 4](#step-4-managed-settings) |

> **Files 1 and 2 must be deployed together.** File 2 points at file 1 by absolute path. If the script is missing, **every shell command is denied**.

---

## Prerequisites

### 1. Python 3.8+ at a fixed, admin-owned path

The hook config calls Python by absolute path so a user cannot substitute their own. Check yours:

```powershell
(Get-Command python).Source
```

The shipped config expects `C:\Program Files\Python312\python.exe`. **If yours differs, edit all four `exec` values in `10-security-baseline.windows.json` before deploying.**

No pip packages required — the script uses only the Python standard library.

### 2. Local administrator rights

Needed to write to `Program Files` and `ProgramData`. Fleet deployment goes through Intune.

### 3. Three decisions before you roll out

These three behaviours were confirmed by testing against a live Copilot CLI. Each changes how you should deploy.

**a. Tune `permissions.allow` for your toolchain — or developers will be prompted constantly.**

Defining *any* managed permission rule causes unmatched operations to default to requiring approval, including file reads that are normally auto-approved. The shipped `managed-settings.json` includes a starter allow list covering common build, test and read-only commands. **Add your standard toolchain to it before rollout.** `deny` and `ask` always take precedence, so extending `allow` does not weaken the guardrails.

This is the single biggest factor in whether developers accept the tool or work around it.

**b. Decide `sandbox.failIfUnavailable` deliberately — OneDrive can break sandboxed commands.**

Local sandboxing works on standard Windows 11, but with sandboxing required an ordinary `echo` command failed on a test machine because the sandbox blocked PowerShell from reading its own config under a OneDrive-redirected Documents folder:

```
PSInvalidOperationException: PowerShell has stopped working because of a security
issue: Cannot read the configuration file:
C:\Users\<user>\OneDrive - <Tenant>\...\PowerShell\powershell.config.json
```

OneDrive Known Folder Move is standard in most Microsoft-managed environments, so this is likely to affect a large share of a fleet — and it surfaces as a crash with a path-permission stack trace, not a clear "sandbox unavailable" message.

**Test this on a machine with OneDrive-redirected Documents before setting `failIfUnavailable: true`.** Until validated, `false` is the safer setting.

**c. Pin the CLI version — installing a version is not enough.**

Copilot CLI auto-updates on startup. Testing confirmed that installing a specific version does **not** hold on its own:

| Configuration | Version that actually runs |
|---|---|
| `npm install -g @github/copilot@1.0.89`, auto-update on | 1.0.90-1 — the pin is ignored |
| Same install + `COPILOT_AUTO_UPDATE=false` | 1.0.89 — the pin holds |

A durable pin needs both:

```powershell
npm install -g @github/copilot@1.0.89     # install the known-good version
setx COPILOT_AUTO_UPDATE false            # deploy at machine/user scope via MDM
```

A shell-session variable only lasts for that shell. Note also that `copilot update stable` will **not** move a machine back from a prerelease build.

To check which channel a machine is on, compare `copilot --version` against `npm view @github/copilot dist-tags`. A version *higher* than `latest` means that machine is on `prerelease`.

---

## Install — pilot machines

Run in an **elevated** PowerShell session, from the pack root.

### Step 1: guard script

```powershell
New-Item -ItemType Directory -Force 'C:\Program Files\GitHubCopilotPolicy' | Out-Null
Copy-Item .\scripts\copilot_policy_guard.py 'C:\Program Files\GitHubCopilotPolicy\' -Force
```

### Step 2: hook config

```powershell
New-Item -ItemType Directory -Force 'C:\ProgramData\GitHub\Copilot\policy.d' | Out-Null
Copy-Item .\policy-hooks\10-security-baseline.windows.json 'C:\ProgramData\GitHub\Copilot\policy.d\' -Force
```

### Step 3: lock permissions

```powershell
icacls 'C:\ProgramData\GitHub\Copilot\policy.d' /inheritance:r `
  /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' /grant 'Users:(OI)(CI)RX'
```

> Not optional. `C:\ProgramData` is user-writable by default — without this a developer can edit or delete the policy, and the control is void.

### Step 4: managed settings

**Either** copy locally:

```powershell
New-Item -ItemType Directory -Force "$env:ProgramFiles\GitHubCopilot" | Out-Null
Copy-Item .\managed-settings\managed-settings.json "$env:ProgramFiles\GitHubCopilot\" -Force
```

**Or** publish centrally — commit the file to your enterprise `.github-private` repository at `copilot/managed-settings.json`. Every enterprise-issued client picks it up at sign-in and refreshes periodically.

Central needs **no machine access and no admin rights**, so the deny/ask/allow rules and allow-all suppression can be enforced immediately, with the hooks following later. Policy hooks cannot be delivered this way — they are machine-local by design.

Where several sources define the same setting, sandbox and permission settings combine using the **most restrictive** value.

---

## Install — fleet (Intune)

Package steps 1–3 as a PowerShell script and deploy as a **Win32 app**:

| Setting | Value |
|---|---|
| Install command | `powershell.exe -ExecutionPolicy Bypass -File .\install.ps1` |
| Install behaviour | **System** |
| Detection rule | File exists: `C:\Program Files\GitHubCopilotPolicy\copilot_policy_guard.py` |
| Assignment | Device group receiving Copilot CLI |

A platform script (Devices → Scripts, system context) is quicker to stand up but has no detection or remediation. Prefer the Win32 app for anything you need to evidence in an audit.

Deliver `managed-settings.json` via MDM under `HKLM\SOFTWARE\Policies\GitHubCopilot`, or publish centrally as above.

---

## Verify

Do not stop at "the file copied" — confirm the guard actually decides.

### 1. The installed script denies a high-risk command

```powershell
'{"sessionId":"t","timestamp":0,"cwd":"C:\\","toolName":"powershell","toolArgs":{"command":"cat .env"}}' |
  & 'C:\Program Files\Python312\python.exe' 'C:\Program Files\GitHubCopilotPolicy\copilot_policy_guard.py' pre-tool
```

Expected:

```json
{"permissionDecision": "deny", "permissionDecisionReason": "[dotenv-files] Reading .env files is not permitted."}
```

An empty response means the rule did not match. No response at all, or an error, means the Python path is wrong.

### 2. Secret redaction works

```powershell
'{"sessionId":"t","timestamp":0,"cwd":"C:\\","toolName":"powershell","toolArgs":{"command":"cat c.txt"},"toolResult":{"resultType":"success","textResultForLlm":"db_password = hunter2SuperSecret"}}' |
  & 'C:\Program Files\Python312\python.exe' 'C:\Program Files\GitHubCopilotPolicy\copilot_policy_guard.py' post-tool
```

Expected: the value replaced with `[REDACTED:generic-secret-assignment]`.

### 3. End to end in Copilot CLI

Ask Copilot to run `cat .env` in a folder containing one:

```
✗ Denied by preToolUse hook: [dotenv-files] Reading .env files is not permitted.
```

### 4. A developer cannot disable it

Set `disableAllHooks: true` in `%USERPROFILE%\.copilot\settings.json`, then repeat test 3. The denial must still occur.

---

## Audit log (optional)

The guard writes a JSONL record for every decision when `COPILOT_POLICY_AUDIT_LOG` is set. Add it to each hook entry in the config:

```json
"env": { "COPILOT_POLICY_AUDIT_LOG": "C:\\ProgramData\\GitHub\\Copilot\\policy-audit.jsonl" }
```

Records timestamp, event, decision, rule ID and session ID — no command text or file content.

---

## Tuning and updating

Both rule sets are plain lists at the top of `scripts\copilot_policy_guard.py`:

- **`_RAW_SHELL_RULES`** — `(rule_id, "deny" | "ask", reason, regex)`. A deny match always beats an ask match.
- **`_RAW_SECRET_PATTERNS`** — `(label, regex, group)`. Group `0` redacts the whole match; a group number redacts only that capture group.

There is no auto-update and no upstream source, so after any change: edit the rule, re-verify using the tests above, and redeploy through the same channel.

---

## Watch out for

**Wrong Python path blocks everything.** The most common rollout failure. Verify before deploying.

**Never ship the config without the script.** Separate Intune waves create a window where all shell commands are denied.

**Remove the capture hook before fleet rollout.** `90-payload-capture.pilot-only.json` logs raw prompts and tool output, including any secrets present. Pilot diagnostics only — delete the hook and its log file afterwards.

**Skipping `icacls` voids the control.** Users can edit or delete an unprotected policy directory.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Every shell command denied | Wrong Python path, or script missing | Run verify test 1 |
| Hooks do nothing | Config not in `policy.d`, or invalid JSON | Check the path; confirm the JSON parses |
| Developers prompted constantly | `permissions.allow` not tuned | Prerequisite 3a |
| Ordinary commands crash with path errors | Sandbox on a OneDrive-redirected profile | Prerequisite 3b |
| Behaviour differs between machines | CLI versions have drifted | Prerequisite 3c |
