#!/usr/bin/env python3
"""
Copilot CLI policy guard - reference baseline (DRAFT, not an official GitHub or Microsoft artifact).

One script, several hook modes. Copilot CLI runs it as a policy hook, sends the
event payload as JSON on stdin, and reads a JSON decision from stdout.

Modes (passed as the first argument):
  pre-tool     preToolUse         Block or require approval for high-risk shell commands.
  post-tool    postToolUse        Redact secrets from tool output before the model sees it.
  prompt       userPromptTransformed  Redact secrets from prompt text before it is sent to the model.
  permission   permissionRequest  Deny any request to run outside the sandbox (defence in depth).
  capture      any event          Log the raw payload to a file. Use during the pilot to confirm payload shapes.

Failure behaviour (per GitHub's hooks reference):
  pre-tool   : any error here exits 2, which Copilot CLI treats as DENY (fail-closed).
  other modes: errors produce no output, so the event continues unchanged (fail-open).
  timeouts   : fail OPEN for every event, including pre-tool. Keep this script fast.

Standard library only. Python 3.8+.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone

VERSION = "0.1.0-draft"
SHELL_TOOLS = {"bash", "powershell", "shell", "Bash", "PowerShell"}

# ---------------------------------------------------------------------------
# Shell command rules: (rule_id, decision, reason, compiled regex)
# Matched against a normalised, lower-cased copy of the command.
# "deny" blocks the command. "ask" forces a human approval prompt.
# ---------------------------------------------------------------------------
_RAW_SHELL_RULES = [
    # Privilege escalation
    ("priv-escalation", "deny", "Privilege escalation (sudo/su/doas/runas) is not permitted from Copilot CLI.",
     r"(^|[;&|(`\s])(sudo|doas|su|runas|pkexec)(\s|$)"),

    # Download-and-execute
    ("download-pipe-exec", "deny", "Piping downloaded content into an interpreter is not permitted.",
     r"(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|fetch)\b[^|;&]*\|\s*(sudo\s+)?"
     r"(sh|bash|zsh|ksh|dash|fish|python[0-9.]*|perl|ruby|node|php|pwsh|powershell|iex|invoke-expression)\b"),
    ("download-subshell-exec", "deny", "Executing downloaded content via a subshell is not permitted.",
     r"(sh|bash|zsh|python[0-9.]*|perl|ruby|node)\s+(-c\s+)?[\"']?(\$\(|<\()\s*(curl|wget)"),
    ("decode-pipe-exec", "deny", "Decoding content and piping it into an interpreter is not permitted.",
     r"(base64\s+(-d|--decode|-D)|xxd\s+-r|openssl\s+(enc\s+)?-d)[^|;&]*\|\s*(sh|bash|zsh|python[0-9.]*|perl|ruby|node)\b"),
    ("ps-invoke-expression", "deny", "Invoke-Expression / iex is not permitted.",
     r"(^|[;|&(\s])(iex|invoke-expression)(\s|\(|$)"),
    ("ps-encoded-command", "deny", "Encoded PowerShell commands are not permitted.",
     r"(pwsh|powershell)(\.exe)?\s+.*-(e|ec|enc|encodedcommand)\s+[a-z0-9+/=]{8,}"),
    ("ps-webclient-download", "deny", "In-memory script download via WebClient is not permitted.",
     r"net\.webclient.*download(string|file|data)"),

    # Destructive operations
    ("rm-root-home", "deny", "Recursive delete of root, home or wildcard paths is not permitted.",
     r"\brm\s+(-[a-z]*\s+)*-[a-z]*(r[a-z]*f|f[a-z]*r)[a-z]*\s+(-[a-z-]+\s+)*"
     r"(/|/\*|~|~/|~/\*|\$home|\$home/|\$home/\*|\*|\.\.|\.\./\*|/[a-z]+/?)(\s|$)"),
    ("rm-recursive-force", "ask", "Recursive force delete requires approval.",
     r"\brm\s+(-[a-z]*\s+)*-[a-z]*(r[a-z]*f|f[a-z]*r)"),
    ("ps-remove-recursive-root", "deny", "Recursive delete of a drive root or user profile is not permitted.",
     r"remove-item\b.*-recurse.*\s([a-z]:\\?|\$env:userprofile|\$home|~)(\s|$|\\\*)"),
    ("disk-format", "deny", "Disk formatting or raw device writes are not permitted.",
     r"(\bmkfs(\.[a-z0-9]+)?\b|\bdd\b[^;&|]*\bof=/dev/|\bformat\s+[a-z]:|\bdiskpart\b|\bfdisk\b|\bwipefs\b)"),
    ("fork-bomb", "deny", "Fork bomb pattern detected.",
     r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}"),
    ("chmod-world-root", "deny", "World-writable or setuid permission changes on system paths are not permitted.",
     r"\bchmod\s+(-[a-z]+\s+)*(777|a\+rwx|[ugo]*\+s|[0-7]?[4-7][0-7]{3})\s+(/|/[a-z]+|~)(\s|$)"),

    # Reverse shells / raw sockets
    ("reverse-shell", "deny", "Reverse shell or raw socket execution pattern detected.",
     r"(/dev/tcp/|/dev/udp/|\bnc(at)?\b[^;&|]*\s-(e|c)\s|\bsocat\b[^;&|]*exec:|\bmkfifo\b[^;&|]*\|\s*(sh|bash))"),

    # Credential stores and secret files
    ("credential-files", "deny", "Access to credential files (SSH keys, cloud credentials, .env) is not permitted.",
     r"(~|\$home|\$env:userprofile)?[/\\]?\.(ssh|aws|azure|kube|gnupg|docker)([/\\]|\s|$)"
     r"|\bid_(rsa|dsa|ecdsa|ed25519)\b|\.git-credentials\b|(^|[\s/\\\"'=])\.netrc\b|(^|[\s/\\\"'=])\.npmrc\b"
     r"|(^|[\s/\\\"'=])\.pypirc\b|\bgh[/\\]hosts\.yml\b"),
    ("dotenv-files", "deny", "Reading .env files is not permitted.",
     r"(^|[\s/\\\"'=<*])\.env(\.[a-z0-9_-]+)?($|[\s\"';|&>)])"),
    ("system-credential-files", "deny", "Access to system credential stores is not permitted.",
     r"(/etc/(shadow|gshadow|sudoers)\b|\bntds\.dit\b|system32[/\\]config[/\\](sam|security|system)\b"
     r"|/proc/\d+/environ\b|\bsecrets\.yaml\b|/var/run/secrets/\b)"),
    ("bulk-secret-search", "deny", "Bulk searching the filesystem for secret files is not permitted.",
     r"\b(find|fd|rg|grep|ls|dir|get-childitem|gci)\b[^;&|]*"
     r"(-name|-path|-glob|-include|--include|-recurse|-r)\s*[\"']?[^\s\"';|&]*"
     r"(\.env|\.pem|id_rsa|credentials|\.npmrc|secret)"),
    ("shell-history", "deny", "Reading shell history is not permitted.",
     r"(\.bash_history|\.zsh_history|\.history\b|consolehost_history\.txt|\bhistory\s+-c)"),
    ("token-extraction", "deny", "Extracting access tokens from CLIs or OS keychains is not permitted.",
     r"(\bgh\s+auth\s+token\b|\baz\s+account\s+get-access-token\b|\bgcloud\s+auth\s+(print-access-token|print-identity-token)\b"
     r"|\bsecurity\s+(find|dump)-(generic-password|internet-password|keychain)\b|\bcmdkey\s+/list\b"
     r"|\bget-storedcredential\b|\bvaultcmd\b|\baws\s+configure\s+(get|export-credentials)\b"
     r"|\baws\s+sts\s+get-session-token\b)"),
    ("env-dump", "ask", "Dumping environment variables can expose secrets and requires approval.",
     r"(^|[;&|]\s*)(env|printenv|set|export\s+-p|declare\s+-x)\s*($|[;&|>])|get-childitem\s+env:|\bgci\s+env:|\bls\s+env:|dir\s+env:"),

    # Security control tampering
    ("disable-security", "deny", "Disabling OS security controls is not permitted.",
     r"(\bsetenforce\s+0\b|set-mppreference\b.*-disable|\bspctl\s+--master-disable\b|\bcsrutil\s+disable\b"
     r"|set-executionpolicy\s+.*(bypass|unrestricted)|\bufw\s+disable\b|netsh\s+advfirewall\s+set\s+.*state\s+off)"),
    ("copilot-policy-tamper", "deny", "Modifying Copilot policy files is not permitted.",
     r"(github-copilot[/\\]policy\.d|githubcopilot[/\\]managed-settings|github[/\\]copilot[/\\]policy\.d|copilot_policy_guard)"),

    # Persistence and exfiltration (approval, not block)
    ("persistence", "ask", "Creating scheduled tasks or startup items requires approval.",
     r"(\bcrontab\b|\blaunchctl\s+(load|bootstrap|submit)\b|\bschtasks\s+/create\b|register-scheduledtask\b"
     r"|\bsystemctl\s+(enable|--user\s+enable)\b)"),
    ("file-upload", "ask", "Uploading local files to a remote endpoint requires approval.",
     r"\bcurl\b[^;&|]*\s(-d|--data(-binary|-raw|-urlencode)?|-f|--form|-t|--upload-file)\s*[\"']?@"
     r"|\bwget\b[^;&|]*--post-file|invoke-(webrequest|restmethod)\b[^;&|]*-infile"),
    ("git-force-push", "ask", "Force pushing requires approval.",
     r"\bgit\s+push\b[^;&|]*(\s--force\b|\s-f\b|\s--force-with-lease\b|\s\+[a-z0-9_/-]+)"),
    ("package-publish", "ask", "Publishing packages requires approval.",
     r"\b(npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\bdotnet\s+nuget\s+push\b|\bcargo\s+publish\b|\bgem\s+push\b"),
]

SHELL_RULES = [(rid, dec, reason, re.compile(rx, re.IGNORECASE)) for rid, dec, reason, rx in _RAW_SHELL_RULES]

# ---------------------------------------------------------------------------
# Secret patterns: (label, compiled regex, group to replace or 0 for whole match)
# ---------------------------------------------------------------------------
_RAW_SECRET_PATTERNS = [
    ("private-key", r"-----BEGIN[ A-Z0-9]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z0-9]*PRIVATE KEY-----", 0),
    ("aws-access-key-id", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b", 0),
    ("aws-secret-key", r"(?i)\baws_?secret_?access_?key\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})", 1),
    ("github-token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b", 0),
    ("azure-storage-key", r"(?i)\b(?:AccountKey|SharedAccessKey)=([A-Za-z0-9+/]{20,}={0,2})", 1),
    ("azure-sas-signature", r"(?i)[?&]sig=([A-Za-z0-9%+/=]{20,})", 1),
    ("slack-token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b", 0),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b", 0),
    ("stripe-key", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b", 0),
    ("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b", 0),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", 0),
    ("url-credentials", r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:([^@\s/]{3,})@", 1),
    ("generic-secret-assignment",
     r"(?i)(?:^|[^a-z0-9_.\-])[a-z0-9_.\-]*"
     r"(?:password|passwd|pwd|secret|api_?key|apikey|access_?token|auth_?token|private_?key)"
     r"[a-z0-9_.\-]*[\"']?\s*[:=]\s*[\"']?([^\s\"'`;,]{8,})", 1),
]

SECRET_PATTERNS = [(label, re.compile(rx), grp) for label, rx, grp in _RAW_SECRET_PATTERNS]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def read_payload():
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    return json.loads(raw)


def emit(obj):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def get_first(d, *keys):
    for k in keys:
        if isinstance(d, dict) and k in d:
            return d[k]
    return None


def parse_maybe_json(value):
    if isinstance(value, str):
        s = value.strip()
        if s.startswith("{") or s.startswith("["):
            try:
                return json.loads(s)
            except ValueError:
                return value
    return value


def all_strings(value):
    """Collect every string inside a nested structure."""
    out = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(all_strings(v))
    elif isinstance(value, list):
        for v in value:
            out.extend(all_strings(v))
    return out


def extract_command(tool_args):
    """Return the shell command text from tool arguments.

    The hooks reference types toolArgs as 'unknown', so this accepts a dict with a
    'command'/'cmd'/'script' key, a JSON string, or a plain string. If no known key
    is present, every string value is scanned so nothing is silently skipped.
    """
    tool_args = parse_maybe_json(tool_args)
    if isinstance(tool_args, str):
        return tool_args
    if isinstance(tool_args, dict):
        cmd = get_first(tool_args, "command", "cmd", "script", "commandLine", "input")
        if isinstance(cmd, str):
            return cmd
        if isinstance(cmd, list):
            return " ".join(str(c) for c in cmd)
    return "\n".join(all_strings(tool_args))


def normalise(cmd, strip_escapes):
    """Reduce trivial obfuscation before matching: quotes, empty quotes, $IFS, whitespace.

    strip_escapes removes bash-style backslash escapes (r\\m -> rm). That would also
    mangle Windows paths, so commands are checked both with and without it.
    """
    s = cmd
    s = s.replace('""', "").replace("''", "")          # r""m -> rm
    if strip_escapes:
        s = re.sub(r"\\(?=[A-Za-z])", "", s)             # r\m -> rm
    s = s.replace('"', " ").replace("'", " ")
    s = re.sub(r"\$\{?IFS\}?", " ", s)                  # rm${IFS}-rf
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def evaluate_command(cmd):
    """Return (decision, rule_id, reason) or (None, None, None) if no rule matches. Deny beats ask."""
    variants = {normalise(cmd, False), normalise(cmd, True)}
    ask_hit = None
    for rid, decision, reason, rx in SHELL_RULES:
        if any(rx.search(v) for v in variants):
            if decision == "deny":
                return "deny", rid, reason
            if ask_hit is None:
                ask_hit = ("ask", rid, reason)
    return ask_hit if ask_hit else (None, None, None)


def redact(text):
    """Return (redacted_text, [labels found])."""
    if not isinstance(text, str) or not text:
        return text, []
    found = []
    out = text
    for label, rx, grp in SECRET_PATTERNS:
        def _sub(m, label=label, grp=grp):
            found.append(label)
            if grp == 0:
                return "[REDACTED:%s]" % label
            start, end = m.span(grp)
            s0 = m.start(0)
            whole = m.group(0)
            return whole[: start - s0] + "[REDACTED:%s]" % label + whole[end - s0:]
        out = rx.sub(_sub, out)
    return out, sorted(set(found))


def audit(event, detail):
    """Optional append-only audit log. Set COPILOT_POLICY_AUDIT_LOG to a path to enable."""
    path = os.environ.get("COPILOT_POLICY_AUDIT_LOG")
    if not path:
        return
    try:
        rec = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, "version": VERSION}
        rec.update(detail)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass  # never let logging break the hook


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
def mode_pre_tool(p):
    tool = get_first(p, "toolName", "tool_name") or ""
    if tool not in SHELL_TOOLS:
        return  # only shell tools are inspected; file access is covered by managed deny rules
    cmd = extract_command(get_first(p, "toolArgs", "tool_input"))
    decision, rid, reason = evaluate_command(cmd)
    if decision is None:
        return
    audit("preToolUse", {"decision": decision, "rule": rid, "tool": tool, "sessionId": p.get("sessionId")})
    emit({"permissionDecision": decision, "permissionDecisionReason": "[%s] %s" % (rid, reason)})


def mode_post_tool(p):
    result = get_first(p, "toolResult", "tool_result") or {}
    text = get_first(result, "textResultForLlm", "text_result_for_llm")
    new_text, found = redact(text)
    if not found:
        return
    audit("postToolUse", {"redacted": found, "tool": get_first(p, "toolName", "tool_name")})
    emit({"modifiedResult": {"resultType": "success", "textResultForLlm": new_text}})


def mode_prompt(p):
    text = p.get("transformedPrompt")
    new_text, found = redact(text)
    if not found or not new_text:
        return
    audit("userPromptTransformed", {"redacted": found, "sessionId": p.get("sessionId")})
    emit({"modifiedTransformedPrompt": new_text})


def mode_permission(p):
    tool_input = parse_maybe_json(get_first(p, "toolInput", "tool_input", "toolArgs")) or {}
    if isinstance(tool_input, dict) and tool_input.get("requestSandboxBypass") is True:
        audit("permissionRequest", {"decision": "deny", "rule": "sandbox-bypass",
                                    "tool": get_first(p, "toolName", "tool_name")})
        emit({"behavior": "deny", "message": "Running outside the sandbox is not permitted by policy."})


def mode_capture(p):
    path = os.environ.get("COPILOT_POLICY_CAPTURE_LOG")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "payload": p}) + "\n")
    except OSError:
        pass


MODES = {
    "pre-tool": mode_pre_tool,
    "post-tool": mode_post_tool,
    "prompt": mode_prompt,
    "permission": mode_permission,
    "capture": mode_capture,
}


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--version":
        print(VERSION)
        return 0
    handler = MODES.get(mode)
    if handler is None:
        sys.stderr.write("copilot_policy_guard: unknown mode %r\n" % mode)
        return 2 if mode == "pre-tool" else 1
    try:
        handler(read_payload())
        return 0
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write("copilot_policy_guard %s error: %s\n" % (mode, exc))
        # Exit 2 on pre-tool makes Copilot CLI deny the tool call (fail-closed).
        return 2 if mode == "pre-tool" else 1


if __name__ == "__main__":
    sys.exit(main())
