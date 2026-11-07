# Writing SecuScan v2 plugins

A plugin is **one TOML file** in `plugins/`. No code is ever executed from a plugin —
command templates and output parsers are data, validated at server startup. If anything
is inconsistent (an unknown placeholder, a bad regex, a template referencing a capture
group that doesn't exist), the plugin is rejected with a precise error instead of
misbehaving mid-scan.

Validate while developing:

```bash
cargo run -p secuscan-cli -- plugins validate plugins/my-plugin.toml
```

## Anatomy

```toml
# ── identity ─────────────────────────────────────────────────────────────
[plugin]
id = "my-scanner"                 # ^[a-z0-9][a-z0-9-]*$
name = "My Scanner"
version = "1.0.0"
description = "One line for cards and tables."
long_description = """Longer text shown in the task wizard."""
category = "web"                  # groups the catalogue (web/network/recon/…)
icon = "radar"                    # lucide icon name for the UI
difficulty = "intermediate"       # beginner | intermediate | advanced
tags = ["http", "fingerprint"]
author = "You"
license = "MIT"

# ── engine: how it runs ──────────────────────────────────────────────────
[engine]
type = "cli"                      # cli | native
binary = "mytool"                 # must equal argv[0]; availability-checked
timeout_seconds = 600
output_format = "text"            # text | json_lines
# Optional: non-zero exit codes your tool documents as non-error
# (grep-convention tools, severity-tiered exits like testssl.sh's 1-4).
# Any OTHER non-zero exit classifies the task as Failed (tool failure)
# while preserving captured output. Default: [] (only 0 is success).
ok_exit_codes = [1, 2]
argv = [
  "mytool",
  "-v",
  "--if:aggressive:then:--deep",            # conditional flag (bool/non-empty field)
  "--if:ports:then:-p:else:--top-ports",    # if / else
  "--if:ports:then:{ports}:else:100",       # substitution inside branches
  "{target}",                               # plain substitution
]

# ── form fields (rendered by the wizard, enforced by the backend) ────────
[[fields]]
id = "target"                     # every plugin MUST have exactly one
label = "Target URL"              # field named `target` or `url`
type = "string"                   # string | text | integer | boolean | select
required = true
pattern = '^[a-zA-Z0-9][a-zA-Z0-9.:/_?&=%#~-]*$'
message = "Must be a valid URL"

[[fields]]
id = "aggressive"
label = "Deep scan"
type = "boolean"
default = false

[[fields]]
id = "level"
label = "Level"
type = "select"
default = "1"
options = [ { value = "1", label = "Fast" }, { value = "2", label = "Deep" } ]

[[fields]]
id = "ports"
label = "Ports"
type = "string"
pattern = '^[0-9,\- ]*$'

[[fields]]
id = "threads"
label = "Threads"
type = "integer"
default = 10
min = 1
max = 100

# ── presets (one-click partial inputs in the wizard) ─────────────────────
[presets.quick]                   # top-level table, one sub-table per preset
ports = ""
aggressive = false

# ── output parsing ───────────────────────────────────────────────────────
[parser]
type = "line_regex"
pattern = '(?P<item>[^:]+):\s+(?P<detail>.+)$'
# Optional: lines matching any skip pattern are discarded BEFORE the main
# pattern runs. Use this to drop tool diagnostics and run metadata that
# would otherwise masquerade as findings (e.g. nikto's `+ ERROR:` lines).
skip_patterns = ['^\+\s+(ERROR|WARN):', '^== debug:']

[parser.finding]
title = "{item}"
description = "{detail}"
category = "My Scanner"
severity = "info"                 # critical|high|medium|low|info

[[parser.severity_rules]]         # elevate severity on captured values
field = "item"
values = ["CRITICAL-*", "CVE-*"]  # exact or glob
severity = "high"

# ── whole-output heuristics (any parser type) ────────────────────────────
[[static_rules]]
pattern = "(?i)kernel panic"
title = "Crash signature in output"
severity = "high"

# ── safety envelope ──────────────────────────────────────────────────────
[safety]
level = "safe"                    # safe | intrusive | exploit
requires_consent = true
consent_message = "Explain what the operator is agreeing to."
allowed_targets = ["127.0.0.1", "10.*.*.*", "192.168.0.0/16"]
max_concurrent = 2                # parallel tasks of this plugin
max_per_hour = 30                 # 0 = unlimited
capabilities = ["network"]        # denied capabilities block task creation

[dependencies]
binaries = ["mytool"]             # availability-checked at load & refresh
```

> **Preset tables:** `[presets.<name>]` is a top-level table (a sibling of `[plugin]`,
> `[engine]`, `[safety]`, not nested inside `[plugin]`). Each value must pass its
> field's validation — checked at load time.

## Command template semantics

- Tokens are **argv elements**, never a shell string — no quoting bugs, no injection.
- `{field}` — replaced with the field's value. If the element renders to the empty
  string it is dropped entirely (`-p {ports}` with empty ports never passes `-p ""`).
- `--if:field:then:X` — emits `X` when the field is truthy (bool true / non-empty
  string / non-zero integer), otherwise nothing.
- `--if:field:then:X:else:Y` — emits `X` or `Y`. Each conditional produces **one**
  argv element; use two tokens when a tool wants `-p 8080` as separate elements.
- Hardening: values beginning with `-` are rejected unless the field sets
  `allow_dash = true`; NUL bytes are always rejected; argv[0] must be a literal.

## Parser types

| type | behaviour |
|---|---|
| `passthrough` | capture output, no findings |
| `line_regex` | one finding per matching line; `{group}` substitution in templates; `severity_rules` (exact or glob) can only *elevate* severity; `metadata_fields` copies captures into finding metadata; `skip_patterns` drops diagnostic lines before the main pattern runs |
| `json_lines` | one finding per JSON-object line; dot-path field mapping (`title_field` required; optional `description_field`, `severity_field`, `url_field`, `proof_field`); `severity_map` translates the tool's own severities |

Static rules run against the whole output regardless of parser type — ideal for
markers like sqlmap's `is vulnerable` or nmap's `VULNERABLE`.

Findings are deduplicated (`severity+title+url`) and capped at 5 000 per task.

## Native plugins

Set `engine.type = "native"` and `engine.native = "port_scanner" | "http_headers" |
"http_recon" | "tls_check"`, then declare matching fields (see the shipped manifests).
Native scanners run in-process — no external binaries, no parser needed.

## Checklist before shipping a plugin

1. `secuscan plugins validate plugins/my-plugin.toml` passes.
2. Safety level honest: `exploit` for anything that actively attacks (sqlmap), `intrusive`
   for noisy/brute-force scans, `safe` for passive/observation.
3. `allowed_targets` set for network-layer plugins (default to private ranges).
4. Field patterns strict (allow only what the tool genuinely accepts).
5. Parser templates reference only real capture groups / JSON paths.
6. Consent message explains the impact on the target.
