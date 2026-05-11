# MISP MCP Server

[![npm version](https://img.shields.io/npm/v/@ultralab/misp-mcp-server.svg)](https://www.npmjs.com/package/@ultralab/misp-mcp-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/Model%20Context%20Protocol-1.0-blue)](https://modelcontextprotocol.io)

A **Model Context Protocol** server for [MISP](https://www.misp-project.org/) (Malware Information Sharing Platform), with **built-in prompt injection defense** powered by [`prompt-defense-audit`](https://www.npmjs.com/package/prompt-defense-audit).

> **Why this exists:** MISP holds operational threat intel — IOCs, threat actor profiles, attack patterns. When you connect an LLM agent to MISP via MCP, two new attack surfaces emerge:
>
> 1. **Adversarial seeding.** A threat actor who can submit content into your MISP instance (or a federated feed) can plant prompt-injection payloads designed to hijack downstream LLM agents.
> 2. **Sensitive intel leakage.** A manipulated LLM can be coerced into returning intel above its authorized TLP level.
>
> This server wraps every outgoing MISP response in `prompt-defense-audit`'s output scanner, blocking high-risk patterns before they reach the LLM. Read-only by design — no write tools exposed.

Tracks: [MISP/MISP#10745 — MCP server for MISP](https://github.com/MISP/MISP/issues/10745)

---

## Features

- 🛡️ **Defense built in** — every MISP response scanned for prompt-injection / XSS / shell-injection patterns before being returned
- 🔒 **Read-only by design** — no event/attribute mutation tools; an LLM cannot modify your threat-intel platform
- 🧰 **8 high-utility tools** covering events, attributes, search, tags, feeds, galaxies
- ⚡ **Zero-config** beyond `MISP_URL` and `MISP_API_KEY`
- 🪶 **Stdio transport** — works with Claude Desktop, Cursor, Continue, Cline, any MCP client
- 📋 **MIT license** — fork freely, use commercially

---

## Quick start

### 1. Install

```bash
npm install -g @ultralab/misp-mcp-server
```

Or use `npx` directly in your MCP client config (no install needed).

### 2. Configure your MCP client

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%/Claude/claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "misp": {
      "command": "npx",
      "args": ["-y", "@ultralab/misp-mcp-server"],
      "env": {
        "MISP_URL": "https://misp.your-org.example",
        "MISP_API_KEY": "your_misp_api_key_here"
      }
    }
  }
}
```

**Cursor / Continue / Cline** — similar pattern, see your client's MCP config docs.

### 3. Restart your MCP client and start asking

```
"What MISP events are tagged tlp:white from the last 7 days?"
"Show me event 12345 — I'm investigating a phishing report."
"What threat actor galaxies do we have configured?"
"Find all attributes matching the IP 198.51.100.42."
```

---

## Tools exposed

| Tool | Purpose |
|------|---------|
| `misp_version` | Health check + server version |
| `misp_list_events` | Paginated event headers |
| `misp_get_event` | Full event with attributes (scanned for injection) |
| `misp_search_events` | Search by tag / type / value / date range |
| `misp_search_attributes` | Direct IOC lookup |
| `misp_list_tags` | All configured tags (TLP, taxonomy, etc.) |
| `misp_list_feeds` | Configured threat-intel feeds |
| `misp_list_galaxies` | Threat actor / campaign clusters |

> **Mutation tools intentionally not included.** An LLM with write access to MISP is a supply-chain compromise vector. If you need agent-driven MISP mutations, build a per-tool allowlist with human-in-the-loop confirmation.

---

## Defense layer

Every tool response is run through [`prompt-defense-audit`'s `scanOutput`](https://github.com/ppcvote/prompt-defense-audit) before being returned to the LLM client.

**High-risk patterns** (`critical` / `high` severity) — response is **blocked** and replaced with a safe summary. Example trigger patterns:

- Script-tag injection (`<script>...</script>`)
- Iframe / object injection
- JavaScript URLs (`javascript:`)
- Shell-command patterns in unexpected contexts
- Known prompt-injection vector signatures from `prompt-defense-audit`'s 17+ vector library

**Low/medium-risk patterns** — response annotated with a `[defense]` prefix listing matched patterns but still returned.

### Opt out (not recommended)

```bash
PROMPT_DEFENSE_DISABLED=true
```

Use only if you fully trust your MISP instance + all federated feeds and need raw response fidelity for a specific debugging scenario.

---

## Environment variables

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `MISP_URL` | ✅ | — | Base URL of your MISP instance (e.g. `https://misp.example.com`) |
| `MISP_API_KEY` | ✅ | — | MISP automation API key (Profile → Auth Keys) |
| `MISP_INSECURE_TLS` | ❌ | `false` | Set to `true` only for self-signed dev instances |
| `PROMPT_DEFENSE_DISABLED` | ❌ | `false` | Set `true` to skip output scanning (NOT recommended) |

---

## For enterprise users

The free OSS defense layer ships with `prompt-defense-audit` (17+ regex-based vectors, ~3ms latency, deterministic).

For deployments that need:

- 🔍 **Persistent audit logs** of every MISP query an LLM has made
- 👥 **Team policies** (per-role allowlists, per-TLP gating, escalation flows)
- 🌏 **Jurisdictional compliance** (EU GDPR / TW 個資法 / 中國 PIPL data-residency)
- 🚨 **Live threat intel** updates to the defense ruleset (new injection vectors pushed daily)
- 📊 **SLA-backed** uptime and response

→ Upgrade path: route MCP server through [**Quartz Cloud**](https://quartz.tw) — Taiwan-domiciled runtime AI firewall, drop-in passthrough.

---

## Development

```bash
git clone https://github.com/ppcvote/misp-mcp-server.git
cd misp-mcp-server
npm install
npm test            # smoke tests, no live MISP
npm run dev         # tsx watch mode
npm run build       # produce dist/
```

### Architecture

```
LLM client (Claude Desktop, Cursor, etc.)
    │ stdio
    ▼
@ultralab/misp-mcp-server
    │
    ├─ src/tools.ts       — 8 read-only tool definitions + dispatch
    ├─ src/misp-client.ts — minimal MISP REST API wrapper
    └─ src/index.ts       — MCP Server + scanOutput() defense layer
    │
    ▼
MISP REST API (/events, /attributes, /tags, /feeds, /galaxies)
```

---

## Project context

Built by [Ultra Lab](https://ultralab.tw) — a one-person AI products company in Taiwan, focused on AI safety, threat intel, and the supply chain between LLM agents and operational security tooling.

This server is part of a broader thesis: **the MCP ecosystem will be a major prompt-injection vector unless servers default to defensive output handling.** We're shipping reference implementations for high-leverage targets (MISP first, OpenCTI / TheHive / Vault next) to anchor the standard.

Companion projects:
- [`prompt-defense-audit`](https://www.npmjs.com/package/prompt-defense-audit) — the underlying detection engine
- [`ultraprobe`](https://www.npmjs.com/package/ultraprobe) — CLI scanner for AI app system prompts
- [`quartz.tw`](https://quartz.tw) — paid runtime firewall (audit logs, team policies, jurisdictional moat)

---

## License

MIT © 2026 Ultra Lab — see [LICENSE](LICENSE).

## Contributing

PRs welcome. Please:

1. Keep the read-only invariant. Mutation tools must be argued explicitly with a threat-model writeup.
2. Add a test for any new tool.
3. If you add new MISP API coverage, link to the relevant OpenAPI spec section in your PR.

For discussion, see [MISP/MISP#10745](https://github.com/MISP/MISP/issues/10745).
