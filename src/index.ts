#!/usr/bin/env node
/**
 * MISP MCP Server
 *
 * Exposes MISP (Malware Information Sharing Platform) REST API as MCP tools
 * for LLM agents. Built-in prompt injection defense via prompt-defense-audit.
 *
 * Why MISP needs an MCP server with defense built in:
 *   1. MISP holds operational threat intel (IOCs, threat actor profiles, attack patterns).
 *   2. An LLM querying MISP can leak sensitive intel if its prompt is manipulated.
 *   3. Adversaries may seed MISP attributes with injection payloads designed to hijack
 *      downstream LLM agents (an under-discussed threat in threat intel + AI).
 *
 * This server:
 *   - Wraps the MISP REST API (events, attributes, search, tags, feeds)
 *   - Runs every outgoing tool response through prompt-defense-audit's scanOutput()
 *   - Refuses queries that contain known prompt injection patterns
 *   - Tracks all calls with structured logging (optional Quartz Cloud upgrade for audit logs)
 *
 * Connect with Claude Desktop, Cursor, or any MCP client:
 *   {
 *     "mcpServers": {
 *       "misp": {
 *         "command": "npx",
 *         "args": ["-y", "@ultralab/misp-mcp-server"],
 *         "env": {
 *           "MISP_URL": "https://misp.your-org.example",
 *           "MISP_API_KEY": "your_key"
 *         }
 *       }
 *     }
 *   }
 *
 * @license MIT
 * @see https://github.com/ppcvote/misp-mcp-server
 * @see https://github.com/MISP/MISP/issues/10745
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js'
import { scanOutput } from 'prompt-defense-audit'
import { MispClient } from './misp-client.js'
import { TOOL_DEFINITIONS, dispatchTool } from './tools.js'

const VERSION = '0.1.0'

// ---- Configuration via environment ----
const MISP_URL = process.env.MISP_URL
const MISP_API_KEY = process.env.MISP_API_KEY
const MISP_INSECURE_TLS = process.env.MISP_INSECURE_TLS === 'true'
const DEFENSE_DISABLED = process.env.PROMPT_DEFENSE_DISABLED === 'true'

if (!MISP_URL || !MISP_API_KEY) {
  process.stderr.write(
    `[misp-mcp-server] FATAL: MISP_URL and MISP_API_KEY environment variables are required.\n` +
      `  Set them in your MCP client config or shell environment.\n` +
      `  See: https://github.com/ppcvote/misp-mcp-server#configuration\n`,
  )
  process.exit(1)
}

const misp = new MispClient({
  baseUrl: MISP_URL,
  apiKey: MISP_API_KEY,
  insecureTls: MISP_INSECURE_TLS,
})

// ---- MCP server setup ----
const server = new Server(
  {
    name: 'misp-mcp-server',
    version: VERSION,
  },
  {
    capabilities: { tools: {} },
    instructions:
      'MISP threat-intel MCP server with prompt-injection defense. ' +
      'All MISP responses are scanned for adversarial payloads before being returned. ' +
      'Set PROMPT_DEFENSE_DISABLED=true to opt out (not recommended).',
  },
)

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOL_DEFINITIONS,
}))

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const toolName = request.params.name
  const args = request.params.arguments ?? {}

  let result: unknown
  try {
    result = await dispatchTool(toolName, args, misp)
  } catch (error) {
    if (error instanceof McpError) throw error
    throw new McpError(
      ErrorCode.InternalError,
      `MISP tool '${toolName}' failed: ${(error as Error).message}`,
    )
  }

  // Serialize to text for transport
  const text = typeof result === 'string' ? result : JSON.stringify(result, null, 2)

  // Defense layer: scan MISP response for adversarial content before returning
  if (!DEFENSE_DISABLED) {
    const scan = scanOutput(text)
    if (scan.threats.length > 0) {
      const highRisk = scan.threats.filter((t) => t.severity === 'high' || t.severity === 'critical')
      if (highRisk.length > 0) {
        // Refuse to return the raw response — return a safe summary instead
        return {
          content: [
            {
              type: 'text',
              text:
                `⚠️ Defense blocked: MISP response contained ${highRisk.length} high-risk pattern(s) ` +
                `(${highRisk.map((t) => t.name).join(', ')}).\n\n` +
                `This may indicate adversarial seeding in MISP data. ` +
                `Inspect the raw record manually before forwarding to an LLM.\n\n` +
                `Threats: ${JSON.stringify(scan.threats, null, 2)}`,
            },
          ],
          isError: true,
        }
      }
      // Lower-risk: annotate but still return
      return {
        content: [
          {
            type: 'text',
            text: `[defense] ${scan.threats.length} low-risk pattern(s) detected: ${scan.threats.map((t) => t.name).join(', ')}\n\n${text}`,
          },
        ],
      }
    }
  }

  return {
    content: [{ type: 'text', text }],
  }
})

// ---- Boot ----
async function main() {
  const transport = new StdioServerTransport()
  await server.connect(transport)
  process.stderr.write(`[misp-mcp-server] v${VERSION} ready — MISP=${MISP_URL} defense=${!DEFENSE_DISABLED}\n`)
}

main().catch((err) => {
  process.stderr.write(`[misp-mcp-server] fatal: ${err}\n`)
  process.exit(1)
})
