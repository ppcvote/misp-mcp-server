/**
 * MCP tool definitions for MISP operations.
 *
 * Read-only by design. We intentionally do NOT expose:
 *   - Event creation / modification / deletion
 *   - Attribute creation / modification / deletion
 *   - Tag management
 *   - User / org management
 *
 * Rationale: an LLM with write access to your threat-intel platform is a
 * supply-chain compromise vector. If you need to mutate MISP from an agent,
 * implement a per-tool allowlist with human-in-the-loop confirmation.
 */

import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js'
import type { MispClient } from './misp-client.js'

export const TOOL_DEFINITIONS = [
  {
    name: 'misp_version',
    description:
      'Health check — return the MISP server version and capability flags. ' +
      'Use this to verify connectivity before issuing other queries.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: 'misp_list_events',
    description:
      'List MISP events (most recent first). Returns event headers (id, info, date, threat level, tags). ' +
      'For detailed attributes, call misp_get_event with an id. ' +
      'Default page size is 20; max 100.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
        page: { type: 'integer', minimum: 1, default: 1 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'misp_get_event',
    description:
      'Fetch a single MISP event by id, including its attributes (IOCs). ' +
      'The response is scanned for prompt-injection payloads before being returned.',
    inputSchema: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
          description: 'MISP event id (numeric or UUID)',
        },
      },
      required: ['id'],
      additionalProperties: false,
    },
  },
  {
    name: 'misp_search_events',
    description:
      'Search MISP events by tag, type, value, category, or date range. ' +
      'Useful for threat hunting (e.g. all events tagged with a CVE, or matching an IOC value).',
    inputSchema: {
      type: 'object',
      properties: {
        value: { type: 'string', description: 'IOC value to search for (substring match)' },
        type: { type: 'string', description: 'Attribute type (e.g. ip-src, domain, sha256)' },
        category: { type: 'string', description: 'Attribute category (e.g. Network activity, Payload delivery)' },
        tag: { type: 'string', description: 'Tag name (e.g. tlp:white, malware:trickbot)' },
        from: { type: 'string', description: 'Start date YYYY-MM-DD' },
        to: { type: 'string', description: 'End date YYYY-MM-DD' },
        limit: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'misp_search_attributes',
    description:
      'Search MISP attributes (IOCs) directly. ' +
      'Faster than searching events when you have a specific IOC type/value pair to look up.',
    inputSchema: {
      type: 'object',
      properties: {
        value: { type: 'string' },
        type: { type: 'string' },
        category: { type: 'string' },
        tag: { type: 'string' },
        limit: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'misp_list_tags',
    description:
      'List all tags configured on the MISP instance. ' +
      'Useful for discovering taxonomy values (TLP levels, malware families, campaign names) ' +
      'before running a tag-scoped search.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'misp_list_feeds',
    description:
      'List configured MISP threat-intel feeds (enabled and disabled). ' +
      'Use this to understand which external sources are feeding the instance.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'misp_list_galaxies',
    description:
      'List MISP galaxies (threat actor profiles, campaign clusters, technique catalogs). ' +
      'Galaxies are MISP\'s structured representation of MITRE ATT&CK, threat actors, etc.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
]

interface ToolArgs {
  [key: string]: unknown
}

export async function dispatchTool(name: string, args: ToolArgs, misp: MispClient): Promise<unknown> {
  switch (name) {
    case 'misp_version':
      return await misp.version()

    case 'misp_list_events':
      return await misp.listEvents(
        clampInt(args.limit, 1, 100, 20),
        clampInt(args.page, 1, 10000, 1),
      )

    case 'misp_get_event': {
      const id = String(args.id ?? '').trim()
      if (!id) throw new McpError(ErrorCode.InvalidParams, 'misp_get_event: id is required')
      return await misp.getEvent(id)
    }

    case 'misp_search_events':
      return await misp.searchEvents({
        value: optString(args.value),
        type: optString(args.type),
        category: optString(args.category),
        tag: optString(args.tag),
        from: optString(args.from),
        to: optString(args.to),
        limit: clampInt(args.limit, 1, 100, 20),
      })

    case 'misp_search_attributes':
      return await misp.searchAttributes({
        value: optString(args.value),
        type: optString(args.type),
        category: optString(args.category),
        tag: optString(args.tag),
        limit: clampInt(args.limit, 1, 100, 20),
      })

    case 'misp_list_tags':
      return await misp.listTags()

    case 'misp_list_feeds':
      return await misp.listFeeds()

    case 'misp_list_galaxies':
      return await misp.listGalaxies()

    default:
      throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`)
  }
}

function clampInt(v: unknown, min: number, max: number, fallback: number): number {
  const n = typeof v === 'number' ? v : typeof v === 'string' ? parseInt(v, 10) : NaN
  if (!Number.isFinite(n)) return fallback
  return Math.min(Math.max(Math.floor(n), min), max)
}

function optString(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined
  const trimmed = v.trim()
  return trimmed === '' ? undefined : trimmed
}
