/**
 * Smoke tests — no live MISP needed.
 *
 * For real MISP integration tests, set MISP_URL + MISP_API_KEY and run:
 *   npm run test:integration  (not added yet)
 */

import { describe, it, expect } from 'vitest'
import { TOOL_DEFINITIONS } from '../src/tools.js'

describe('misp-mcp-server', () => {
  describe('tool definitions', () => {
    it('exposes the 8 read-only tools', () => {
      const names = TOOL_DEFINITIONS.map((t) => t.name).sort()
      expect(names).toEqual([
        'misp_get_event',
        'misp_list_events',
        'misp_list_feeds',
        'misp_list_galaxies',
        'misp_list_tags',
        'misp_search_attributes',
        'misp_search_events',
        'misp_version',
      ])
    })

    it('does NOT expose any mutation tools', () => {
      const names = TOOL_DEFINITIONS.map((t) => t.name)
      const mutating = names.filter((n) =>
        /create|update|delete|add|remove|publish|modify/i.test(n),
      )
      expect(mutating).toEqual([])
    })

    it('every tool has a description and inputSchema', () => {
      for (const tool of TOOL_DEFINITIONS) {
        expect(tool.description).toBeTruthy()
        expect(tool.description.length).toBeGreaterThan(40)
        expect(tool.inputSchema).toBeDefined()
        expect(tool.inputSchema.type).toBe('object')
      }
    })

    it('descriptions mention prompt-injection defense where relevant', () => {
      const eventTool = TOOL_DEFINITIONS.find((t) => t.name === 'misp_get_event')!
      expect(eventTool.description).toMatch(/prompt-injection|injection|defense|scan/i)
    })
  })

  describe('prompt-defense-audit integration', () => {
    it('imports scanOutput', async () => {
      const { scanOutput } = await import('prompt-defense-audit')
      const result = scanOutput('hello world')
      expect(result).toBeDefined()
      expect(typeof result.safe).toBe('boolean')
    })

    it('flags a script-tag payload as unsafe', async () => {
      const { scanOutput } = await import('prompt-defense-audit')
      const result = scanOutput('Normal text <script>alert(1)</script> more text')
      expect(result.safe).toBe(false)
      expect(result.threats.length).toBeGreaterThan(0)
    })

    it('passes clean text', async () => {
      const { scanOutput } = await import('prompt-defense-audit')
      const result = scanOutput('IOC value: 192.0.2.1 (test address)')
      expect(result.safe).toBe(true)
    })
  })
})
