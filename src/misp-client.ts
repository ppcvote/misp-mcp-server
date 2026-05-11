/**
 * Minimal MISP REST API client.
 *
 * Covers the read-heavy endpoints that LLM agents typically need.
 * Read-only by default — POST/PUT/DELETE are NOT exposed via the MCP server
 * (a malicious or hijacked LLM should not be able to modify your MISP instance).
 *
 * @see https://www.misp-project.org/openapi/
 */

interface MispClientOptions {
  baseUrl: string
  apiKey: string
  insecureTls?: boolean
}

export interface MispEvent {
  id: string
  uuid: string
  info: string
  date: string
  threat_level_id?: string
  analysis?: string
  attribute_count?: string
  Tag?: Array<{ name: string; colour: string }>
}

export interface MispAttribute {
  id: string
  uuid: string
  event_id: string
  type: string
  category: string
  value: string
  comment?: string
  to_ids?: boolean
}

export interface MispSearchParams {
  value?: string
  type?: string
  category?: string
  tag?: string
  from?: string
  to?: string
  limit?: number
  page?: number
}

export class MispClient {
  private baseUrl: string
  private apiKey: string
  private insecureTls: boolean

  constructor(options: MispClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    this.apiKey = options.apiKey
    this.insecureTls = options.insecureTls ?? false
    if (this.insecureTls) {
      // For self-signed MISP instances only — log so operators know
      process.stderr.write('[misp-client] WARN: TLS verification disabled (MISP_INSECURE_TLS=true)\n')
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
    }
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path}`
    const res = await fetch(url, {
      ...init,
      headers: {
        Authorization: this.apiKey,
        Accept: 'application/json',
        'Content-Type': 'application/json',
        ...(init.headers ?? {}),
      },
    })

    if (!res.ok) {
      const body = await res.text().catch(() => '')
      throw new Error(`MISP ${init.method ?? 'GET'} ${path} failed: ${res.status} ${res.statusText}${body ? ` — ${body.slice(0, 200)}` : ''}`)
    }

    return (await res.json()) as T
  }

  /** GET /servers/getVersion — health check + version */
  async version(): Promise<{ version: string; perm_sync: boolean; perm_sighting?: boolean }> {
    return this.request('/servers/getVersion.json')
  }

  /** GET /events/index — paginated event list */
  async listEvents(limit = 20, page = 1): Promise<MispEvent[]> {
    const data = await this.request<MispEvent[]>(`/events/index/limit:${limit}/page:${page}`)
    return data
  }

  /** GET /events/view/{id} */
  async getEvent(id: string | number): Promise<{ Event: MispEvent & { Attribute?: MispAttribute[] } }> {
    return this.request(`/events/view/${id}`)
  }

  /** POST /events/restSearch — flexible event search */
  async searchEvents(params: MispSearchParams): Promise<{ response: Array<{ Event: MispEvent }> }> {
    return this.request('/events/restSearch', {
      method: 'POST',
      body: JSON.stringify({ returnFormat: 'json', ...params }),
    })
  }

  /** POST /attributes/restSearch */
  async searchAttributes(params: MispSearchParams): Promise<{ response: { Attribute: MispAttribute[] } }> {
    return this.request('/attributes/restSearch', {
      method: 'POST',
      body: JSON.stringify({ returnFormat: 'json', ...params }),
    })
  }

  /** GET /tags */
  async listTags(): Promise<{ Tag: Array<{ id: string; name: string; colour: string }> }> {
    return this.request('/tags')
  }

  /** GET /feeds/index — configured threat-intel feeds */
  async listFeeds(): Promise<Array<{ Feed: { id: string; name: string; url: string; enabled: boolean } }>> {
    return this.request('/feeds/index')
  }

  /** GET /galaxies — threat actor / campaign clusters */
  async listGalaxies(): Promise<Array<{ Galaxy: { id: string; name: string; description: string } }>> {
    return this.request('/galaxies')
  }
}
