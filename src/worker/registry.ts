// Sync from the official MCP Registry (registry.modelcontextprotocol.io) into a queue of servers
// to check. Only the latest, active version of each server with a public remote URL is kept, and
// servers that need a per-user key (required headers, URL placeholders, query strings) are skipped,
// since they can't be graded fairly without credentials.
import { USER_AGENT } from '../mcp/wire'
import { checkTarget } from '../security/target'
import { canonicalUrl, ensureSchema, serverId } from './store'

export const REGISTRY_API = 'https://registry.modelcontextprotocol.io/v0/servers'
const PAGE_SIZE = 100 // the registry's maximum
/** Pages read per cron run. One page uses about 7 ms of CPU, and the free plan allows 10 ms a run. */
const PAGES_PER_RUN = 1
const SYNC_EVERY_MS = 7 * 24 * 60 * 60 * 1000

export interface Candidate {
  url: string
  host: string
  registryName: string
  title: string | null
  description: string | null
  version: string | null
  repositoryUrl: string | null
  websiteUrl: string | null
}

type Json = Record<string, unknown>
const str = (v: unknown, max = 500): string | null => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null)
const httpsUrl = (v: unknown): string | null => {
  const s = str(v, 300)
  if (!s) return null
  try {
    return new URL(s).protocol === 'https:' ? s : null
  } catch {
    return null
  }
}

/** A registry server that can't be checked without a per-user credential. */
export interface KeyedServer {
  registryName: string
  url: string
  /** What it needs: a required header, a URL placeholder, or a query string. */
  reason: 'header' | 'placeholder' | 'query'
  title: string | null
  description: string | null
  repositoryUrl: string | null
  websiteUrl: string | null
}

/**
 * Does a registry name's namespace prove it belongs to this host? Reverse-DNS namespaces are verified
 * by the registry through DNS or HTTP on that domain (com.example/x covers example.com and its
 * subdomains); io.github.* namespaces only prove a GitHub account.
 */
export function nsMatchesHost(registryName: string, host: string): boolean {
  const ns = registryName.split('/')[0]?.toLowerCase() ?? ''
  if (!ns || ns.startsWith('io.github.')) return false
  const domain = ns.split('.').reverse().join('.')
  const h = host.toLowerCase()
  return h === domain || h.endsWith(`.${domain}`)
}

/**
 * The registry's website and source links for a server, kept only when they plausibly belong to it:
 * anything when the namespace proves the domain, the server's own site, or (for io.github.<user>)
 * that user's GitHub repositories. Anyone can publish a registry entry pointing at any URL.
 */
export function trustedRegistryLinks(registryName: string, serverUrl: string, websiteUrl: string | null, repositoryUrl: string | null): { websiteUrl: string | null; repositoryUrl: string | null } {
  let host = ''
  try {
    host = new URL(serverUrl).hostname.toLowerCase()
  } catch {
    return { websiteUrl: null, repositoryUrl: null }
  }
  const proven = nsMatchesHost(registryName, host)
  const user = registryName.match(/^io\.github\.([a-z0-9-]+)\//i)?.[1]?.toLowerCase()
  const site = (u: string) => {
    try {
      const h = new URL(u).hostname.toLowerCase()
      return proven || h === host || host.endsWith(`.${h}`) || h.endsWith(`.${host}`)
    } catch {
      return false
    }
  }
  const repo = (u: string) => {
    try {
      const p = new URL(u)
      return proven || (!!user && p.hostname.toLowerCase() === 'github.com' && p.pathname.toLowerCase().startsWith(`/${user}/`))
    } catch {
      return false
    }
  }
  return { websiteUrl: websiteUrl && site(websiteUrl) ? websiteUrl : null, repositoryUrl: repositoryUrl && repo(repositoryUrl) ? repositoryUrl : null }
}

/**
 * Turn one registry page into check candidates, plus the servers that need a per-user credential
 * (kept privately: they're the servers most likely to want to charge for their tools). Pure, so it
 * can be tested.
 */
export function parseRegistryPage(page: unknown): { candidates: Candidate[]; keyed: KeyedServer[]; nextCursor?: string } {
  const data = (page ?? {}) as { servers?: unknown; metadata?: Json }
  const candidates: Candidate[] = []
  const keyed: KeyedServer[] = []
  for (const item of Array.isArray(data.servers) ? (data.servers as Json[]) : []) {
    const meta = ((item._meta as Json | undefined)?.['io.modelcontextprotocol.registry/official'] ?? {}) as Json
    if (meta.isLatest !== true) continue
    if (meta.status !== undefined && meta.status !== 'active') continue
    const server = (item.server ?? {}) as Json
    const remotes = Array.isArray(server.remotes) ? (server.remotes as Json[]) : []
    const repo = server.repository as Json | undefined
    let needs: KeyedServer | undefined
    let found = false
    for (const remote of remotes) {
      if (remote.type !== 'streamable-http' && remote.type !== 'sse') continue
      const raw = typeof remote.url === 'string' ? remote.url : ''
      // Required headers, URL placeholders and query strings mean a per-user key we don't have.
      const reason: KeyedServer['reason'] | undefined =
        Array.isArray(remote.headers) && (remote.headers as Json[]).some((h) => h?.isRequired === true) ? 'header'
          : /[{}]/.test(raw) ? 'placeholder'
            : raw.includes('?') ? 'query'
              : undefined
      if (reason) {
        if (/^https:\/\//i.test(raw)) {
          needs ??= {
            registryName: String(server.name ?? '').slice(0, 200), url: raw.slice(0, 500), reason,
            title: str(server.title, 120), description: str(server.description, 400),
            repositoryUrl: httpsUrl(repo?.url), websiteUrl: httpsUrl(server.websiteUrl),
          }
        }
        continue
      }
      if (!raw || raw.includes('#')) continue
      if (!checkTarget(raw).ok) continue
      const canonical = canonicalUrl(raw)
      if (!canonical.ok) continue
      found = true
      candidates.push({
        url: canonical.url,
        host: new URL(canonical.url).hostname,
        registryName: String(server.name ?? '').slice(0, 200),
        title: str(server.title, 120),
        description: str(server.description, 400),
        version: str(server.version, 50),
        repositoryUrl: httpsUrl(repo?.url),
        websiteUrl: httpsUrl(server.websiteUrl),
      })
      break // one URL per server
    }
    // Only servers with no usable public URL at all count as needing a key.
    if (!found && needs && needs.registryName) keyed.push(needs)
  }
  const next = typeof data.metadata?.nextCursor === 'string' && data.metadata.nextCursor ? data.metadata.nextCursor : undefined
  return { candidates, keyed, ...(next ? { nextCursor: next } : {}) }
}

async function setting(db: D1Database, key: string): Promise<string | null> {
  return db.prepare(`SELECT value FROM settings WHERE key = ?`).bind(key).first<string>('value')
}
function putSetting(db: D1Database, key: string, value: string | null) {
  return value === null
    ? db.prepare(`DELETE FROM settings WHERE key = ?`).bind(key)
    : db.prepare(`INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = ?2`).bind(key, value)
}

/** Is a registry sync in progress or due? */
export async function syncDue(db: D1Database, now = Date.now()): Promise<boolean> {
  await ensureSchema(db)
  if (await setting(db, 'registry_cursor')) return true
  const last = await setting(db, 'registry_synced_at')
  return !last || now - Date.parse(last) > SYNC_EVERY_MS
}

/** Read a few pages of the registry and queue their servers. `done` is true when the sync is complete. */
export async function syncStep(db: D1Database, fetchImpl: typeof fetch = fetch, pages = PAGES_PER_RUN): Promise<{ added: number; done: boolean }> {
  let added = 0
  for (let i = 0; i < pages; i++) {
    const page = await syncPage(db, fetchImpl)
    added += page.added
    if (page.done) return { added, done: true }
  }
  return { added, done: false }
}

async function syncPage(db: D1Database, fetchImpl: typeof fetch): Promise<{ added: number; done: boolean }> {
  await ensureSchema(db)
  const cursor = await setting(db, 'registry_cursor')
  // Only the latest version of each server; older versions would be skipped anyway.
  const qs = new URLSearchParams({ limit: String(PAGE_SIZE), version: 'latest', ...(cursor ? { cursor } : {}) })
  const res = await fetchImpl(`${REGISTRY_API}?${qs}`, { headers: { Accept: 'application/json', 'User-Agent': USER_AGENT }, signal: AbortSignal.timeout(20_000) })
  if (!res.ok) throw new Error(`registry HTTP ${res.status}`)
  const { candidates, keyed, nextCursor } = parseRegistryPage(await res.json())

  const now = new Date().toISOString()
  const statements: D1PreparedStatement[] = []
  for (const c of candidates) {
    const id = await serverId(c.url)
    statements.push(
      // Several registry entries can name the same URL (the registry doesn't check who owns it).
      // The entry already stored keeps it, unless a new one's namespace proves the server's domain
      // and the stored one's doesn't. The same entry is only rewritten when it changed.
      db.prepare(`INSERT INTO registry (url, id, host, registry_name, title, description, version, repository_url, website_url, first_seen_at, last_seen_at, ns_match)
                  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11)
                  ON CONFLICT (url) DO UPDATE SET
                    registry_name = CASE WHEN registry.registry_name = ?4 OR (?11 = 1 AND registry.ns_match = 0) THEN ?4 ELSE registry.registry_name END,
                    title = CASE WHEN registry.registry_name = ?4 OR (?11 = 1 AND registry.ns_match = 0) THEN ?5 ELSE registry.title END,
                    description = CASE WHEN registry.registry_name = ?4 OR (?11 = 1 AND registry.ns_match = 0) THEN ?6 ELSE registry.description END,
                    version = CASE WHEN registry.registry_name = ?4 OR (?11 = 1 AND registry.ns_match = 0) THEN ?7 ELSE registry.version END,
                    repository_url = CASE WHEN registry.registry_name = ?4 OR (?11 = 1 AND registry.ns_match = 0) THEN ?8 ELSE registry.repository_url END,
                    website_url = CASE WHEN registry.registry_name = ?4 OR (?11 = 1 AND registry.ns_match = 0) THEN ?9 ELSE registry.website_url END,
                    ns_match = CASE WHEN registry.registry_name = ?4 OR (?11 = 1 AND registry.ns_match = 0) THEN ?11 ELSE registry.ns_match END,
                    -- A proven owner settles it; two unproven claimants make it contested.
                    contested = CASE WHEN registry.registry_name != ?4 AND ?11 = 1 AND registry.ns_match = 0 THEN 0
                                     WHEN registry.registry_name != ?4 AND ?11 = 0 AND registry.ns_match = 0 THEN 1 ELSE registry.contested END,
                    last_seen_at = ?10
                  WHERE (registry.registry_name = ?4 AND (registry.title IS NOT ?5 OR registry.description IS NOT ?6 OR registry.version IS NOT ?7
                          OR registry.repository_url IS NOT ?8 OR registry.website_url IS NOT ?9))
                     OR (registry.registry_name != ?4 AND ?11 = 1 AND registry.ns_match = 0)
                     OR (registry.registry_name != ?4 AND ?11 = 0 AND registry.ns_match = 0 AND registry.contested = 0)`)
        .bind(c.url, id, c.host, c.registryName, c.title, c.description, c.version, c.repositoryUrl, c.websiteUrl, now, nsMatchesHost(c.registryName, c.host) ? 1 : 0),
      // Listed servers mirror whichever entry owns their URL, written only when it changed.
      db.prepare(`UPDATE servers SET registry_name = IIF(r.contested = 1, NULL, r.registry_name), description = IIF(r.contested = 1, NULL, r.description),
                    repository_url = IIF(r.contested = 1, NULL, r.repository_url), website_url = IIF(r.contested = 1, NULL, r.website_url)
                  FROM registry r
                  WHERE r.url = ?1 AND servers.id = r.id
                    AND (servers.registry_name IS NOT IIF(r.contested = 1, NULL, r.registry_name) OR servers.description IS NOT IIF(r.contested = 1, NULL, r.description)
                      OR servers.repository_url IS NOT IIF(r.contested = 1, NULL, r.repository_url) OR servers.website_url IS NOT IIF(r.contested = 1, NULL, r.website_url))`)
        .bind(c.url),
    )
  }
  for (const k of keyed) {
    statements.push(
      db.prepare(`INSERT INTO keyed_servers (registry_name, url, reason, title, description, repository_url, website_url, first_seen_at, last_seen_at)
                  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
                  ON CONFLICT (registry_name) DO UPDATE SET url = ?2, reason = ?3, title = ?4, description = ?5, repository_url = ?6, website_url = ?7, last_seen_at = ?8
                  WHERE keyed_servers.url IS NOT ?2 OR keyed_servers.reason IS NOT ?3 OR keyed_servers.title IS NOT ?4 OR keyed_servers.description IS NOT ?5
                     OR keyed_servers.repository_url IS NOT ?6 OR keyed_servers.website_url IS NOT ?7`)
        .bind(k.registryName, k.url, k.reason, k.title, k.description, k.repositoryUrl, k.websiteUrl, now),
    )
  }
  statements.push(putSetting(db, 'registry_cursor', nextCursor ?? null))
  if (!nextCursor) statements.push(putSetting(db, 'registry_synced_at', now))
  await db.batch(statements)
  return { added: candidates.length, done: !nextCursor }
}

export interface QueuedServer extends Candidate {
  id: string
  attempts: number
}

/**
 * The next registry servers to check: never checked, or a failed attempt over an hour ago. Each is
 * on a different host, and the host checked last is avoided unless nothing else is left, so no one
 * domain gets a burst of checks.
 */
export async function nextCandidates(db: D1Database, count: number): Promise<QueuedServer[]> {
  await ensureSchema(db)
  const lastHost = ''
  const retryBefore = retryCutoff()
  const { results } = await db
    .prepare(`SELECT r.url, r.id, r.host, IIF(r.contested = 1, NULL, r.registry_name) AS registry_name, r.title, IIF(r.contested = 1, NULL, r.description) AS description,
                     r.version, IIF(r.contested = 1, NULL, r.repository_url) AS repository_url, IIF(r.contested = 1, NULL, r.website_url) AS website_url, r.attempts
              FROM registry r LEFT JOIN servers s ON s.id = r.id
              WHERE r.status = 'pending' AND (r.last_attempt_at IS NULL OR r.last_attempt_at < ?1)
                AND (s.id IS NULL OR s.blocked = 0)
              ORDER BY r.attempts ASC, r.first_seen_at ASC LIMIT 10`)
    .bind(retryBefore)
    .all<{ url: string; id: string; host: string; registry_name: string; title: string | null; description: string | null; version: string | null; repository_url: string | null; website_url: string | null; attempts: number }>()
  return pickHosts(results, lastHost, count).map((row) => ({
    url: row.url, id: row.id, host: row.host, registryName: row.registry_name, title: row.title, description: row.description,
    version: row.version, repositoryUrl: row.repository_url, websiteUrl: row.website_url, attempts: row.attempts,
  }))
}

/** Up to `count` rows on different hosts, keeping their order, with `lastHost` only as a last resort. */
export function pickHosts<T extends { host: string }>(rows: T[], lastHost: string, count: number): T[] {
  const picked: T[] = []
  const hosts = new Set<string>()
  for (const row of [...rows.filter((r) => r.host !== lastHost), ...rows.filter((r) => r.host === lastHost)]) {
    if (picked.length >= count) break
    if (hosts.has(row.host)) continue
    hosts.add(row.host)
    picked.push(row)
  }
  return picked
}

/** A failed attempt can be retried after an hour. */
const retryCutoff = () => new Date(Date.now() - 60 * 60 * 1000).toISOString()

/**
 * Claim a server before checking it. Several cron runs check servers at the same time, so the
 * claim only succeeds if no other run has claimed it since it was picked. Marking the attempt
 * first also means a run that gets cut off doesn't block the queue.
 */
export async function claimAttempt(db: D1Database, c: QueuedServer): Promise<boolean> {
  const { meta } = await db
    .prepare(`UPDATE registry SET attempts = attempts + 1, last_attempt_at = ?2
              WHERE url = ?1 AND status = 'pending' AND (last_attempt_at IS NULL OR last_attempt_at < ?3)`)
    .bind(c.url, new Date().toISOString(), retryCutoff())
    .run()
  return meta.changes > 0
}

/** Checked and listed, or given up after three failed attempts. */
export async function finishAttempt(db: D1Database, c: QueuedServer, ok: boolean): Promise<void> {
  const status = ok ? 'checked' : c.attempts + 1 >= 3 ? 'skipped' : 'pending'
  await db.prepare(`UPDATE registry SET status = ?2 WHERE url = ?1`).bind(c.url, status).run()
}

export async function registryStats(db: D1Database): Promise<Record<string, number>> {
  await ensureSchema(db)
  const { results } = await db.prepare(`SELECT status, COUNT(*) AS n FROM registry GROUP BY status`).all<{ status: string; n: number }>()
  return Object.fromEntries(results.map((r) => [r.status, r.n]))
}
