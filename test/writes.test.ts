// The database code against a real SQLite (Node's built-in one) with the real schema and migrations,
// counting every row each operation changes, triggers and the search index included. The free plan
// allows 100,000 row writes a day, so writes that change nothing must cost nothing.
import { DatabaseSync } from 'node:sqlite'
import { beforeAll, describe, expect, it } from 'vitest'
import type { Report } from '../src/checks/types'
import { checksAllowedNow, DAILY_CHECK_BUDGET, DAILY_WRITE_BUDGET, recordUsage, usedToday, WriteMeter } from '../src/worker/budget'
import { clearWebhooks, pruneEvents, subscribe } from '../src/worker/alerts'
import { finishSignIn } from '../src/worker/oauth'
import { consumeChallenge, createChallenge } from '../src/worker/owners'
import { loadPrivateReport, savePrivateReport } from '../src/worker/private'
import { nextCandidates, syncStep } from '../src/worker/registry'
import { saveReport, serverId } from '../src/worker/store'

/** Just enough of the D1 API over node:sqlite for the code under test. */
function d1(db: DatabaseSync): D1Database {
  type P = string | number | null | Uint8Array
  const norm = (v: unknown): P => (v === undefined ? null : typeof v === 'boolean' ? Number(v) : (v as P))
  const statement = (sql: string, params: unknown[] = []) => ({
    bind: (...p: unknown[]) => statement(sql, p),
    first: async (col?: string) => {
      const row = db.prepare(sql).get(...params.map(norm)) as Record<string, unknown> | undefined
      return row ? (col ? row[col] : row) : null
    },
    // Like D1, a statement in a batch reports its rows, or how many rows it changed.
    all: async () =>
      /^\s*select\b/i.test(sql) || /\breturning\b/i.test(sql)
        ? { results: db.prepare(sql).all(...params.map(norm)), success: true, meta: {} }
        : { results: [], success: true, meta: { changes: Number(db.prepare(sql).run(...params.map(norm)).changes) } },
    run: async () => ({ success: true, results: [], meta: { changes: Number(db.prepare(sql).run(...params.map(norm)).changes) } }),
  })
  return {
    prepare: (sql: string) => statement(sql),
    batch: async (stmts: ReturnType<typeof statement>[]) => {
      db.exec('BEGIN')
      try {
        const out = []
        for (const s of stmts) out.push(await s.all())
        db.exec('COMMIT')
        return out
      } catch (err) {
        db.exec('ROLLBACK')
        throw err
      }
    },
  } as unknown as D1Database
}

const raw = new DatabaseSync(':memory:')
const DB = d1(raw)
const totalChanges = () => Number((raw.prepare('SELECT total_changes() AS n').get() as { n: number }).n)
async function rowsWritten(fn: () => Promise<unknown>): Promise<number> {
  const before = totalChanges()
  await fn()
  return totalChanges() - before
}
const searchHits = (term: string) => raw.prepare(`SELECT id FROM server_search WHERE server_search MATCH ?`).all(term).map((r) => (r as { id: string }).id)

const report = (over: Partial<Report> = {}): Report => ({
  url: 'https://mcp.example.com/mcp', checkedAt: '2026-11-23T00:00:00.000Z', durationMs: 100, connected: true, authenticated: false,
  era: 'modern', version: '2026-07-28', steps: [], prompts: [], resources: [], resourceTemplates: [],
  tools: [{ name: 'send_email', description: 'Send an email to someone.' }],
  checks: [{ id: 'protocol.era', category: 'protocol', title: 'Speaks the current spec', status: 'pass', weight: 3, detail: 'ok' }],
  score: 100, grade: 'A', gradingVersion: 2, ...over,
})
const registry = { registryName: 'com.example/mail', description: 'Sends mail.', repositoryUrl: null, websiteUrl: null }
const URL_ = 'https://mcp.example.com/mcp'
// The real id (derived from the URL), so the registry sync finds the same server.
let ID = ''

beforeAll(async () => {
  ID = await serverId(URL_)
  // First use creates the schema and runs every migration, as in production.
  await saveReport(DB, ID, URL_, report(), { list: true, registry })
})

describe('saving reports', () => {
  it('indexes a new server for search, with its registry details', () => {
    expect(searchHits('mail')).toEqual([ID])
    expect(searchHits('send_email')).toEqual([ID])
  })

  it('re-saving an unchanged server writes only its own row', async () => {
    const n = await rowsWritten(() => saveReport(DB, ID, URL_, report({ checkedAt: '2026-11-30T00:00:00.000Z' }), { list: true, registry }))
    expect(n).toBe(1)
  })

  it('a re-check without registry details keeps them', async () => {
    await saveReport(DB, ID, URL_, report({ checkedAt: '2026-12-01T00:00:00.000Z' }))
    expect(raw.prepare(`SELECT registry_name, description FROM servers WHERE id = ?`).get(ID)).toEqual({ registry_name: 'com.example/mail', description: 'Sends mail.' })
  })

  it('rebuilds the search entry when indexed text changes', async () => {
    const n = await rowsWritten(() => saveReport(DB, ID, URL_, report({ checkedAt: '2026-12-02T00:00:00.000Z', tools: [{ name: 'list_calendars', description: 'List calendars.' }] })))
    expect(n).toBeGreaterThan(1)
    expect(searchHits('calendars')).toEqual([ID])
    expect(searchHits('send_email')).toEqual([])
  })
})

describe('reports that must not replace the stored one', () => {
  it('an older report (a replayed receipt) is kept out and writes nothing', async () => {
    let result: Awaited<ReturnType<typeof saveReport>> | undefined
    const n = await rowsWritten(async () => (result = await saveReport(DB, ID, URL_, report({ checkedAt: '2026-01-01T00:00:00.000Z', grade: 'F', score: 10 }))))
    expect(n).toBe(0)
    expect(result).toMatchObject({ saved: false, listed: true })
    expect(raw.prepare(`SELECT grade FROM servers WHERE id = ?`).get(ID)).toEqual({ grade: 'A' })
  })

  it('a report made with credentials or custom headers never replaces a public listing', async () => {
    const result = await saveReport(DB, ID, URL_, report({ checkedAt: '2027-01-01T00:00:00.000Z', authenticated: true, grade: 'D', score: 61 }))
    expect(result).toMatchObject({ saved: false, listed: true })
    expect(raw.prepare(`SELECT grade, listed FROM servers WHERE id = ?`).get(ID)).toEqual({ grade: 'A', listed: 1 })
  })
})

describe('registry sync', () => {
  const page = {
    servers: [{
      server: { name: 'com.example/mail', title: 'Mail', description: 'Sends mail.', version: '1.0.0', remotes: [{ type: 'streamable-http', url: 'https://mcp.example.com/mcp' }] },
      _meta: { 'io.modelcontextprotocol.registry/official': { status: 'active', isLatest: true } },
    }],
    metadata: {},
  }
  const serve = (body: unknown) => (async () => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } })) as unknown as typeof fetch

  it('writes nothing for entries that did not change', async () => {
    await syncStep(DB, serve(page))
    const n = await rowsWritten(() => syncStep(DB, serve(page)))
    // Only the sync's own bookkeeping (cursor cleared, finish time) is written.
    expect(n).toBeLessThanOrEqual(2)
  })

  it('updates entries that did change', async () => {
    const changed = structuredClone(page)
    changed.servers[0]!.server.description = 'Sends and reads mail.'
    await syncStep(DB, serve(changed))
    expect(raw.prepare(`SELECT description FROM registry WHERE url = 'https://mcp.example.com/mcp'`).get()).toEqual({ description: 'Sends and reads mail.' })
    expect(raw.prepare(`SELECT description FROM servers WHERE id = ?`).get(ID)).toEqual({ description: 'Sends and reads mail.' })
    expect(searchHits('reads')).toEqual([ID])
  })
})

describe('daily budgets', () => {
  it('spread checks evenly across the day and stop at the write budget', () => {
    const at = (time: string) => Date.parse(`2026-11-24T${time}Z`)
    expect(DAILY_CHECK_BUDGET).toBe(600)
    expect(checksAllowedNow({ checks: 0, rows: 0 }, at('00:00:00'))).toBe(1)
    expect(checksAllowedNow({ checks: 0, rows: 0 }, at('12:00:00'))).toBe(301)
    expect(checksAllowedNow({ checks: 301, rows: 0 }, at('12:00:00'))).toBe(0)
    expect(checksAllowedNow({ checks: 599, rows: 0 }, at('23:59:59'))).toBe(1)
    expect(checksAllowedNow({ checks: 600, rows: 0 }, at('23:59:59'))).toBe(0)
    expect(checksAllowedNow({ checks: 0, rows: DAILY_WRITE_BUDGET }, at('12:00:00'))).toBe(0)
  })

  it('record a run in one write (none when it did nothing), and start again each day', async () => {
    const now = Date.now()
    const before = await usedToday(DB, now)
    expect(await rowsWritten(() => recordUsage(DB, before, 0, 0, now))).toBe(0)
    expect(await rowsWritten(() => recordUsage(DB, before, 2, 40, now))).toBe(1)
    // The record's own write counts too.
    expect(await usedToday(DB, now)).toEqual({ checks: before.checks + 2, rows: before.rows + 41 })
    expect(await usedToday(DB, now + 86_400_000)).toEqual({ checks: 0, rows: 0 })
  })

  it('meter every row written through them, in batches and with first()', async () => {
    const meter = new WriteMeter()
    const db = meter.db(DB)
    await db.prepare(`INSERT INTO settings (key, value) VALUES ('meter_test', '1')`).run()
    await db.batch([db.prepare(`UPDATE settings SET value = '2' WHERE key = ?1`).bind('meter_test'), db.prepare(`SELECT 1`)])
    expect(await db.prepare(`SELECT value FROM settings WHERE key = 'meter_test'`).first('value')).toBe('2')
    expect(await db.prepare(`SELECT value FROM settings WHERE key = 'missing'`).first('value')).toBeNull()
    expect(meter.rows).toBe(2)
    const env = meter.env({ DB, OTHER: 'kept' })
    expect(env.OTHER).toBe('kept')
    await env.DB.prepare(`DELETE FROM settings WHERE key = 'meter_test'`).run()
    expect(meter.rows).toBe(3)
  })
})

describe('registry entries that name the same server', () => {
  const entry = (name: string, description: string, websiteUrl?: string) => ({
    server: { name, title: name, description, version: '1.0.0', ...(websiteUrl ? { websiteUrl } : {}), remotes: [{ type: 'streamable-http', url: 'https://mcp.squat.example/mcp' }] },
    _meta: { 'io.modelcontextprotocol.registry/official': { status: 'active', isLatest: true } },
  })
  const serve = (servers: unknown[]) => (async () => new Response(JSON.stringify({ servers, metadata: {} }), { headers: { 'content-type': 'application/json' } })) as unknown as typeof fetch
  const stored = () => raw.prepare(`SELECT registry_name, description FROM registry WHERE url = 'https://mcp.squat.example/mcp'`).get()

  it('a domain-proven entry takes over, and a squatter can never take it back', async () => {
    await syncStep(DB, serve([entry('io.github.squatter/x', 'Visit evil.example')]))
    expect(stored()).toEqual({ registry_name: 'io.github.squatter/x', description: 'Visit evil.example' })
    await syncStep(DB, serve([entry('example.squat/mcp', 'The real server')]))
    expect(stored()).toEqual({ registry_name: 'example.squat/mcp', description: 'The real server' })
    await syncStep(DB, serve([entry('io.github.squatter/x', 'Visit evil.example again')]))
    expect(stored()).toEqual({ registry_name: 'example.squat/mcp', description: 'The real server' })
  })
})

describe('private reports', () => {
  it('get an unguessable link, the same one for the same receipt, and expire', async () => {
    const a = await savePrivateReport(DB, URL_, report({ authenticated: true }), 'sig-a')
    const b = await savePrivateReport(DB, URL_, report({ authenticated: true }), 'sig-b')
    expect(a.id).toMatch(/^[0-9a-f]{32}$/)
    expect(a.id).not.toBe(b.id)
    // Sharing the same receipt again (a replay) returns the same link and writes nothing.
    let again: { id: string } | undefined
    expect(await rowsWritten(async () => (again = await savePrivateReport(DB, URL_, report({ authenticated: true }), 'sig-a')))).toBe(0)
    expect(again?.id).toBe(a.id)
    expect((await loadPrivateReport(DB, a.id))?.report.authenticated).toBe(true)
    expect(await loadPrivateReport(DB, 'not-an-id')).toBeUndefined()
    raw.prepare(`UPDATE private_reports SET created_at = '2020-01-01T00:00:00.000Z' WHERE id = ?`).run(a.id)
    expect(await loadPrivateReport(DB, a.id)).toBeUndefined()
  })

  it('refuses reports too large to store', async () => {
    // Random tool names don't compress, so this is well over the cap once gzipped.
    const tools = Array.from({ length: 4000 }, () => ({ name: crypto.randomUUID() + crypto.randomUUID(), description: crypto.randomUUID().repeat(3) }))
    await expect(savePrivateReport(DB, URL_, report({ authenticated: true, tools }), 'sig-big')).rejects.toThrow(/too large/)
  })
})

describe('OAuth callback', () => {
  it('exchanges a code at most once, however often the callback is replayed', async () => {
    raw.prepare(`INSERT INTO oauth_pending (state, server_url, issuer, token_endpoint, client_id, auth_method, redirect_uri, verifier, resource, created_at)
                 VALUES ('state-1', ?, 'https://auth.example.com', 'https://auth.example.com/token', 'cid', 'none', 'https://mcp.nischaldhakal.com.np/oauth/callback', 'v', ?, ?)`).run(URL_, URL_, Date.now())
    let calls = 0
    const tokenEndpoint = (async () => {
      calls++
      return new Response(JSON.stringify({ access_token: 't', token_type: 'Bearer' }), { headers: { 'content-type': 'application/json' } })
    }) as unknown as typeof fetch
    const query = new URLSearchParams({ state: 'state-1', code: 'c', iss: 'https://auth.example.com' })
    for (let i = 0; i < 5; i++) await finishSignIn(DB, 'state-1', query, tokenEndpoint)
    expect(calls).toBe(1)
  })
})

describe('owner challenges', () => {
  it('work once, for the server they were issued for', async () => {
    const c = await createChallenge(DB, ID)
    expect(c.line).toBe(`mcp-check: clear-alerts ${ID} ${c.nonce}`)
    expect(await consumeChallenge(DB, 'otherserver12', c.nonce)).toBe(false)
    expect(await consumeChallenge(DB, ID, c.nonce)).toBe(true)
    expect(await consumeChallenge(DB, ID, c.nonce)).toBe(false)
  })
})

describe('registry entries that both lack proof', () => {
  const entry = (name: string, description: string) => ({
    server: { name, title: name, description, version: '1.0.0', remotes: [{ type: 'streamable-http', url: 'https://mcp.contested.example/mcp' }] },
    _meta: { 'io.modelcontextprotocol.registry/official': { status: 'active', isLatest: true } },
  })
  const serve = (servers: unknown[]) => (async () => new Response(JSON.stringify({ servers, metadata: {} }), { headers: { 'content-type': 'application/json' } })) as unknown as typeof fetch

  it('are marked contested, and queued checks get none of their details', async () => {
    await syncStep(DB, serve([entry('io.github.first/x', 'First claim')]))
    await syncStep(DB, serve([entry('io.github.second/x', 'Second claim')]))
    expect(raw.prepare(`SELECT registry_name, contested FROM registry WHERE url = 'https://mcp.contested.example/mcp'`).get()).toEqual({ registry_name: 'io.github.first/x', contested: 1 })
    // Repeating both doesn't write again.
    expect(await rowsWritten(() => syncStep(DB, serve([entry('io.github.first/x', 'First claim'), entry('io.github.second/x', 'Second claim')])))).toBeLessThanOrEqual(2)
    const queued = (await nextCandidates(DB, 10)).find((c) => c.url === 'https://mcp.contested.example/mcp')
    expect(queued).toMatchObject({ registryName: null, description: null })
  })
})

describe('directory pages', () => {
  it('come from the snapshot, with the pinned server first', async () => {
    const { directoryPage, refreshSnapshot } = await import('../src/worker/directory')
    for (let i = 0; i < 5; i++) {
      const url = `https://s${i}.example.com/mcp`
      await saveReport(DB, await serverId(url), url, report({ url, score: 90 + i, checkedAt: `2026-12-0${i + 1}T00:00:00.000Z` }), { list: true })
    }
    await refreshSnapshot(DB, URL_)
    const page1 = await directoryPage(DB, { sort: 'grade', page: 1, pageSize: 2, pinnedUrl: URL_ })
    expect(page1.servers[0]?.url).toBe(URL_)
    expect(page1.servers.slice(1).map((s) => s.score)).toEqual([94, 93])
    expect(page1.total).toBe(6)
    const recent = await directoryPage(DB, { sort: 'recent', page: 2, pageSize: 2, pinnedUrl: URL_ })
    expect(recent.servers.map((s) => s.url)).toEqual(['https://s2.example.com/mcp', 'https://s1.example.com/mcp'])
  })
})


describe('webhook slots', () => {
  const ok = (async () => new Response('ok')) as unknown as typeof fetch
  it('one per visitor per server, and the owner can clear them all', async () => {
    await subscribe(DB, ID, 'https://hooks.example.com/a', 'https://mcp.nischaldhakal.com.np', 'visitor-1', ok)
    await expect(subscribe(DB, ID, 'https://hooks.example.com/b', 'https://mcp.nischaldhakal.com.np', 'visitor-1', ok)).rejects.toThrow(/already have a webhook/)
    await subscribe(DB, ID, 'https://hooks.example.com/c', 'https://mcp.nischaldhakal.com.np', 'visitor-2', ok)
    expect(await clearWebhooks(DB, ID)).toBe(2)
    expect(raw.prepare(`SELECT COUNT(*) AS n FROM webhooks WHERE server_id = ?`).get(ID)).toEqual({ n: 0 })
  })
})

describe('webhook slot race', () => {
  it('two parallel requests from one visitor get one webhook', async () => {
    const slowOk = (async () => {
      await new Promise((r) => setTimeout(r, 50))
      return new Response('ok')
    }) as unknown as typeof fetch
    const results = await Promise.allSettled([
      subscribe(DB, ID, 'https://hooks.example.com/r1', 'https://mcp.nischaldhakal.com.np', 'racer', slowOk),
      subscribe(DB, ID, 'https://hooks.example.com/r2', 'https://mcp.nischaldhakal.com.np', 'racer', slowOk),
    ])
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
    expect(raw.prepare(`SELECT COUNT(*) AS n FROM webhooks WHERE server_id = ? AND subscriber = 'racer'`).get(ID)).toEqual({ n: 1 })
  })
})

describe('old alert events', () => {
  it('are pruned by sequence, keeping recent ones', async () => {
    const old = new Date(Date.now() - 400 * 86_400_000).toISOString()
    const recent = new Date().toISOString()
    // Events are only ever stamped with the time they're written, so earlier ones are older.
    raw.prepare(`UPDATE events SET at = ?`).run(old)
    for (const at of [old, old, recent]) raw.prepare(`INSERT INTO events (server_id, type, at) VALUES ('prune-test', 'listed', ?)`).run(at)
    await pruneEvents(DB)
    expect(raw.prepare(`SELECT at FROM events WHERE server_id = 'prune-test'`).all()).toEqual([{ at: recent }])
  })
})
