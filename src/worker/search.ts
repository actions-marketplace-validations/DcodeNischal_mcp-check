// Directory search: keyword search (SQLite FTS5 in D1) merged with meaning search (Workers AI
// embeddings in Vectorize), so "send email" also finds a Gmail server that never says "send".
// Meaning search is optional: without the AI and VECTORS bindings, or if either fails or runs
// out of free quota, search falls back to keywords alone.
import type { Report } from '../checks/types'
import { S_COLUMNS } from './directory'
import { issuesOf } from './stats'
import { GRADING_VERSION, regrade } from '../checks/grade'
import { ensureSchema, gunzip, gzip, type DirectoryEntry } from './store'

export interface SearchEnv {
  DB: D1Database
  AI?: Ai
  VECTORS?: Vectorize
}

export const EMBED_MODEL = '@cf/baai/bge-small-en-v1.5'
/** bge-v1.5 retrieves better when short queries carry this instruction (documents don't). */
const QUERY_PREFIX = 'Represent this sentence for searching relevant passages: '
/**
 * Cosine similarity below this is treated as unrelated. Measured with bge-small and the query
 * prefix: relevant pairs scored 0.57-0.70 ("send email" vs a Gmail server 0.57), unrelated
 * ones 0.30-0.51.
 */
export const MIN_SIMILARITY = 0.55
const KEYWORD_LIMIT = 100
const VECTOR_LIMIT = 50
const EMBED_BATCH = 25
/** Reciprocal rank fusion constant: higher flattens the difference between ranks. */
const RRF_K = 60

// --- text ------------------------------------------------------------------------------------

/** The tool names and descriptions, one per line, as stored for search. */
export function toolsText(tools: Report['tools']): string {
  return tools
    .map((t) => `${t.name}: ${(t.title ? `${t.title}. ` : '') + (t.description ?? '')}`.replace(/\s+/g, ' ').trim().slice(0, 240))
    .join('\n')
    .slice(0, 8000)
}

/** What gets embedded for one server. */
export function embedText(s: { name: string | null; registry_name: string | null; description: string | null; tools_text: string | null }): string {
  const tools = (s.tools_text ?? '').split('\n').filter(Boolean)
  return [s.name, s.registry_name, s.description, tools.length ? `Tools: ${tools.join('; ')}` : '']
    .filter(Boolean)
    .join('\n')
    .slice(0, 1500)
}

/** Lower-case words of the query, without duplicates. */
export function queryWords(search: string): string[] {
  const words = search.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? []
  return [...new Set(words)].filter((w) => w.length >= 2).slice(0, 8)
}

/**
 * An FTS5 MATCH expression. Each word matches itself (stemmed, so "emails" finds "email") or,
 * from three letters, anything it starts (so "deepw" finds "deepwiki"). Words only contain
 * letters and digits, so quoting them is safe.
 */
export function ftsQuery(words: string[], mode: 'all' | 'any'): string {
  return words.map((w) => (w.length >= 3 ? `("${w}" OR "${w}"*)` : `"${w}"`)).join(mode === 'all' ? ' AND ' : ' OR ')
}

/** Merge ranked lists of ids: each list adds 1 / (k + rank) to an id's score. */
export function fuse(lists: string[][], k = RRF_K): string[] {
  const score = new Map<string, number>()
  for (const list of lists) list.forEach((id, i) => score.set(id, (score.get(id) ?? 0) + 1 / (k + i + 1)))
  return [...score.entries()].sort((a, b) => b[1] - a[1]).map(([id]) => id)
}

/** Crude stemming, only for picking which tool to show as the match. */
const stem = (w: string) => w.replace(/(ing|ed|es|s)$/, '').slice(0, Math.max(3, w.length - 3)) || w

/** The tool that best matches the query words, if any. */
export function matchedTool(words: string[], tools: string | null): string | undefined {
  if (!tools || !words.length) return undefined
  const stems = words.filter((w) => w.length >= 3).map(stem)
  let best: { name: string; hits: number } | undefined
  for (const line of tools.split('\n')) {
    const colon = line.indexOf(':')
    const name = colon < 0 ? line : line.slice(0, colon)
    const tokens = line.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean)
    const hits = stems.filter((s) => tokens.some((t) => t.startsWith(s))).length
    if (hits && (!best || hits > best.hits)) best = { name, hits }
  }
  return best?.name
}

// --- searching -------------------------------------------------------------------------------

export interface SearchQuery {
  search: string
  grade?: string
  sort?: 'relevance' | 'grade' | 'recent'
  page: number
  pageSize: number
  /** A server to keep first whenever it's among the results. */
  pinnedUrl?: string
}

export interface SearchResult {
  servers: (DirectoryEntry & { match?: string })[]
  total: number
  /** Which kinds of search contributed. */
  modes: ('keyword' | 'meaning')[]
}

/** Keyword matches, best first: every word first, then any word. */
async function keywordIds(db: D1Database, words: string[], grade?: string): Promise<string[]> {
  if (!words.length) return []
  // Column weights: id (not indexed), name, description, tools, url.
  const sql = `SELECT f.id FROM server_search f JOIN servers s ON s.id = f.id
               WHERE server_search MATCH ?1 AND s.listed = 1 AND s.blocked = 0 ${grade ? 'AND s.grade = ?2' : ''}
               ORDER BY bm25(server_search, 0.0, 8.0, 3.0, 1.0, 4.0) LIMIT ${KEYWORD_LIMIT}`
  const bind = (q: string) => db.prepare(sql).bind(...(grade ? [q, grade] : [q]))
  const statements = [bind(ftsQuery(words, 'all'))]
  if (words.length > 1) statements.push(bind(ftsQuery(words, 'any')))
  const results = await db.batch<{ id: string }>(statements)
  const ids = results.flatMap((r) => r.results.map((row) => row.id))
  return [...new Set(ids)]
}

/** Meaning matches, best first. Empty when the bindings are missing or fail. */
async function meaningIds(env: SearchEnv, search: string): Promise<string[] | undefined> {
  if (!env.AI || !env.VECTORS || search.length < 3) return undefined
  try {
    const { data } = (await env.AI.run(EMBED_MODEL, { text: [QUERY_PREFIX + search] })) as { data?: number[][] }
    const vector = data?.[0]
    if (!vector) return undefined
    const { matches } = await env.VECTORS.query(vector, { topK: VECTOR_LIMIT, returnValues: false, returnMetadata: 'none' })
    return matches.filter((m) => m.score >= MIN_SIMILARITY).map((m) => m.id)
  } catch (err) {
    console.error('meaning search failed', String(err))
    return undefined
  }
}

const GRADE_ORDER = (a: DirectoryEntry, b: DirectoryEntry) =>
  a.grade.localeCompare(b.grade) || a.partial - b.partial || b.score - a.score || (a.name ?? '').localeCompare(b.name ?? '')

export async function searchServers(env: SearchEnv, q: SearchQuery): Promise<SearchResult> {
  await ensureSchema(env.DB)
  const words = queryWords(q.search)
  const [keyword, meaning] = await Promise.all([keywordIds(env.DB, words, q.grade), meaningIds(env, q.search)])
  const ranked = fuse(meaning?.length ? [keyword, meaning] : [keyword])
  const modes: SearchResult['modes'] = ['keyword', ...(meaning ? (['meaning'] as const) : [])]
  if (!ranked.length) return { servers: [], total: 0, modes }

  // Load the matches, dropping anything unlisted since it was indexed and applying the grade filter
  // to meaning matches (keyword matches were already filtered).
  const { results } = await env.DB
    // One primary-key lookup per match (see directoryPage for why not "id IN (...)").
    .prepare(`SELECT ${S_COLUMNS}, s.tools_text
              FROM json_each(?1) AS j CROSS JOIN servers AS s ON s.id = j.value
              WHERE s.listed = 1 AND s.blocked = 0 ${q.grade ? 'AND s.grade = ?2' : ''}`)
    .bind(...(q.grade ? [JSON.stringify(ranked), q.grade] : [JSON.stringify(ranked)]))
    .all<DirectoryEntry & { tools_text: string | null }>()
  const byId = new Map(results.map((r) => [r.id, r]))
  let rows = ranked.map((id) => byId.get(id)).filter((r) => r !== undefined)
  if (q.sort === 'grade') rows = rows.sort(GRADE_ORDER)
  else if (q.sort === 'recent') rows = rows.sort((a, b) => b.checked_at.localeCompare(a.checked_at))
  // MCP Check's own server stays on top whenever it matches.
  if (q.pinnedUrl) rows = [...rows.filter((r) => r.url === q.pinnedUrl), ...rows.filter((r) => r.url !== q.pinnedUrl)]

  const keywordSet = new Set(keyword)
  const start = (q.page - 1) * q.pageSize
  const servers = rows.slice(start, start + q.pageSize).map(({ tools_text, ...row }) => {
    const tool = keywordSet.has(row.id) ? matchedTool(words, tools_text) : undefined
    const match = tool ? `Matched tool: ${tool}` : keywordSet.has(row.id) ? undefined : 'Similar in meaning'
    return match ? { ...row, match } : row
  })
  return { servers, total: rows.length, modes }
}

// --- keeping the indexes current (from the cron tick) ----------------------------------------

/**
 * Bring older stored reports up to date, a few at a time: fill in tool text and issues for servers
 * saved before those columns existed, and regrade reports graded under earlier rules. Saving tool
 * text fires the triggers that update the keyword index and mark the server for re-embedding.
 */
export async function backfillToolsText(db: D1Database, limit = 10): Promise<number> {
  await ensureSchema(db)
  // Once a pass finds nothing for the current grading rules, stop scanning until they change.
  const done = await db.prepare(`SELECT value FROM settings WHERE key = 'backfill_done'`).first<string>('value')
  if (done === String(GRADING_VERSION)) return 0
  const { results } = await db
    .prepare(`SELECT id, report FROM servers WHERE (tools_text IS NULL OR issues IS NULL OR grading_version < ?2) AND listed = 1 AND blocked = 0 LIMIT ?1`)
    .bind(limit, GRADING_VERSION)
    .all<{ id: string; report: ArrayBuffer | number[] }>()
  if (!results.length) {
    await db.prepare(`INSERT INTO settings (key, value) VALUES ('backfill_done', ?1) ON CONFLICT (key) DO UPDATE SET value = ?1`).bind(String(GRADING_VERSION)).run()
    return 0
  }
  const statements: D1PreparedStatement[] = []
  for (const row of results) {
    const bytes = row.report instanceof ArrayBuffer ? new Uint8Array(row.report) : Uint8Array.from(row.report)
    const stored = JSON.parse(await gunzip(bytes)) as Report
    const report = regrade(stored)
    statements.push(
      db.prepare(`UPDATE servers SET tools_text = ?2, issues = ?3, grade = ?4, score = ?5, grading_version = ?6, report = ?7 WHERE id = ?1`)
        .bind(row.id, toolsText(report.tools ?? []), issuesOf(report), report.grade, report.score, report.gradingVersion ?? 1, report === stored ? bytes : await gzip(JSON.stringify(report))),
    )
  }
  await db.batch(statements)
  return results.length
}

/** Embed servers whose text changed since they were last embedded. */
export async function embedPending(env: SearchEnv, limit = EMBED_BATCH): Promise<number> {
  if (!env.AI || !env.VECTORS) return 0
  await ensureSchema(env.DB)
  const { results } = await env.DB
    // The partial index holds only servers waiting to be embedded, so this reads just those.
    .prepare(`SELECT id, name, registry_name, description, tools_text FROM servers INDEXED BY servers_embed_stale
              WHERE embed_stale = 1 AND listed = 1 AND blocked = 0 AND tools_text IS NOT NULL LIMIT ?1`)
    .bind(limit)
    .all<{ id: string; name: string | null; registry_name: string | null; description: string | null; tools_text: string | null }>()
  if (!results.length) return 0
  const { data } = (await env.AI.run(EMBED_MODEL, { text: results.map(embedText) })) as { data?: number[][] }
  if (!data || data.length !== results.length) throw new Error('embedding returned the wrong number of vectors')
  await env.VECTORS.upsert(results.map((r, i) => ({ id: r.id, values: data[i]! })))
  await env.DB
    .prepare(`UPDATE servers SET embed_stale = 0 WHERE id IN (SELECT value FROM json_each(?1))`)
    .bind(JSON.stringify(results.map((r) => r.id)))
    .run()
  return results.length
}
