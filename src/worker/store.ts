// Saved reports in D1: one row per server URL, gzip-compressed. Reports are only saved when a
// visitor shares one, and only if it carries a valid signature from this Worker, so nobody can
// upload a made-up grade.
import type { Report } from '../checks/types'
import { toolsText } from './search'
import { issuesOf } from './stats'

const MAX_RECEIPT_AGE_MS = 60 * 60 * 1000

// Only finished results are cached at module level, never a promise still in flight: the runtime
// won't settle a promise in a request other than the one that created it, so a shared in-flight
// promise whose request ended would leave every later request waiting forever.
let schemaReady = false
/** The first tables (MIGRATIONS adds everything since). Exported for the schema tests. */
export const BASE_SCHEMA = [
  `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS servers (
        id TEXT PRIMARY KEY,
        url TEXT NOT NULL UNIQUE,
        name TEXT,
        version TEXT,
        grade TEXT NOT NULL,
        score INTEGER NOT NULL,
        era TEXT,
        spec_version TEXT,
        tools_count INTEGER NOT NULL DEFAULT 0,
        partial INTEGER NOT NULL DEFAULT 0,
        auth_required INTEGER NOT NULL DEFAULT 0,
        authenticated INTEGER NOT NULL DEFAULT 0,
        report BLOB NOT NULL,
        checked_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_viewed_at TEXT,
        listed INTEGER NOT NULL DEFAULT 0
      )`,
  `CREATE INDEX IF NOT EXISTS servers_listed_grade ON servers (listed, grade, score DESC)`,
]

let schemaRetryAt = 0

export async function ensureSchema(db: D1Database): Promise<void> {
  if (schemaReady || Date.now() < schemaRetryAt) return
  try {
    await db.batch(BASE_SCHEMA.map((sql) => db.prepare(sql)))
    await migrate(db)
    schemaReady = true
  } catch (err) {
    // Usually the account's daily write limit. Carry on with the tables as they are, so pages that
    // only read keep working, and try again in a minute.
    schemaRetryAt = Date.now() + 60_000
    console.error('schema update failed, retrying in a minute:', String(err))
  }
}

// Changes since the first deploy. Each step runs once; "duplicate column" or "already exists" means
// another request applied it at the same moment, which is fine.
export const MIGRATIONS: string[][] = [
  [
    `ALTER TABLE servers ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE servers ADD COLUMN failures INTEGER NOT NULL DEFAULT 0`,
    `ALTER TABLE servers ADD COLUMN last_attempt_at TEXT`,
  ],
  [
    // Details from the official MCP Registry, shown on server pages.
    `ALTER TABLE servers ADD COLUMN registry_name TEXT`,
    `ALTER TABLE servers ADD COLUMN description TEXT`,
    `ALTER TABLE servers ADD COLUMN repository_url TEXT`,
    `ALTER TABLE servers ADD COLUMN website_url TEXT`,
    // Servers found in the registry, waiting to be checked.
    `CREATE TABLE IF NOT EXISTS registry (
      url TEXT PRIMARY KEY,
      id TEXT NOT NULL,
      host TEXT NOT NULL,
      registry_name TEXT NOT NULL,
      title TEXT,
      description TEXT,
      version TEXT,
      repository_url TEXT,
      website_url TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      attempts INTEGER NOT NULL DEFAULT 0,
      last_attempt_at TEXT,
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS registry_pending ON registry (status, last_attempt_at)`,
  ],
  [
    // Search: tool names and descriptions as text, a keyword index kept current by triggers,
    // and a flag for servers whose text changed since they were last embedded.
    `ALTER TABLE servers ADD COLUMN tools_text TEXT`,
    `ALTER TABLE servers ADD COLUMN embed_stale INTEGER NOT NULL DEFAULT 1`,
    `CREATE VIRTUAL TABLE IF NOT EXISTS server_search USING fts5(id UNINDEXED, name, description, tools, url, tokenize = 'porter unicode61')`,
    `CREATE TRIGGER IF NOT EXISTS servers_search_insert AFTER INSERT ON servers WHEN new.listed = 1 AND new.blocked = 0 BEGIN
      INSERT INTO server_search (rowid, id, name, description, tools, url) VALUES (new.rowid, new.id, trim(coalesce(new.name, '') || ' ' || coalesce(new.registry_name, '')), coalesce(new.description, ''), coalesce(new.tools_text, ''), new.url);
    END`,
    `CREATE TRIGGER IF NOT EXISTS servers_search_update AFTER UPDATE OF name, registry_name, description, tools_text, url, listed, blocked ON servers BEGIN
      DELETE FROM server_search WHERE rowid = old.rowid;
      INSERT INTO server_search (rowid, id, name, description, tools, url) SELECT new.rowid, new.id, trim(coalesce(new.name, '') || ' ' || coalesce(new.registry_name, '')), coalesce(new.description, ''), coalesce(new.tools_text, ''), new.url WHERE new.listed = 1 AND new.blocked = 0;
    END`,
    `CREATE TRIGGER IF NOT EXISTS servers_search_delete AFTER DELETE ON servers BEGIN
      DELETE FROM server_search WHERE rowid = old.rowid;
    END`,
    `CREATE TRIGGER IF NOT EXISTS servers_embed_stale AFTER UPDATE OF name, registry_name, description, tools_text ON servers
      WHEN old.name IS NOT new.name OR old.registry_name IS NOT new.registry_name OR old.description IS NOT new.description OR old.tools_text IS NOT new.tools_text BEGIN
      UPDATE servers SET embed_stale = 1 WHERE rowid = new.rowid;
    END`,
    // Index what's already listed. Clearing first makes this safe to run again (see MIGRATIONS[2]).
    `DELETE FROM server_search`,
    `INSERT INTO server_search (rowid, id, name, description, tools, url)
      SELECT rowid, id, trim(coalesce(name, '') || ' ' || coalesce(registry_name, '')), coalesce(description, ''), coalesce(tools_text, ''), url FROM servers WHERE listed = 1 AND blocked = 0`,
  ],
  [
    // OAuth sign-in: sign-ins in progress (deleted when claimed, or after ten minutes) and the
    // client ids MCP Check got by registering with authorization servers.
    `CREATE TABLE IF NOT EXISTS oauth_pending (
      state TEXT PRIMARY KEY,
      server_url TEXT NOT NULL,
      issuer TEXT NOT NULL,
      token_endpoint TEXT NOT NULL,
      client_id TEXT NOT NULL,
      client_secret TEXT,
      auth_method TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      verifier TEXT NOT NULL,
      resource TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      access_token TEXT,
      expires_in INTEGER,
      scope TEXT,
      error TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS oauth_clients (
      issuer TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      client_id TEXT NOT NULL,
      client_secret TEXT,
      auth_method TEXT NOT NULL,
      registered_at TEXT NOT NULL,
      PRIMARY KEY (issuer, redirect_uri)
    )`,
  ],
  [
    // Alerts: events recorded by triggers whenever a server is listed, changes grade, or is
    // dropped after failing re-checks (not when its owner removes it), and webhook deliveries
    // queued for each event. See src/worker/alerts.ts.
    `CREATE TABLE IF NOT EXISTS events (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id TEXT NOT NULL,
      type TEXT NOT NULL,
      grade TEXT,
      prev_grade TEXT,
      score INTEGER,
      prev_score INTEGER,
      at TEXT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS events_server ON events (server_id, seq)`,
    `CREATE TABLE IF NOT EXISTS webhooks (
      id TEXT PRIMARY KEY,
      server_id TEXT NOT NULL,
      url TEXT NOT NULL,
      secret TEXT NOT NULL,
      format TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      failures INTEGER NOT NULL DEFAULT 0,
      last_status INTEGER,
      created_at TEXT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS webhooks_server ON webhooks (server_id, active)`,
    `CREATE TABLE IF NOT EXISTS deliveries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      webhook_id TEXT NOT NULL,
      event_seq INTEGER NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      next_at TEXT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS deliveries_due ON deliveries (next_at)`,
    `CREATE TRIGGER IF NOT EXISTS servers_event_new AFTER INSERT ON servers WHEN new.listed = 1 BEGIN
      INSERT INTO events (server_id, type, grade, score, at) VALUES (new.id, 'listed', new.grade, new.score, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
    END`,
    `CREATE TRIGGER IF NOT EXISTS servers_event_listed AFTER UPDATE OF listed ON servers WHEN old.listed = 0 AND new.listed = 1 BEGIN
      INSERT INTO events (server_id, type, grade, score, at) VALUES (new.id, 'listed', new.grade, new.score, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
    END`,
    `CREATE TRIGGER IF NOT EXISTS servers_event_grade AFTER UPDATE OF grade ON servers WHEN old.listed = 1 AND new.listed = 1 AND old.grade IS NOT new.grade BEGIN
      INSERT INTO events (server_id, type, grade, prev_grade, score, prev_score, at) VALUES (new.id, 'grade_changed', new.grade, old.grade, new.score, old.score, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
    END`,
    `CREATE TRIGGER IF NOT EXISTS servers_event_unreachable AFTER UPDATE OF listed ON servers WHEN old.listed = 1 AND new.listed = 0 AND new.blocked = 0 AND new.failures >= 3 BEGIN
      INSERT INTO events (server_id, type, grade, score, at) VALUES (new.id, 'unreachable', new.grade, new.score, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
    END`,
    `CREATE TRIGGER IF NOT EXISTS events_queue_deliveries AFTER INSERT ON events BEGIN
      INSERT INTO deliveries (webhook_id, event_seq, attempts, next_at) SELECT id, new.seq, 0, new.at FROM webhooks WHERE server_id = new.server_id AND active = 1;
    END`,
  ],
  [
    // Each server's warnings and failures as JSON, for directory-wide stats (see stats.ts).
    `ALTER TABLE servers ADD COLUMN issues TEXT`,
  ],
  [
    // Which grading rules each stored grade follows. Older ones are regraded in the background,
    // and a grade that changes only because the rules changed isn't an alert-worthy event.
    `ALTER TABLE servers ADD COLUMN grading_version INTEGER NOT NULL DEFAULT 1`,
    `DROP TRIGGER IF EXISTS servers_event_grade`,
    `CREATE TRIGGER servers_event_grade AFTER UPDATE OF grade ON servers
      WHEN old.listed = 1 AND new.listed = 1 AND old.grade IS NOT new.grade AND old.grading_version = new.grading_version BEGIN
      INSERT INTO events (server_id, type, grade, prev_grade, score, prev_score, at) VALUES (new.id, 'grade_changed', new.grade, old.grade, new.score, old.score, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
    END`,
  ],
  [
    // Indexes for the queries that run every minute or on every directory view, so each reads a
    // handful of rows instead of whole tables (the free plan allows 5M rows read a day).
    `CREATE INDEX IF NOT EXISTS registry_queue ON registry (status, attempts, first_seen_at)`,
    `CREATE INDEX IF NOT EXISTS servers_embed_stale ON servers (id) WHERE embed_stale = 1`,
    `CREATE INDEX IF NOT EXISTS servers_directory ON servers (listed, blocked, grade, partial, score DESC, name)`,
    `CREATE INDEX IF NOT EXISTS servers_recent ON servers (listed, blocked, checked_at DESC)`,
    `CREATE INDEX IF NOT EXISTS servers_recheck ON servers (COALESCE(last_attempt_at, checked_at)) WHERE listed = 1 AND blocked = 0 AND authenticated = 0`,
  ],
  [
    // Owners who proved control of their server's domain (re-confirmed at each weekly re-check).
    `ALTER TABLE servers ADD COLUMN owner_verified_at TEXT`,
    // Registry servers that need a per-user credential to reach. Private: never shown on the site.
    `CREATE TABLE IF NOT EXISTS keyed_servers (
      registry_name TEXT PRIMARY KEY,
      url TEXT NOT NULL,
      reason TEXT NOT NULL,
      title TEXT,
      description TEXT,
      repository_url TEXT,
      website_url TEXT,
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL
    )`,
  ],
  [
    // Fewer row writes (the free plan allows 100,000 a day): rebuild a server's search entry only
    // when something it indexes actually changes, and drop indexes newer ones replaced.
    `DROP TRIGGER IF EXISTS servers_search_update`,
    `CREATE TRIGGER servers_search_update AFTER UPDATE OF name, registry_name, description, tools_text, url, listed, blocked ON servers
      WHEN old.name IS NOT new.name OR old.registry_name IS NOT new.registry_name OR old.description IS NOT new.description
        OR old.tools_text IS NOT new.tools_text OR old.url IS NOT new.url OR old.listed IS NOT new.listed OR old.blocked IS NOT new.blocked BEGIN
      DELETE FROM server_search WHERE rowid = old.rowid;
      INSERT INTO server_search (rowid, id, name, description, tools, url) SELECT new.rowid, new.id, trim(coalesce(new.name, '') || ' ' || coalesce(new.registry_name, '')), coalesce(new.description, ''), coalesce(new.tools_text, ''), new.url WHERE new.listed = 1 AND new.blocked = 0;
    END`,
    `DROP INDEX IF EXISTS registry_pending`,
    `DROP INDEX IF EXISTS servers_listed_grade`,
  ],
  [
    // OAuth mix-up protection: sign-ins whose endpoints aren't on the issuer's origin must get an iss.
    `ALTER TABLE oauth_pending ADD COLUMN require_iss INTEGER NOT NULL DEFAULT 0`,
  ],
  [
    // Reports made with a token or custom headers, under random links (see private.ts).
    `CREATE TABLE IF NOT EXISTS private_reports (
      id TEXT PRIMARY KEY,
      url TEXT NOT NULL,
      report BLOB NOT NULL,
      created_at TEXT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS private_reports_created ON private_reports (created_at)`,
    // Who added a webhook (a hash of their network), so one visitor can't take every slot.
    `ALTER TABLE webhooks ADD COLUMN subscriber TEXT`,
    // Whether a registry entry's namespace proves it belongs to the server's domain.
    `ALTER TABLE registry ADD COLUMN ns_match INTEGER NOT NULL DEFAULT 0`,
  ],
  [
    // A sign-in's code is exchanged at most once (replaying the callback does nothing).
    `ALTER TABLE oauth_pending ADD COLUMN exchanging INTEGER NOT NULL DEFAULT 0`,
    // One-time codes an owner must serve to clear their server's webhooks.
    `CREATE TABLE IF NOT EXISTS owner_challenges (
      nonce TEXT PRIMARY KEY,
      server_id TEXT NOT NULL,
      action TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`,
    // One webhook per visitor per server, enforced by the database (NULL subscribers are distinct).
    `CREATE UNIQUE INDEX IF NOT EXISTS webhooks_one_per_subscriber ON webhooks (server_id, subscriber)`,
    // Two registry entries with unproven namespaces claim the same server: show neither's details.
    `ALTER TABLE registry ADD COLUMN contested INTEGER NOT NULL DEFAULT 0`,
    // Reports made with credentials now live in private_reports only.
    `DELETE FROM servers WHERE authenticated = 1 AND listed = 0`,
  ],
]

async function migrate(db: D1Database) {
  const current = Number((await db.prepare(`SELECT value FROM settings WHERE key = 'schema_version'`).first<string>('value')) ?? 0)
  for (let v = current; v < MIGRATIONS.length; v++) {
    for (const sql of MIGRATIONS[v]!) {
      try {
        await db.prepare(sql).run()
      } catch (err) {
        // Another instance may have applied this step at the same moment.
        if (!/duplicate column|already exists/i.test(String((err as Error)?.message ?? err))) throw err
      }
    }
    // Never move the version backwards if another instance got further at the same time.
    await db.prepare(`INSERT INTO settings (key, value) VALUES ('schema_version', ?1)
                      ON CONFLICT (key) DO UPDATE SET value = CASE WHEN CAST(value AS INTEGER) < CAST(?1 AS INTEGER) THEN ?1 ELSE value END`).bind(String(v + 1)).run()
  }
}

// --- the signing key, created on first use and kept in D1 ----------------------------------

let cachedKey: CryptoKey | undefined
async function signingKey(db: D1Database): Promise<CryptoKey> {
  if (cachedKey) return cachedKey
  await ensureSchema(db)
  let secret = await db.prepare(`SELECT value FROM settings WHERE key = 'report_key'`).first<string>('value')
  if (!secret) {
    const fresh = base64url(crypto.getRandomValues(new Uint8Array(32)))
    // If two requests race, INSERT OR IGNORE keeps the first; read back whichever won.
    await db.prepare(`INSERT OR IGNORE INTO settings (key, value) VALUES ('report_key', ?)`).bind(fresh).run()
    secret = (await db.prepare(`SELECT value FROM settings WHERE key = 'report_key'`).first<string>('value')) ?? fresh
  }
  cachedKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
  return cachedKey
}

export interface Receipt {
  /** The report exactly as the Worker produced it, as a JSON string. */
  payload: string
  sig: string
}

export async function signReport(db: D1Database, report: Report): Promise<Receipt> {
  const payload = JSON.stringify(report)
  const sig = await crypto.subtle.sign('HMAC', await signingKey(db), new TextEncoder().encode(payload))
  return { payload, sig: base64url(new Uint8Array(sig)) }
}

export async function verifyReceipt(db: D1Database, receipt: unknown): Promise<{ ok: true; report: Report } | { ok: false; reason: string }> {
  if (!receipt || typeof receipt !== 'object') return { ok: false, reason: 'Missing report.' }
  const { payload, sig } = receipt as Partial<Receipt>
  if (typeof payload !== 'string' || typeof sig !== 'string' || payload.length > 2_000_000) return { ok: false, reason: 'Missing report.' }
  let raw: Uint8Array<ArrayBuffer>
  try {
    raw = fromBase64url(sig)
  } catch {
    return { ok: false, reason: 'This report could not be verified.' }
  }
  const valid = await crypto.subtle.verify('HMAC', await signingKey(db), raw, new TextEncoder().encode(payload))
  if (!valid) return { ok: false, reason: 'This report could not be verified.' }
  const report = JSON.parse(payload) as Report
  if (Date.now() - Date.parse(report.checkedAt) > MAX_RECEIPT_AGE_MS) return { ok: false, reason: 'This check is over an hour old. Run it again to share it.' }
  return { ok: true, report }
}

// --- ids and URLs --------------------------------------------------------------------------

/** The canonical form of a server URL: lowercase host, no default port, no trailing slash. */
export function canonicalUrl(raw: string): { ok: true; url: string } | { ok: false; reason: string } {
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    return { ok: false, reason: 'Invalid URL.' }
  }
  if (u.search || u.hash) return { ok: false, reason: "URLs with query strings can't be shared, because they often contain API keys." }
  if (u.username || u.password) return { ok: false, reason: "URLs with credentials can't be shared." }
  const path = u.pathname.length > 1 ? u.pathname.replace(/\/+$/, '') : ''
  return { ok: true, url: `${u.protocol}//${u.host.toLowerCase()}${path}` }
}

/** A short, stable id per server, so sharing again updates the same report and badge. */
export async function serverId(url: string): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(url)))
  return base32(hash).slice(0, 12)
}

// --- saving and loading ---------------------------------------------------------------------

export interface RegistryDetails {
  registryName: string
  description: string | null
  repositoryUrl: string | null
  websiteUrl: string | null
}

/**
 * Save a report. An older report never replaces a newer one (so a replayed receipt changes and writes
 * nothing), and a report made with credentials or custom headers never replaces a server that's
 * listed or removed by its owner. `saved` is false when the stored report was kept.
 */
export async function saveReport(db: D1Database, id: string, url: string, report: Report, opts: { list?: boolean; registry?: RegistryDetails } = {}): Promise<{ listed: boolean; blocked: boolean; saved: boolean }> {
  await ensureSchema(db)
  const blob = await gzip(JSON.stringify({ ...report, url }))
  const now = new Date().toISOString()
  // Listing rules: never list a report made with someone's credentials (its tool list may be
  // private), never re-list a server its owner removed, and keep an existing listing on re-share.
  const row = await db
    .prepare(`INSERT INTO servers (id, url, name, version, grade, score, era, spec_version, tools_count, partial, auth_required, authenticated, report, checked_at, created_at, updated_at, last_attempt_at, listed, failures, tools_text, issues, grading_version, registry_name, description, repository_url, website_url)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15, ?15, CASE WHEN ?16 = 1 AND ?12 = 0 THEN 1 ELSE 0 END, 0, ?17, ?18, ?19, ?21, ?22, ?23, ?24)
              ON CONFLICT (id) DO UPDATE SET name = ?3, version = ?4, grade = ?5, score = ?6, era = ?7, spec_version = ?8,
                tools_count = ?9, partial = ?10, auth_required = ?11, authenticated = ?12, report = ?13, checked_at = ?14, updated_at = ?15, tools_text = ?17, issues = ?18, grading_version = ?19,
                last_attempt_at = ?15, failures = 0,
                listed = CASE WHEN servers.blocked = 1 OR ?12 = 1 THEN 0 WHEN ?16 = 1 THEN 1 ELSE servers.listed END,
                registry_name = CASE WHEN ?20 = 1 THEN ?21 ELSE servers.registry_name END,
                description = CASE WHEN ?20 = 1 THEN ?22 ELSE servers.description END,
                repository_url = CASE WHEN ?20 = 1 THEN ?23 ELSE servers.repository_url END,
                website_url = CASE WHEN ?20 = 1 THEN ?24 ELSE servers.website_url END
              WHERE excluded.checked_at > servers.checked_at AND NOT (?12 = 1 AND (servers.listed = 1 OR servers.blocked = 1))
              RETURNING listed, blocked`)
    .bind(
      id, url,
      report.serverInfo?.title ?? report.serverInfo?.name ?? null,
      report.serverInfo?.version ?? null,
      report.grade, report.score, report.era ?? null, report.version ?? null,
      report.tools.length, report.partial ? 1 : 0, report.auth?.required ? 1 : 0, report.authenticated ? 1 : 0,
      blob, report.checkedAt, now, opts.list ? 1 : 0, toolsText(report.tools), issuesOf(report), report.gradingVersion ?? 1,
      opts.registry ? 1 : 0, opts.registry?.registryName ?? null, opts.registry?.description ?? null, opts.registry?.repositoryUrl ?? null, opts.registry?.websiteUrl ?? null,
    )
    .first<{ listed: number; blocked: number }>()
  if (row) return { listed: !!row.listed, blocked: !!row.blocked, saved: true }
  const kept = await db.prepare(`SELECT listed, blocked FROM servers WHERE id = ?1`).bind(id).first<{ listed: number; blocked: number }>()
  return { listed: !!kept?.listed, blocked: !!kept?.blocked, saved: false }
}

// --- the directory --------------------------------------------------------------------------

export interface DirectoryEntry {
  id: string
  url: string
  name: string | null
  grade: string
  score: number
  tools_count: number
  spec_version: string | null
  era: string | null
  partial: number
  auth_required: number
  checked_at: string
  description: string | null
  owner_verified_at: string | null
}

export const PAGE_SIZE = 30

/**
 * A page of the directory. `pinnedUrl` (MCP Check's own server) is always first on page 1, in any
 * sort, when it matches the filters; it's left out of the sorted rows so it never appears twice.
 */
export async function listServers(db: D1Database, q: { search?: string; grade?: string; sort?: 'grade' | 'recent'; page?: number; pinnedUrl?: string }): Promise<{ servers: DirectoryEntry[]; total: number }> {
  await ensureSchema(db)
  const where = ['listed = 1', 'blocked = 0']
  const binds: unknown[] = []
  if (q.pinnedUrl) {
    where.push('url != ?')
    binds.push(q.pinnedUrl)
  }
  if (q.search) {
    // Escape LIKE wildcards so a search for "%" or "_" matches literally.
    const like = `%${q.search.replace(/[\\%_]/g, (c) => `\\${c}`)}%`
    where.push(`(name LIKE ? ESCAPE '\\' OR url LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')`)
    binds.push(like, like, like)
  }
  if (q.grade) {
    where.push('grade = ?')
    binds.push(q.grade)
  }
  const order = q.sort === 'recent' ? 'checked_at DESC' : 'grade ASC, partial ASC, score DESC, name ASC'
  const page = Math.max(1, q.page ?? 1)
  const columns = 'id, url, name, grade, score, tools_count, spec_version, era, partial, auth_required, checked_at, description, owner_verified_at'
  const [rows, count, pinned] = await db.batch([
    db.prepare(`SELECT ${columns} FROM servers WHERE ${where.join(' AND ')} ORDER BY ${order} LIMIT ${PAGE_SIZE} OFFSET ${(page - 1) * PAGE_SIZE}`).bind(...binds),
    db.prepare(`SELECT COUNT(*) AS n FROM servers WHERE ${where.join(' AND ')}`).bind(...binds),
    db.prepare(`SELECT ${columns} FROM servers WHERE url = ? AND listed = 1 AND blocked = 0 ${q.grade ? 'AND grade = ?' : ''}`)
      .bind(...[q.pinnedUrl ?? '', ...(q.grade ? [q.grade] : [])]),
  ])
  const top = q.pinnedUrl && !q.search ? ((pinned?.results ?? []) as DirectoryEntry[]) : []
  const servers = [...(page === 1 ? top : []), ...((rows?.results ?? []) as DirectoryEntry[])]
  return { servers, total: Number((count?.results?.[0] as { n?: number } | undefined)?.n ?? 0) + top.length }
}

/** Every listed server, for the sitemap. */
export async function listedIds(db: D1Database): Promise<{ id: string; checked_at: string }[]> {
  await ensureSchema(db)
  const { results } = await db.prepare(`SELECT id, checked_at FROM servers WHERE listed = 1 AND blocked = 0 ORDER BY checked_at DESC LIMIT 45000`).all<{ id: string; checked_at: string }>()
  return results
}

/** Listed servers whose report is older than `olderThan`, least recently tried first. */
export async function dueForRecheck(db: D1Database, olderThan: string, retryAfter: string, limit: number): Promise<{ id: string; url: string }[]> {
  await ensureSchema(db)
  const { results } = await db
    .prepare(`SELECT id, url FROM servers INDEXED BY servers_recheck WHERE listed = 1 AND blocked = 0 AND authenticated = 0 AND checked_at < ?1
              AND (last_attempt_at IS NULL OR last_attempt_at < ?2) ORDER BY COALESCE(last_attempt_at, checked_at) ASC LIMIT ?3`)
    .bind(olderThan, retryAfter, limit)
    .all<{ id: string; url: string }>()
  return results
}

/** A re-check couldn't reach the server. Three in a row removes it from the directory. */
export async function recordFailure(db: D1Database, id: string): Promise<void> {
  await db
    .prepare(`UPDATE servers SET failures = failures + 1, last_attempt_at = ?2, listed = CASE WHEN failures + 1 >= 3 THEN 0 ELSE listed END WHERE id = ?1`)
    .bind(id, new Date().toISOString())
    .run()
}

/** The owner asked for removal: unlist, and never allow re-listing. */
export async function blockServer(db: D1Database, id: string): Promise<void> {
  // Already removed: nothing to write (anyone can repeat the request while the proof line is up).
  await db.prepare(`UPDATE servers SET listed = 0, blocked = 1, updated_at = ?2 WHERE id = ?1 AND blocked = 0`).bind(id, new Date().toISOString()).run()
}

export async function serverUrl(db: D1Database, id: string): Promise<string | undefined> {
  await ensureSchema(db)
  return (await db.prepare(`SELECT url FROM servers WHERE id = ?`).bind(id).first<string>('url')) ?? undefined
}

export interface StoredServer {
  id: string
  url: string
  name: string | null
  grade: string
  score: number
  partial: number
  checked_at: string
  last_viewed_at: string | null
  listed: number
  blocked: number
  registry_name: string | null
  description: string | null
  repository_url: string | null
  website_url: string | null
  owner_verified_at: string | null
}

export async function loadReport(db: D1Database, id: string): Promise<{ meta: StoredServer; report: Report } | undefined> {
  await ensureSchema(db)
  const row = await db.prepare(`SELECT id, url, name, grade, score, partial, checked_at, last_viewed_at, listed, blocked, registry_name, description, repository_url, website_url, owner_verified_at, report FROM servers WHERE id = ?`).bind(id).first<StoredServer & { report: ArrayBuffer | number[] }>()
  if (!row) return undefined
  const bytes = row.report instanceof ArrayBuffer ? new Uint8Array(row.report) : Uint8Array.from(row.report)
  const report = JSON.parse(await gunzip(bytes)) as Report
  const { report: _blob, ...meta } = row
  return { meta, report }
}

/** Grade only, for badges. */
export async function loadGrade(db: D1Database, id: string): Promise<{ grade: string; score: number; partial: number } | undefined> {
  await ensureSchema(db)
  return (await db.prepare(`SELECT grade, score, partial FROM servers WHERE id = ?`).bind(id).first<{ grade: string; score: number; partial: number }>()) ?? undefined
}

/** Remember that someone looked, at most once a day per report (used to expire unloved reports). */
export async function touch(db: D1Database, meta: StoredServer): Promise<void> {
  if (meta.last_viewed_at && Date.now() - Date.parse(meta.last_viewed_at) < 24 * 60 * 60 * 1000) return
  await db.prepare(`UPDATE servers SET last_viewed_at = ? WHERE id = ?`).bind(new Date().toISOString(), meta.id).run()
}

// --- encoding helpers -----------------------------------------------------------------------

export async function gzip(text: string): Promise<Uint8Array> {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'))
  return new Uint8Array(await new Response(stream).arrayBuffer())
}

export async function gunzip(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))
  return new Response(stream).text()
}

function base64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function fromBase64url(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}

const ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789'
function base32(bytes: Uint8Array): string {
  let out = ''
  let bits = 0
  let value = 0
  for (const b of bytes) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  return out
}
