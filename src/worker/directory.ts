// Directory pages and the sitemap read a snapshot of the directory's order, refreshed by the cron run
// every two hours and kept as a single settings row. Sorting and counting thousands of rows on every
// request would let anyone use up the free plan's 5M rows read a day; with the snapshot, any page costs
// about 30 row reads no matter how deep it is.
import { ensureSchema, type DirectoryEntry } from './store'

const SNAPSHOT_EVERY_MS = 2 * 60 * 60 * 1000
export const COLUMNS = 'id, url, name, grade, score, tools_count, spec_version, era, partial, auth_required, checked_at, description, owner_verified_at'
/** The same columns from `s`, for queries that join servers to a list of ids. */
export const S_COLUMNS = COLUMNS.split(', ').map((c) => `s.${c}`).join(', ')

/** Listed servers in grade order: "id|grade|YYYY-MM-DD", plus the indexes of those rows by recency. */
export interface Snapshot {
  at: string
  byGrade: string[]
  byRecent: number[]
}

async function buildSnapshot(db: D1Database, excludeUrl: string): Promise<Snapshot> {
  const { results } = await db
    .prepare(`SELECT id, grade, checked_at FROM servers WHERE listed = 1 AND blocked = 0 AND url != ?1
              ORDER BY grade ASC, partial ASC, score DESC, name ASC`)
    .bind(excludeUrl)
    .all<{ id: string; grade: string; checked_at: string }>()
  const byGrade = results.map((r) => `${r.id}|${r.grade}|${r.checked_at.slice(0, 10)}`)
  const byRecent = results.map((_, i) => i).sort((a, b) => results[b]!.checked_at.localeCompare(results[a]!.checked_at))
  return { at: new Date().toISOString(), byGrade, byRecent }
}

/** The stored snapshot, built on the spot only if there isn't one yet. */
export async function loadSnapshot(db: D1Database, excludeUrl: string): Promise<Snapshot> {
  await ensureSchema(db)
  const row = await db.prepare(`SELECT value FROM settings WHERE key = 'directory_snapshot'`).first<string>('value')
  return row ? (JSON.parse(row) as Snapshot) : refreshSnapshot(db, excludeUrl)
}

export async function refreshSnapshot(db: D1Database, excludeUrl: string): Promise<Snapshot> {
  const snap = await buildSnapshot(db, excludeUrl)
  await db.prepare(`INSERT INTO settings (key, value) VALUES ('directory_snapshot', ?1) ON CONFLICT (key) DO UPDATE SET value = ?1`).bind(JSON.stringify(snap)).run()
  return snap
}

/** Rebuild the snapshot if it's over two hours old (from the cron run). */
export async function refreshSnapshotIfDue(db: D1Database, excludeUrl: string): Promise<boolean> {
  const row = await db.prepare(`SELECT value FROM settings WHERE key = 'directory_snapshot'`).first<string>('value')
  const at = row ? Date.parse((JSON.parse(row) as Snapshot).at) : 0
  if (Date.now() - at < SNAPSHOT_EVERY_MS) return false
  await refreshSnapshot(db, excludeUrl)
  return true
}

/**
 * One page of the directory from the snapshot. `pinnedUrl` (MCP Check's own server) is always first
 * on page 1 when it matches the filter. Rows come from the live table, so grades are current; servers
 * unlisted since the snapshot simply drop out.
 */
export async function directoryPage(db: D1Database, q: { sort: 'grade' | 'recent'; grade?: string; page: number; pageSize: number; pinnedUrl: string }): Promise<{ servers: DirectoryEntry[]; total: number }> {
  const snap = await loadSnapshot(db, q.pinnedUrl)
  const order = q.sort === 'recent' ? snap.byRecent.map((i) => snap.byGrade[i]!) : snap.byGrade
  const entries = q.grade ? order.filter((e) => e.split('|')[1] === q.grade) : order
  const start = (q.page - 1) * q.pageSize
  const ids = entries.slice(start, start + q.pageSize).map((e) => e.split('|')[0]!)
  const [rows, pinned] = await db.batch([
    // CROSS JOIN keeps the id list as the outer loop, so each row is one primary-key lookup. With
    // "id IN (...)" D1 preferred scanning the whole listed index: every page read every server.
    db.prepare(`SELECT ${S_COLUMNS} FROM json_each(?1) AS j CROSS JOIN servers AS s ON s.id = j.value WHERE s.listed = 1 AND s.blocked = 0`).bind(JSON.stringify(ids)),
    db.prepare(`SELECT ${COLUMNS} FROM servers WHERE url = ?1 AND listed = 1 AND blocked = 0 ${q.grade ? 'AND grade = ?2' : ''}`).bind(...(q.grade ? [q.pinnedUrl, q.grade] : [q.pinnedUrl])),
  ])
  const byId = new Map(((rows?.results ?? []) as DirectoryEntry[]).map((r) => [r.id, r]))
  const top = (pinned?.results ?? []) as DirectoryEntry[]
  const servers = [...(q.page === 1 ? top : []), ...ids.map((id) => byId.get(id)).filter((r): r is DirectoryEntry => !!r)]
  return { servers, total: entries.length + top.length }
}

/** Every listed server for the sitemap, from the snapshot. */
export async function sitemapEntries(db: D1Database, pinnedUrl: string): Promise<{ id: string; date: string }[]> {
  const snap = await loadSnapshot(db, pinnedUrl)
  return snap.byGrade.map((e) => {
    const [id, , date] = e.split('|')
    return { id: id!, date: date! }
  })
}
