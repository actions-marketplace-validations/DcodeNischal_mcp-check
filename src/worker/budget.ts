// Daily limits for background work. The free plan allows 100,000 database row writes and 5M row
// reads a day for the whole Cloudflare account, shared with every other site on it; past the write
// limit, every write fails until midnight UTC. Background work (the registry import, queued checks,
// re-checks, search upkeep) is held well below that, so the rest of the account always has room.
//
// - DAILY_CHECK_BUDGET: background checks a day, re-checks included, spread evenly across the day.
// - DAILY_WRITE_BUDGET: rows background work may write a day, as D1 reports them (index and search
//   rows included). Once it's used, background work stops until midnight UTC.
//
// Checks people run on the website or through the MCP server don't count: they don't write.

export const DAILY_CHECK_BUDGET = 600
export const DAILY_WRITE_BUDGET = 15_000

const DAY_MS = 86_400_000
const KEY = 'budget_day'
const today = (now = Date.now()) => new Date(now).toISOString().slice(0, 10)

export interface UsedToday {
  checks: number
  rows: number
}

/** Background checks and row writes so far today (UTC). */
export async function usedToday(db: D1Database, now = Date.now()): Promise<UsedToday> {
  const value = await db.prepare(`SELECT value FROM settings WHERE key = ?1`).bind(KEY).first<string>('value')
  try {
    const v = JSON.parse(value ?? '{}') as { day?: string; checks?: number; rows?: number }
    if (v.day === today(now)) return { checks: Number(v.checks) || 0, rows: Number(v.rows) || 0 }
  } catch {
    // Unreadable: start the day's count again.
  }
  return { checks: 0, rows: 0 }
}

/** Is today's write budget used up? */
export function overBudget(used: UsedToday): boolean {
  return used.rows >= DAILY_WRITE_BUDGET
}

/**
 * Background checks allowed right now. The day's checks are spread evenly (about one every two and
 * a half minutes), so the directory keeps moving all day instead of using the budget in one burst.
 */
export function checksAllowedNow(used: UsedToday, now = Date.now()): number {
  if (overBudget(used)) return 0
  const elapsed = (now % DAY_MS) / DAY_MS
  const paced = Math.min(DAILY_CHECK_BUDGET, Math.ceil(DAILY_CHECK_BUDGET * elapsed) + 1)
  return Math.max(0, paced - used.checks)
}

/**
 * Add a cron run's checks and row writes to today's totals: one write per run, and none when the
 * run did nothing. Only the cron run writes this, once at its end.
 */
export async function recordUsage(db: D1Database, before: UsedToday, checks: number, rows: number, now = Date.now()): Promise<void> {
  if (checks <= 0 && rows <= 0) return
  const value = JSON.stringify({ day: today(now), checks: before.checks + checks, rows: before.rows + Math.ceil(rows) + 1 })
  await db.prepare(`INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = ?2`).bind(KEY, value).run()
}

/**
 * Counts the rows written through it. Background work runs against a metered database, and the
 * total goes into today's write budget.
 */
export class WriteMeter {
  rows = 0

  db(inner: D1Database): D1Database {
    const add = (r: { meta?: { rows_written?: number; changes?: number } } | undefined) => {
      this.rows += Number(r?.meta?.rows_written ?? r?.meta?.changes ?? 0) || 0
    }
    const wrap = (stmt: D1PreparedStatement): D1PreparedStatement => {
      const metered = {
        inner: stmt,
        bind: (...values: unknown[]) => wrap(stmt.bind(...values)),
        run: async () => {
          const r = await stmt.run()
          add(r)
          return r
        },
        all: async () => {
          const r = await stmt.all()
          add(r)
          return r
        },
        // Through all() so writes with RETURNING are counted too.
        first: async (column?: string) => {
          const r = await stmt.all<Record<string, unknown>>()
          add(r)
          const row = r.results[0]
          if (row === undefined) return null
          return column === undefined ? row : (row[column] ?? null)
        },
        raw: (options?: { columnNames?: boolean }) => stmt.raw(options as { columnNames: true }),
      }
      return metered as unknown as D1PreparedStatement
    }
    return {
      prepare: (sql: string) => wrap(inner.prepare(sql)),
      batch: async (statements: D1PreparedStatement[]) => {
        const results = await inner.batch(statements.map((s) => (s as unknown as { inner?: D1PreparedStatement }).inner ?? s))
        for (const r of results) add(r)
        return results
      },
      exec: (query: string) => inner.exec(query),
      dump: () => inner.dump(),
      withSession: (...args: Parameters<D1Database['withSession']>) => inner.withSession(...args),
    } as unknown as D1Database
  }

  /** The same bindings, with the database metered. */
  env<E extends { DB: D1Database }>(env: E): E {
    return Object.create(env, { DB: { value: this.db(env.DB), enumerable: true } }) as E
  }
}
