// The Worker: serves the API. Static files (the app) are served by Cloudflare before this runs.
import { WorkerEntrypoint } from 'cloudflare:workers'
import { Hono } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { runTool } from '../checks/call'
import { runCheck } from '../checks/run'
import type { Exchange } from '../mcp/types'
import { gradeBadge, unknownBadge } from './badge'
import { atomFeed, clearWebhooks, deliverPending, pruneEvents, recentEvents, subscribe, subscriberId, unsubscribe, WebhookError } from './alerts'
import { loadPrivateReport, PRIVATE_ID, PrivateReportTooLarge, purgeExpiredPrivateReports, savePrivateReport } from './private'
import { consumeChallenge, createChallenge, hasProof, hasProofLine, markVerified, proofUrl, reconfirmOwner, type ProofAction } from './owners'
import { handleMcp, OWN_MCP_URL, OWN_ORIGIN, ownProofText } from './mcp-server'
import { claimSignIn, clientMetadata, COOKIE, finishSignIn, PENDING_TTL_S, purgeExpiredSignIns, SignInError, startSignIn } from './oauth'
import { claimAttempt, finishAttempt, nextCandidates, syncDue, syncStep, trustedRegistryLinks, type QueuedServer } from './registry'
import { checksAllowedNow, overBudget, recordUsage, usedToday, WriteMeter } from './budget'
import { rateKey, targetKey, withinLimit } from './ratelimit'
import { directoryPage, refreshSnapshotIfDue, sitemapEntries } from './directory'
import { looksSecret } from '../security/secret-url'
import { refreshStatsIfDue, storedStats } from './stats'
import { backfillToolsText, embedPending, searchServers } from './search'
import { blockServer, canonicalUrl, dueForRecheck, listedIds, listServers, loadGrade, loadReport, PAGE_SIZE, recordFailure, saveReport, serverId, serverUrl, signReport, verifyReceipt } from './store'
import { checkTarget, reserveZone } from '../security/target'
import { verifyTurnstile, type TurnstileEnv } from './turnstile'

export interface Env extends TurnstileEnv {
  /** Local development only: skip Turnstile, and only when the request host is localhost. */
  DEV_SKIP_TURNSTILE?: string
  DB: D1Database
  /** Optional: meaning search. Without these, directory search uses keywords only. */
  AI?: Ai
  VECTORS?: Vectorize
  CHECK_LIMITER: RateLimit
  ASSETS: Fetcher
  /** This Worker's own Checker entrypoint, so each queued check runs as its own invocation. */
  CHECKER?: Service<Checker>
  /** This Worker itself, so checks can reach its own hostname (a Worker can't fetch its own domain). */
  SELF?: Fetcher
}

/**
 * fetch for checks: requests to MCP Check's own hostname go through the SELF binding. For checks a
 * visitor starts (`target` given), every other host the check reaches (OAuth metadata, registration
 * endpoints a server names) also counts against that host's limit, once per check, so nobody can use
 * MCP Check to flood a host by naming it in their own server's metadata.
 */
function checkFetch(env: Env, target?: string): typeof fetch {
  const own = new URL(OWN_ORIGIN).host
  const charged = new Set(target ? [targetKey(target)] : [])
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url)
    if (target) {
      const key = targetKey(url.toString())
      if (!charged.has(key)) {
        charged.add(key)
        const { success } = await env.CHECK_LIMITER.limit({ key })
        if (!success) throw new Error(`${url.hostname} is getting too many requests from MCP Check right now`)
      }
    }
    return url.host === own && env.SELF ? env.SELF.fetch(new Request(input, init)) : fetch(input, init)
  }) as typeof fetch
}

// Checks can't reach MCP Check's own zone (the website and anything else there), only its own host.
reserveZone('nischaldhakal.com.np', ['mcp.nischaldhakal.com.np'])

const app = new Hono<{ Bindings: Env }>()
const VANTAGE = "Cloudflare's network"
/** Used in alerts sent from cron runs, which have no request to take the origin from. */
const SITE_ORIGIN = 'https://mcp.nischaldhakal.com.np'

app.get('/api/health', (c) => c.json({ ok: true }))

// MCP Check's ownership proof for its own server, the same file any owner serves (see owners.ts).
app.get('/.well-known/mcp-check.txt', async (c) => c.text(await ownProofText(), 200, { 'Cache-Control': 'public, max-age=3600' }))

// MCP Check's own MCP server (see src/worker/mcp-server.ts).
app.all('/mcp', (c) => handleMcp(c.req.raw, { env: c.env, ip: c.req.header('CF-Connecting-IP'), fetchFor: (target) => checkFetch(c.env, target) }))

// Headers a visitor may pass through to the server they're checking (auth and custom API keys).
const FORBIDDEN_HEADERS = new Set(['host', 'content-length', 'content-type', 'accept', 'origin', 'cookie', 'connection', 'transfer-encoding', 'mcp-session-id', 'mcp-protocol-version', 'mcp-method', 'mcp-name'])

// Headers that would let a visitor pose as someone else to the server, or as Cloudflare.
const FORBIDDEN_HEADER_PREFIXES = ['cf-', 'x-forwarded-', 'proxy-', 'sec-']
const SPOOFING_HEADERS = new Set(['user-agent', 'forwarded', 'x-real-ip', 'true-client-ip', 'x-client-ip', 'via', 'referer'])

function passThroughHeaders(input: unknown): Record<string, string> | string {
  if (input === undefined) return {}
  if (!input || typeof input !== 'object' || Array.isArray(input)) return 'headers must be an object'
  const out: Record<string, string> = {}
  for (const [name, value] of Object.entries(input)) {
    const lower = name.toLowerCase()
    if (!/^[A-Za-z0-9-]{1,64}$/.test(name) || FORBIDDEN_HEADERS.has(lower) || SPOOFING_HEADERS.has(lower) || FORBIDDEN_HEADER_PREFIXES.some((p) => lower.startsWith(p))) {
      return `Header "${name}" is not allowed.`
    }
    if (typeof value !== 'string' || value.length > 4096 || /[\r\n]/.test(value)) return `Header "${name}" has an invalid value.`
    out[name] = value
  }
  if (Object.keys(out).length > 10) return 'Too many headers (10 at most).'
  return out
}

/** Rate limit + Turnstile + body parsing shared by every endpoint that contacts a server. */
type GuardFail = { status: 400 | 403 | 429 | 500; error: string; message: string }
type GuardResult = { fail: GuardFail } | { fail?: undefined; body: Record<string, unknown>; headers: Record<string, string> }

async function guard(c: { req: { url: string; header(n: string): string | undefined; json(): Promise<unknown> }; env: Env }, action: string): Promise<GuardResult> {
  const ip = c.req.header('CF-Connecting-IP')
  if (!(await withinLimit(c.env.CHECK_LIMITER, ip))) return { fail: { status: 429, error: 'rate-limited', message: 'Too many requests from your network. Try again in a minute.' } }

  const body = (await c.req.json().catch(() => null)) as Record<string, unknown> | null
  if (!body || typeof body !== 'object' || typeof body.url !== 'string' || body.url.length > 2048) {
    return { fail: { status: 400, error: 'bad-request', message: 'Send { "url": "https://…" }.' } }
  }
  const host = new URL(c.req.url).hostname
  const devSkip = c.env.DEV_SKIP_TURNSTILE === '1' && (host === 'localhost' || host === '127.0.0.1')
  const human = devSkip ? ({ ok: true } as const) : await verifyTurnstile(body.token, ip, c.env, action)
  if (!human.ok) {
    console.warn('turnstile rejected', human.reason)
    return { fail: { status: human.reason === 'not-configured' ? 500 : 403, error: 'verification', message: "We couldn't confirm you're human. Please try again." } }
  }
  const headers = passThroughHeaders(body.headers)
  if (typeof headers === 'string') return { fail: { status: 400, error: 'bad-request', message: headers } }
  // Across all visitors, one target host gets a limited number of requests a minute, so nobody can
  // use MCP Check to flood someone else's server.
  const target = await c.env.CHECK_LIMITER.limit({ key: targetKey(body.url) })
  if (!target.success) return { fail: { status: 429, error: 'rate-limited', message: 'That server is being checked a lot right now. Try again in a minute.' } }
  return { body, headers }
}

app.post('/api/check', async (c) => {
  const g = await guard(c, 'check')
  if (g.fail) return c.json({ ok: false, error: g.fail.error, message: g.fail.message }, g.fail.status)
  const log: Exchange[] = []
  const report = await runCheck(g.body.url as string, { headers: g.headers, vantage: VANTAGE, logSink: log, fetch: checkFetch(c.env, g.body.url as string) })
  // A signed copy the visitor can hand back to /api/share: proof this Worker produced the grade.
  const receipt = report.connected || report.auth ? await signReport(c.env.DB, report) : undefined
  return c.json({ ok: true, report, log: trimLog(log), receipt }, 200, { 'Cache-Control': 'no-store' })
})

app.post('/api/call', async (c) => {
  const g = await guard(c, 'call')
  if (g.fail) return c.json({ ok: false, error: g.fail.error, message: g.fail.message }, g.fail.status)
  const { tool, arguments: args } = g.body as { tool?: unknown; arguments?: unknown }
  if (typeof tool !== 'string' || !tool || tool.length > 256) return c.json({ ok: false, error: 'bad-request', message: 'Send the tool name.' }, 400)
  if (args !== undefined && (!args || typeof args !== 'object' || Array.isArray(args))) return c.json({ ok: false, error: 'bad-request', message: 'Arguments must be an object.' }, 400)
  const outcome = await runTool(g.body.url as string, tool, (args ?? {}) as Record<string, unknown>, { headers: g.headers, fetch: checkFetch(c.env, g.body.url as string) })
  return c.json({ ...outcome, log: trimLog(outcome.log) }, 200, { 'Cache-Control': 'no-store' })
})

// --- OAuth sign-in (see src/worker/oauth.ts) ---------------------------------------------------
// The state is tied to the visitor's browser with a cookie, so a sign-in can only be finished and
// claimed by the browser that started it.

app.post('/api/oauth/start', async (c) => {
  const g = await guard(c, 'check')
  if (g.fail) return c.json({ ok: false, error: g.fail.error, message: g.fail.message }, g.fail.status)
  const url = (g.body.url as string).trim()
  const target = checkTarget(url)
  if (!target.ok) return c.json({ ok: false, error: 'invalid', message: target.reason }, 400)
  try {
    const { authorizeUrl, state, issuer } = await startSignIn(c.env.DB, url, new URL(c.req.url).origin)
    setCookie(c, COOKIE, state, { httpOnly: true, secure: true, sameSite: 'Lax', path: '/', maxAge: PENDING_TTL_S, prefix: 'host' })
    // The page shows both hosts and asks before leaving: the token will go to the server being checked.
    return c.json({ ok: true, authorizeUrl, signInHost: new URL(authorizeUrl).hostname, issuer, tokenGoesTo: new URL(url).hostname }, 200, { 'Cache-Control': 'no-store' })
  } catch (err) {
    if (err instanceof SignInError) return c.json({ ok: false, error: 'signin', message: err.message }, 400)
    throw err
  }
})

app.get('/oauth/client.json', (c) => c.json(clientMetadata(new URL(c.req.url).origin), 200, { 'Cache-Control': 'public, max-age=3600' }))

app.get('/oauth/callback', async (c) => {
  const query = new URL(c.req.url).searchParams
  const state = query.get('state') ?? ''
  const back = (url?: string) => c.redirect(`/?${new URLSearchParams({ ...(url ? { url } : {}), signin: '1' })}`, 303)
  if (!state || state !== getCookie(c, COOKIE, 'host')) return back()
  if (!(await withinLimit(c.env.CHECK_LIMITER, c.req.header('CF-Connecting-IP'), 'callback'))) return back()
  return back(await finishSignIn(c.env.DB, state, query))
})

app.post('/api/oauth/claim', async (c) => {
  const state = getCookie(c, COOKIE, 'host')
  deleteCookie(c, COOKIE, { path: '/', secure: true, prefix: 'host' })
  if (!state) return c.json({ ok: false, error: 'signin', message: 'This sign-in expired. Please sign in again.' }, 400, { 'Cache-Control': 'no-store' })
  const result = await claimSignIn(c.env.DB, state)
  return result.ok
    ? c.json(result, 200, { 'Cache-Control': 'no-store' })
    : c.json({ ok: false, error: 'signin', message: result.message }, 400, { 'Cache-Control': 'no-store' })
})

app.post('/api/share', async (c) => {
  if (!(await withinLimit(c.env.CHECK_LIMITER, c.req.header('CF-Connecting-IP')))) return c.json({ ok: false, error: 'rate-limited', message: 'Too many requests. Try again in a minute.' }, 429)
  const body = (await c.req.json().catch(() => null)) as { receipt?: unknown; list?: unknown } | null
  const verified = await verifyReceipt(c.env.DB, body?.receipt)
  if (!verified.ok) return c.json({ ok: false, error: 'invalid', message: verified.reason }, 400)
  const report = verified.report
  if (!report.connected && !report.auth) return c.json({ ok: false, error: 'invalid', message: "Reports for servers that couldn't be reached can't be shared." }, 400)
  const canonical = canonicalUrl(report.url)
  if (!canonical.ok) return c.json({ ok: false, error: 'invalid', message: canonical.reason }, 400)
  const origin = new URL(c.req.url).origin
  if (report.authenticated) {
    try {
      const sig = (body?.receipt as { sig: string }).sig
      const p = await savePrivateReport(c.env.DB, canonical.url, report, sig)
      return c.json({ ok: true, id: p.id, private: true, expiresAt: p.expiresAt, reportUrl: `${origin}/p/${p.id}`, listed: false, blocked: false, saved: true }, 200, { 'Cache-Control': 'no-store' })
    } catch (err) {
      if (err instanceof PrivateReportTooLarge) return c.json({ ok: false, error: 'invalid', message: err.message }, 400)
      throw err
    }
  }
  // A public page belongs to the exact address it was checked at: a variant (like a trailing slash)
  // that behaves differently can't replace the server's listing.
  if (report.url.trim() !== canonical.url) {
    return c.json({ ok: false, error: 'invalid', message: `To share a public report, check the server at ${canonical.url} exactly.` }, 400)
  }
  // URLs that look like they carry a secret in the path are never listed.
  const secret = looksSecret(canonical.url)
  const id = await serverId(canonical.url)
  const saved = await saveReport(c.env.DB, id, canonical.url, report, { list: body?.list === true && !secret })
  return c.json({ ok: true, id, reportUrl: `${origin}/r/${id}`, badgeUrl: `${origin}/badge/${id}.svg`, listed: saved.listed, blocked: saved.blocked, saved: saved.saved, ...(secret ? { notListed: 'secret-url' } : {}) })
})

app.get('/api/report/:id', async (c) => {
  const id = c.req.param('id')
  if (!ID.test(id)) return c.json({ ok: false, error: 'not-found' }, 404)
  const found = await loadReport(c.env.DB, id)
  if (!found || (found.report.authenticated && !found.meta.listed)) return c.json({ ok: false, error: 'not-found', message: 'No report with this id.' }, 404)
  const m = found.meta
  const links = m.registry_name ? trustedRegistryLinks(m.registry_name, m.url, m.website_url, m.repository_url) : undefined
  const registry = m.registry_name ? { name: m.registry_name, description: m.description, ...links } : undefined
  return c.json({ ok: true, id, report: found.report, listed: !!m.listed, blocked: !!m.blocked, verifiedAt: m.owner_verified_at ?? null, registry }, 200, { 'Cache-Control': 'public, max-age=60' })
})

// The public directory: listed servers, searchable and filterable.
app.get('/api/servers', async (c) => {
  const search = (c.req.query('q') ?? '').trim().slice(0, 100)
  const grade = (c.req.query('grade') ?? '').toUpperCase()
  const sortParam = c.req.query('sort')
  const page = Math.min(1000, Math.max(1, Number.parseInt(c.req.query('page') ?? '1', 10) || 1))
  const gradeFilter = /^[ABCDF]$/.test(grade) ? { grade } : {}
  if (!search) {
    // Pages come from the stored directory snapshot (about 30 rows read for any page), are cached at
    // the edge for a minute under validated parameters only, and misses are rate-limited per visitor.
    const pageCache = (caches as unknown as { default: Cache }).default
    const sort = sortParam === 'recent' ? 'recent' : 'grade'
    const pageKey = new Request(new URL(`/api/servers?${new URLSearchParams({ sort, page: String(page), grade: gradeFilter.grade ?? '' })}`, c.req.url))
    const cached = await pageCache.match(pageKey)
    if (cached) return cached
    if (!(await withinLimit(c.env.CHECK_LIMITER, c.req.header('CF-Connecting-IP'), 'list'))) return c.json({ ok: false, error: 'rate-limited', message: 'Too many requests. Try again in a minute.' }, 429)
    const result = await directoryPage(c.env.DB, { sort, page, pageSize: PAGE_SIZE, pinnedUrl: OWN_MCP_URL, ...gradeFilter })
    const res = c.json({ ok: true, ...result, page, pageSize: PAGE_SIZE }, 200, { 'Cache-Control': 'public, max-age=60' })
    c.executionCtx.waitUntil(pageCache.put(pageKey, res.clone()))
    return res
  }

  // Searches cost an embedding each, so identical ones are answered from the edge cache for a minute.
  // The Workers runtime adds caches.default; the DOM types used by the app don't know it.
  const cache = (caches as unknown as { default: Cache }).default
  const key = new Request(new URL(`/api/servers?${new URLSearchParams({ q: search.toLowerCase(), sort: sortParam ?? '', page: String(page), grade })}`, c.req.url))
  const hit = await cache.match(key)
  if (hit) return hit
  if (!(await withinLimit(c.env.CHECK_LIMITER, c.req.header('CF-Connecting-IP'), 'search'))) return c.json({ ok: false, error: 'rate-limited', message: 'Too many searches. Try again in a minute.' }, 429)
  const sort = sortParam === 'recent' || sortParam === 'grade' ? sortParam : 'relevance'
  const result = await searchServers(c.env, { search, sort, page, pageSize: PAGE_SIZE, pinnedUrl: OWN_MCP_URL, ...gradeFilter })
  const res = c.json({ ok: true, ...result, page, pageSize: PAGE_SIZE }, 200, { 'Cache-Control': 'public, max-age=60' })
  c.executionCtx.waitUntil(cache.put(key, res.clone()))
  return res
})

// Owner actions (see src/worker/owners.ts): the server's domain must serve
// /.well-known/mcp-check.txt containing "mcp-check: verify <id>" or "mcp-check: remove <id>".
async function ownerAction(c: { req: { header(n: string): string | undefined; json(): Promise<unknown> }; env: Env }, action: ProofAction) {
  // checkFetch: the proof file may be on this Worker's own domain (MCP Check's own server).
  if (!(await withinLimit(c.env.CHECK_LIMITER, c.req.header('CF-Connecting-IP')))) return { status: 429 as const, body: { ok: false, error: 'rate-limited', message: 'Too many requests. Try again in a minute.' } }
  const body = (await c.req.json().catch(() => null)) as { id?: unknown } | null
  const id = typeof body?.id === 'string' ? body.id : ''
  const url = ID.test(id) ? await serverUrl(c.env.DB, id) : undefined
  if (!url) return { status: 404 as const, body: { ok: false, error: 'not-found', message: 'No server with this id.' } }
  if (!(await hasProof(url, id, action, checkFetch(c.env)))) {
    return { status: 400 as const, body: { ok: false, error: 'unverified', message: `Couldn't find "mcp-check: ${action} ${id}" at ${proofUrl(url)}.` } }
  }
  return { status: 200 as const, id }
}

// Removal: the server is unlisted, and stays unlisted until its owner verifies again.
app.post('/api/unlist', async (c) => {
  const r = await ownerAction(c, 'remove')
  if (r.status !== 200) return c.json(r.body, r.status)
  await blockServer(c.env.DB, r.id)
  return c.json({ ok: true, message: "Removed from the directory. To list it again later, serve the verify line and press Verify." })
})

// A verified owner (the same proof) removes every webhook on their server.
// A server's owner removes every webhook on it. A permanent proof line isn't enough (anyone could
// repeat it), so this takes a one-time code: ask for one, serve "mcp-check: clear-alerts <id> <code>",
// then send the code back.
app.post('/api/owner/clear-alerts', async (c) => {
  if (!(await withinLimit(c.env.CHECK_LIMITER, c.req.header('CF-Connecting-IP')))) return c.json({ ok: false, error: 'rate-limited', message: 'Too many requests. Try again in a minute.' }, 429)
  const body = (await c.req.json().catch(() => null)) as { id?: unknown; code?: unknown } | null
  const id = typeof body?.id === 'string' ? body.id : ''
  const url = ID.test(id) ? await serverUrl(c.env.DB, id) : undefined
  if (!url) return c.json({ ok: false, error: 'not-found', message: 'No server with this id.' }, 404)
  if (typeof body?.code !== 'string') {
    const challenge = await createChallenge(c.env.DB, id)
    return c.json({ ok: true, step: 'serve', code: challenge.nonce, line: challenge.line, proofUrl: proofUrl(url) }, 200, { 'Cache-Control': 'no-store' })
  }
  const line = `mcp-check: clear-alerts ${id} ${body.code}`
  if (!(await hasProofLine(url, line, checkFetch(c.env)))) {
    return c.json({ ok: false, error: 'unverified', message: `Couldn't find "${line}" at ${proofUrl(url)}.` }, 400)
  }
  if (!(await consumeChallenge(c.env.DB, id, body.code))) return c.json({ ok: false, error: 'expired', message: 'That code was already used or has expired. Ask for a new one.' }, 400)
  const removed = await clearWebhooks(c.env.DB, id)
  return c.json({ ok: true, step: 'done', removed, message: removed ? `Removed ${removed} webhook${removed === 1 ? '' : 's'}. You can take the line down now.` : 'There were no webhooks on this server.' })
})

// Verification: the server page shows a verified-owner badge while the proof stays up.
app.post('/api/verify', async (c) => {
  const r = await ownerAction(c, 'verify')
  if (r.status !== 200) return c.json(r.body, r.status)
  const { at, relisted } = await markVerified(c.env.DB, r.id)
  const message = relisted
    ? "Verified, and listed in the directory again. You can take down the remove line if it's still there."
    : "Verified. This server's page now shows you as its owner."
  return c.json({ ok: true, verifiedAt: at, relisted, message })
})

// Progress of the registry import and the directory size.
// Public numbers about the directory, refreshed every 30 minutes by the cron run. Other sites may
// read them (the launch post on nischaldhakal.com.np shows them live).
app.get('/api/stats', async (c) => {
  const cache = (caches as unknown as { default: Cache }).default
  const key = new Request(new URL('/api/stats', c.req.url))
  const hit = await cache.match(key)
  if (hit) return hit
  const res = c.json(await storedStats(c.env.DB), 200, { 'Cache-Control': 'public, max-age=300', 'Access-Control-Allow-Origin': '*' })
  c.executionCtx.waitUntil(cache.put(key, res.clone()))
  return res
})


// --- alerts (see src/worker/alerts.ts) ------------------------------------------------------

const ATOM = { 'Content-Type': 'application/atom+xml; charset=utf-8', 'Cache-Control': 'public, max-age=300' }

app.get('/feed.xml', async (c) => {
  const origin = new URL(c.req.url).origin
  const events = await recentEvents(c.env.DB)
  return c.body(atomFeed({ origin, path: '/feed.xml', title: 'MCP Check directory', subtitle: 'Servers added to the MCP Check directory, grade changes, and servers that stopped responding.', link: `${origin}/servers`, events }), 200, ATOM)
})

app.get('/r/:id/feed.xml', async (c) => {
  const id = c.req.param('id')
  const origin = new URL(c.req.url).origin
  const found = ID.test(id) ? await loadGrade(c.env.DB, id) : undefined
  if (!found) return c.text('Not found', 404)
  const [events, server] = await Promise.all([
    recentEvents(c.env.DB, id),
    c.env.DB.prepare(`SELECT name, url FROM servers WHERE id = ?1`).bind(id).first<{ name: string | null; url: string }>(),
  ])
  const name = server?.name || server?.url || id
  return c.body(atomFeed({ origin, path: `/r/${id}/feed.xml`, title: `${name} on MCP Check`, subtitle: `Grade changes for ${name}.`, link: `${origin}/r/${id}`, events }), 200, ATOM)
})

app.post('/api/webhooks', async (c) => {
  const g = await guard(c, 'alerts')
  if (g.fail) return c.json({ ok: false, error: g.fail.error, message: g.fail.message }, g.fail.status)
  const serverId = typeof g.body.id === 'string' ? g.body.id : ''
  if (!ID.test(serverId)) return c.json({ ok: false, error: 'not-found', message: 'No server with this id.' }, 404)
  try {
    const subscriber = await subscriberId(rateKey(c.req.header('CF-Connecting-IP')))
    const hook = await subscribe(c.env.DB, serverId, (g.body.url as string).trim(), new URL(c.req.url).origin, subscriber)
    return c.json({ ok: true, ...hook }, 200, { 'Cache-Control': 'no-store' })
  } catch (err) {
    if (err instanceof WebhookError) return c.json({ ok: false, error: 'invalid', message: err.message }, 400)
    throw err
  }
})

// A private report, by its random id. Never cached by shared caches.
app.get('/api/private/:id', async (c) => {
  const found = PRIVATE_ID.test(c.req.param('id')) ? await loadPrivateReport(c.env.DB, c.req.param('id')) : undefined
  if (!found) return c.json({ ok: false, error: 'not-found', message: 'No report with this link.' }, 404, { 'Cache-Control': 'no-store' })
  return c.json({ ok: true, report: found.report, expiresAt: found.expiresAt }, 200, { 'Cache-Control': 'private, no-store', 'X-Robots-Tag': 'noindex' })
})

// The private report page: the app, kept out of search engines.
app.get('/p/:id', async (c) => {
  const page = await c.env.ASSETS.fetch(new Request(new URL('/', c.req.url)))
  const headers = new Headers(page.headers)
  headers.set('X-Robots-Tag', 'noindex, nofollow')
  headers.set('Cache-Control', 'private, no-store')
  headers.set('Referrer-Policy', 'no-referrer')
  return new Response(page.body, { status: 200, headers })
})

app.post('/api/webhooks/:hook/delete', async (c) => {
  const body = (await c.req.json().catch(() => null)) as { secret?: unknown } | null
  const ok = typeof body?.secret === 'string' && (await unsubscribe(c.env.DB, c.req.param('hook'), body.secret))
  return ok ? c.json({ ok: true }) : c.json({ ok: false, error: 'not-found', message: 'No webhook with this id and secret.' }, 404)
})

app.get('/sitemap.xml', async (c) => {
  const cache = (caches as unknown as { default: Cache }).default
  const key = new Request(new URL('/sitemap.xml', c.req.url))
  const hit = await cache.match(key)
  if (hit) return hit
  const origin = new URL(c.req.url).origin
  const servers = await sitemapEntries(c.env.DB, OWN_MCP_URL)
  const ownId = await serverId(OWN_MCP_URL)
  const urls = [
    `<url><loc>${origin}/</loc></url>`,
    `<url><loc>${origin}/servers</loc></url>`,
    `<url><loc>${origin}/r/${ownId}</loc></url>`,
    ...servers.map((s) => `<url><loc>${origin}/r/${s.id}</loc><lastmod>${s.date}</lastmod></url>`),
  ]
  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>\n`
  const res = c.body(xml, 200, { 'Content-Type': 'application/xml; charset=utf-8', 'Cache-Control': 'public, max-age=3600' })
  c.executionCtx.waitUntil(cache.put(key, res.clone()))
  return res
})

app.get('/servers', async (c) => {
  const origin = new URL(c.req.url).origin
  return withMeta(c.env, c.req.url, {
    title: 'MCP server directory: graded public MCP servers · MCP Check',
    description: 'Browse public MCP servers graded A to F on spec compliance, tool quality, OAuth, security and speed. Re-checked every week.',
    url: `${origin}/servers`,
    image: `${origin}/og.png`,
  })
})

// README badge. GitHub caches images through its own proxy, so this is fetched rarely.
app.get('/badge/:file', async (c) => {
  const id = c.req.param('file').replace(/\.svg$/, '')
  const row = ID.test(id) ? await loadGrade(c.env.DB, id) : undefined
  const svg = row ? gradeBadge(row.grade, row.score, !!row.partial) : unknownBadge()
  return c.body(svg, 200, { 'Content-Type': 'image/svg+xml; charset=utf-8', 'Cache-Control': 'public, max-age=3600, s-maxage=3600' })
})

// Shared report pages: the app, with a title and share-preview tags for this report.
app.get('/r/:id', async (c) => {
  const id = c.req.param('id')
  const page = await c.env.ASSETS.fetch(new Request(new URL('/', c.req.url)))
  const found = ID.test(id) ? await loadReport(c.env.DB, id).catch(() => undefined) : undefined
  if (!found || (found.report.authenticated && !found.meta.listed)) return new Response(page.body, { status: 404, headers: page.headers })

  const { report } = found
  const origin = new URL(c.req.url).origin
  const name = report.serverInfo?.title ?? report.serverInfo?.name ?? new URL(report.url).hostname
  const problems = report.checks.filter((x) => x.status === 'fail' || x.status === 'warn').length
  const title = `${name}: grade ${report.grade} (${report.score}/100) · MCP Check`
  const description = `${report.partial ? 'Partial grade (sign-in needed for tools). ' : ''}${report.tools.length} tools · spec ${report.version ?? 'unknown'} · ${problems ? `${problems} thing${problems === 1 ? '' : 's'} to fix` : 'no issues found'}. Checked ${report.checkedAt.slice(0, 10)}.`
  return withMeta(c.env, c.req.url, { title, description, url: `${origin}/r/${id}`, image: `${origin}/og/grade-${report.grade}.png`, feed: { title: `${title} (updates)`, href: `${origin}/r/${id}/feed.xml` } })
})

const ID = /^[a-z2-9]{12}$/

/** The app's HTML with a page-specific title, description and share-preview tags. */
async function withMeta(env: Env, requestUrl: string, m: { title: string; description: string; url: string; image: string; feed?: { title: string; href: string } }): Promise<Response> {
  const page = await env.ASSETS.fetch(new Request(new URL('/', requestUrl)))
  const meta: [string, string, string][] = [
    ['name', 'description', m.description],
    ['property', 'og:type', 'website'],
    ['property', 'og:site_name', 'MCP Check'],
    ['property', 'og:title', m.title],
    ['property', 'og:description', m.description],
    ['property', 'og:url', m.url],
    ['property', 'og:image', m.image],
    ['property', 'og:image:width', '1200'],
    ['property', 'og:image:height', '630'],
    ['name', 'twitter:card', 'summary_large_image'],
  ]
  const feed = m.feed ? `<link rel="alternate" type="application/atom+xml" title="${escapeAttr(m.feed.title)}" href="${escapeAttr(m.feed.href)}">` : ''
  const tags = meta.map(([attr, key, value]) => `<meta ${attr}="${key}" content="${escapeAttr(value)}">`).join('') + `<link rel="canonical" href="${escapeAttr(m.url)}">` + feed
  const rewritten = new HTMLRewriter()
    .on('title', { element: (el) => { el.setInnerContent(m.title) } })
    // Drop the home page's own description and preview tags; these replace them.
    .on('meta[name="description"], meta[property^="og:"], meta[name^="twitter:"], link[rel="canonical"]', { element: (el) => { el.remove() } })
    .on('head', { element: (el) => { el.append(tags, { html: true }) } })
    .transform(new Response(page.body, page))
  const headers = new Headers(rewritten.headers)
  headers.set('Cache-Control', 'public, max-age=60')
  return new Response(rewritten.body, { status: 200, headers })
}

// The cron trigger fires every five minutes. Each run, while today's budgets last (see budget.ts):
// 1. embeds changed servers for search;
// 2. once an hour: tool text for older reports, the stats and directory snapshot when due, expired
//    sign-ins and private links, MCP Check's own server; and once a day, old alert events;
// 3. reads one page of the registry while a (weekly) sync is in progress;
// 4. runs the checks the day's pace allows, up to CHECKERS at once, each through the Checker
//    entrypoint so every check has its own CPU budget (one run alone has 10 ms on the free plan);
//    when the queue is empty, re-checks the listed server with the oldest report instead.
// Everything it writes goes through a WriteMeter; at the end the run records its checks and rows.
const CHECKERS = 4

async function tick(rawEnv: Env) {
  const used = await usedToday(rawEnv.DB)
  if (overBudget(used)) return console.log('daily write budget used', used.rows)
  const meter = new WriteMeter()
  const env = meter.env(rawEnv)
  const now = new Date()
  const hourly = now.getUTCMinutes() < 5
  let checks = 0
  try {
    await embedPending(env).then(
      (n) => n && console.log('embedded', n),
      (err) => console.error('embedding failed', String(err)),
    )
    if (hourly) {
      // Unpacking older reports takes CPU, so it runs in its own invocation.
      const backfill = env.CHECKER ? env.CHECKER.backfill() : backfillToolsText(env.DB).then((n) => ({ n, rows: 0 }))
      await Promise.resolve(backfill).then(
        (r) => {
          meter.rows += r.rows
          if (r.n) console.log('backfilled', r.n)
        },
        (err) => console.error('backfill failed', String(err)),
      )
      await refreshStatsIfDue(env.DB).catch((err) => console.error('stats failed', String(err)))
      await refreshSnapshotIfDue(env.DB, OWN_MCP_URL).catch((err) => console.error('directory snapshot failed', String(err)))
      await purgeExpiredSignIns(env.DB).catch((err) => console.error('sign-in purge failed', String(err)))
      await purgeExpiredPrivateReports(env.DB).catch((err) => console.error('private report purge failed', String(err)))
      await checkOwnServer(env).catch((err) => console.error('own server check failed', String(err)))
      if (now.getUTCHours() === 0) await pruneEvents(env.DB).catch((err) => console.error('event prune failed', String(err)))
    }
    if (await syncDue(env.DB)) {
      await syncStep(env.DB).then(
        (step) => console.log('registry sync', step),
        (err) => console.error('registry sync failed', String(err)),
      )
    }
    // Webhook deliveries, in their own invocation.
    const alerts = env.CHECKER ? env.CHECKER.deliverAlerts() : deliverPending(env.DB, SITE_ORIGIN).then((n) => ({ n, rows: 0 }))
    const allowed = checksAllowedNow(used)
    if (allowed > 0) {
      // Without the binding (tests, misconfiguration), check one server in this run instead.
      const checker = env.CHECKER
      const runs = checker
        ? Array.from({ length: Math.min(CHECKERS, allowed) }, () => checker.checkNext())
        : [checkNext(env).then((checked) => ({ checked, rows: 0 }))]
      const results = await Promise.all(runs.map((r) => Promise.resolve(r).catch((err) => (console.error('checker failed', String(err)), { checked: false, rows: 0 }))))
      for (const r of results) meter.rows += r.rows
      checks = results.filter((r) => r.checked).length
      if (!checks) checks = await recheck(env)
    }
    await Promise.resolve(alerts).then(
      (r) => {
        meter.rows += r.rows
        if (r.n) console.log('alerts delivered', r.n)
      },
      (err) => console.error('alerts failed', String(err)),
    )
  } finally {
    await recordUsage(rawEnv.DB, used, checks, meter.rows).catch((err) => console.error('usage record failed', String(err)))
  }
}

/** MCP Check's own MCP server is listed (pinned on top) and re-checked once a day. */
async function checkOwnServer(env: Env) {
  const id = await serverId(OWN_MCP_URL)
  const row = await env.DB.prepare(`SELECT checked_at, owner_verified_at FROM servers WHERE id = ?1`).bind(id).first<{ checked_at: string; owner_verified_at: string | null }>()
  // Verified the same way as any owner: /.well-known/mcp-check.txt on this domain serves the verify line.
  if (row && !row.owner_verified_at && (await hasProof(OWN_MCP_URL, id, 'verify', checkFetch(env)))) await markVerified(env.DB, id)
  const last = row?.checked_at
  if (last && Date.now() - Date.parse(last) < 24 * 60 * 60 * 1000) return
  const report = await runCheck(OWN_MCP_URL, { vantage: VANTAGE, fetch: checkFetch(env) })
  if (!report.connected) return console.error('own server unreachable', report.error)
  await saveReport(env.DB, id, OWN_MCP_URL, report, { list: true })
  await env.DB.prepare(`UPDATE servers SET description = ?2, website_url = ?3, repository_url = ?4 WHERE id = ?1`)
    .bind(id, "MCP Check's own server: check any MCP server against the spec, and search this directory, from your agent.", OWN_ORIGIN, 'https://github.com/DcodeNischal/mcp-check')
    .run()
  if (await hasProof(OWN_MCP_URL, id, 'verify', checkFetch(env))) await markVerified(env.DB, id)
  console.log('own server', report.grade, report.score)
}

/** Checks one queued server per call. The cron run calls it through a service binding to itself. */
// Each method reports the rows it wrote, which count against the cron run's daily write budget.
export class Checker extends WorkerEntrypoint<Env> {
  async checkNext(): Promise<{ checked: boolean; rows: number }> {
    const meter = new WriteMeter()
    const checked = await checkNext(meter.env(this.env))
    return { checked, rows: meter.rows }
  }

  /** Fill in tool text and issues for a few older reports. */
  async backfill(): Promise<{ n: number; rows: number }> {
    const meter = new WriteMeter()
    const n = await backfillToolsText(meter.db(this.env.DB))
    return { n, rows: meter.rows }
  }

  /** Send queued webhook deliveries. */
  async deliverAlerts(): Promise<{ n: number; rows: number }> {
    const meter = new WriteMeter()
    const n = await deliverPending(meter.db(this.env.DB), SITE_ORIGIN)
    return { n, rows: meter.rows }
  }
}

/** Check the next queued server that no other run has claimed. False when the queue is empty. */
async function checkNext(env: Env): Promise<boolean> {
  for (const candidate of await nextCandidates(env.DB, 4)) {
    if (await claimAttempt(env.DB, candidate)) {
      await checkQueued(env, candidate)
      return true
    }
  }
  return false
}

async function checkQueued(env: Env, candidate: QueuedServer) {
  const report = await runCheck(candidate.url, { vantage: VANTAGE, fetch: checkFetch(env) })
  const ok = report.connected || !!report.auth
  if (ok) {
    await saveReport(env.DB, candidate.id, candidate.url, report, {
      list: true,
      registry: { registryName: candidate.registryName, description: candidate.description, repositoryUrl: candidate.repositoryUrl, websiteUrl: candidate.websiteUrl },
    })
  }
  await finishAttempt(env.DB, candidate, ok)
  console.log('registry check', candidate.url, ok ? report.grade : 'unreachable')
}

// Re-check one listed server whose report is over a week old. Three failures in a row unlist it.
/** Re-check the listed server with the oldest report (over a week old). Returns how many it checked. */
async function recheck(env: Env): Promise<number> {
  const now = Date.now()
  const due = await dueForRecheck(env.DB, new Date(now - 7 * 86_400_000).toISOString(), new Date(now - 86_400_000).toISOString(), 1)
  for (const server of due) {
    const report = await runCheck(server.url, { vantage: VANTAGE, fetch: checkFetch(env) })
    if (report.connected || report.auth) await saveReport(env.DB, server.id, server.url, report)
    else await recordFailure(env.DB, server.id)
    await reconfirmOwner(env.DB, server.id, server.url, checkFetch(env)).catch((err) => console.error('owner reconfirm failed', String(err)))
    console.log('recheck', server.id, report.connected || report.auth ? report.grade : 'unreachable')
  }
  return due.length
}

// Any other /api path. Registered last so it never shadows a real route.
app.all('/api/*', (c) => c.json({ ok: false, error: 'not-found' }, 404))

function escapeAttr(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!)
}

/** Keep the raw log useful but bounded: oversized message bodies become a preview. */
function trimLog(log: Exchange[]): Exchange[] {
  const PER_MESSAGE = 64 * 1024
  return log.map((e) => ({
    ...e,
    messages: e.messages.map((m) => {
      const text = JSON.stringify(m)
      return text.length > PER_MESSAGE ? { truncated: true, bytes: text.length, preview: text.slice(0, 2000) } : m
    }),
  }))
}

export default {
  fetch: app.fetch,
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(tick(env).catch((err) => console.error('tick failed', String(err))))
  },
} satisfies ExportedHandler<Env>
