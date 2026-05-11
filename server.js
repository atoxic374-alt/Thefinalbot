const express = require('express');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const { exec } = require('child_process');
const { Client, RichPresence, CustomStatus } = require('discord.js-selfbot-v13');
const { getStore } = require('./lib/jsonStore');
const { encrypt, decrypt, tryDecrypt, isEncrypted } = require('./lib/crypto');
const { buildProxyAgents, testProxy, maskProxy } = require('./lib/proxy');
const auth = require('./lib/auth');
const users = require('./lib/users');
const oauth = require('./lib/oauth');
const {
  ctx: userCtx, runWithUser, withUser, currentUserId,
  scopedStore, clientsPool, activeRef, SYSTEM_UID,
} = require('./lib/userScope');
const helmet = require('helmet');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1);
const PORT = 5000;

// Bounded-set helper — prevents Sets used for "first-time-only" warnings or
// dedupe windows from growing without limit. When the cap is hit we drop the
// oldest insertion (Set iteration order = insertion order).
function addBounded(set, value, max) {
  if (!set.has(value) && set.size >= max) {
    const oldest = set.values().next().value;
    if (oldest !== undefined) set.delete(oldest);
  }
  set.add(value);
}

// Bounded-map helper — same idea for Maps with a "ts" field per entry.
function addBoundedMap(map, key, value, max) {
  if (!map.has(key) && map.size >= max) {
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
  map.set(key, value);
}

// ── Security middleware ────────────────────────────────────────────────
// Helmet sets sane HTTP security headers. CSP is disabled because the app
// uses many inline event handlers throughout the legacy frontend; tightening
// CSP would require refactoring every component.
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'same-site' },
}));

app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));

app.use(session({
  name: 'dam.sid',
  secret: auth.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true, // every request extends the cookie's expiry
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // proxy terminates TLS; cookie still flows over HTTPS via proxy
    maxAge: 90 * 24 * 60 * 60 * 1000, // 90 days; device-token cookie is 1y
  },
}));

// API rate limiter — 300 requests / minute / IP for /api/*. SSE endpoints
// bypass via their own keyGenerator? Using global is fine; SSE keeps a
// single open connection rather than spamming requests.
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path.startsWith('/api/auth/') === false && req.path.includes('/stream'),
  message: { success: false, error: 'rate_limited' },
});
app.use('/api/', apiLimiter);

// Stricter limiter on auth endpoints to slow brute force.
const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'too_many_attempts' },
});
app.use('/api/auth/', authLimiter);

// Default Discord-style avatar (used as fallback) — public.
const DEFAULT_AVATAR_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="32" fill="#5865F2"/>
  <path fill="#fff" d="M44.6 19.5c-2.3-1-4.7-1.8-7.3-2.2-.3.6-.7 1.4-1 2-2.7-.4-5.4-.4-8 0-.3-.6-.7-1.4-1-2-2.5.5-5 1.3-7.3 2.3-4.6 6.9-5.8 13.6-5.2 20.2 3.1 2.3 6 3.7 8.9 4.6.7-1 1.4-2 1.9-3.1-1.1-.4-2.1-.9-3.1-1.5.3-.2.5-.4.8-.6 5.9 2.7 12.4 2.7 18.3 0 .3.2.5.4.8.6-1 .6-2 1.1-3.1 1.5.6 1.1 1.2 2.1 1.9 3.1 2.9-.9 5.8-2.3 8.9-4.6.7-7.7-1.2-14.3-5.2-20.2zM25.4 36.1c-1.8 0-3.2-1.6-3.2-3.6s1.4-3.6 3.2-3.6 3.3 1.6 3.2 3.6c0 2-1.4 3.6-3.2 3.6zm13.1 0c-1.8 0-3.2-1.6-3.2-3.6s1.4-3.6 3.2-3.6 3.3 1.6 3.2 3.6c0 2-1.4 3.6-3.2 3.6z"/>
</svg>`;
app.get('/discord.png', (req, res) => {
  res.set('Content-Type', 'image/svg+xml').send(DEFAULT_AVATAR_SVG);
});
app.get('/favicon.ico', (req, res) => {
  res.set('Content-Type', 'image/svg+xml').send(DEFAULT_AVATAR_SVG);
});

// ── Authentication endpoints (no auth required) ────────────────────
app.get('/login', (req, res) => {
  // Try device-token restore so a returning user lands straight on /
  try { auth.tryRestoreFromDeviceToken(req); } catch {}
  if (req.session?.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'login.html'));
});
app.get('/signup', (req, res) => res.redirect('/login?mode=signup'));

app.get('/api/auth/status', (req, res) => {
  try { auth.tryRestoreFromDeviceToken(req); } catch {}
  // Surface the short-lived Discord verification (used to pre-fill the login
  // form after the user came back from the OAuth round-trip). Expires in 5
  // minutes so a stale session can't be used to phish a username.
  let discordVerifiedFor = null;
  const dv = req.session?.discordVerifiedFor;
  if (dv && (Date.now() - dv.ts) < 5 * 60 * 1000) {
    discordVerifiedFor = {
      username: dv.username,
      avatar: dv.avatar,
      discordUsername: dv.discordUsername,
    };
  } else if (dv) {
    delete req.session.discordVerifiedFor;
  }
  // Also surface a pending Discord identity for the signup pre-fill.
  let pendingDiscord = null;
  if (req.session?.pendingDiscord) {
    pendingDiscord = {
      username: req.session.pendingDiscord.username,
      avatar: req.session.pendingDiscord.avatar,
    };
  }
  res.json({
    success: true,
    initialized: users.count() > 0,
    authed: !!(req.session && req.session.user),
    user: req.session?.user ? users.publicUser(users.findById(req.session.user.id)) : null,
    discordOAuth: oauth.isConfigured(),
    discordVerifiedFor,
    pendingDiscord,
  });
});

// Sign up: create a new account with username + password.
// Optionally include `linkPendingDiscord: true` to link a Discord identity
// the user just authorised in this session (kept in `req.session.pendingDiscord`).
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    let discord = null;
    if (req.session?.pendingDiscord) discord = req.session.pendingDiscord;
    const u = await users.createUser({ username, password, discord });
    delete req.session.pendingDiscord;
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ success: false, error: 'session_error' });
      req.session.user = { id: u.id, username: u.username, loginAt: Date.now() };
      users.touchLogin(u.id);
      // Always issue a long-lived device token so the user never has to log in
      // again from this browser unless they explicitly log out.
      try {
        const tok = users.issueDeviceToken(u.id, { ua: req.headers['user-agent'], ip: req.ip });
        auth.setDeviceCookie(res, tok);
      } catch {}
      res.json({ success: true, user: users.publicUser(users.findById(u.id)) });
    });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const ip = req.ip;
    const delay = auth._failureDelay(ip);
    if (delay) await new Promise(r => setTimeout(r, delay));
    const { username, password } = req.body || {};
    const u = await users.verifyPassword(username, password);
    if (!u) {
      auth._noteFailure(ip);
      return res.status(401).json({ success: false, error: 'invalid_credentials' });
    }
    auth._clearFailures(ip);
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ success: false, error: 'session_error' });
      req.session.user = { id: u.id, username: u.username, loginAt: Date.now() };
      users.touchLogin(u.id);
      // Always issue a long-lived device token — once the user logs in here,
      // this browser stays signed in until they hit Logout.
      try {
        const tok = users.issueDeviceToken(u.id, { ua: req.headers['user-agent'], ip: req.ip });
        auth.setDeviceCookie(res, tok);
      } catch {}
      res.json({ success: true, user: users.publicUser(users.findById(u.id)) });
    });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
});

app.post('/api/auth/logout', (req, res) => {
  if (req.session) req.session.destroy(() => {});
  auth.clearDeviceCookie(res);
  res.clearCookie('dam.sid');
  res.json({ success: true });
});

// Change password (requires current session)
app.post('/api/auth/change-password', async (req, res) => {
  if (!req.session?.user) return res.status(401).json({ success: false, error: 'unauthorized' });
  try {
    const { oldPassword, newPassword } = req.body || {};
    await users.changePassword(req.session.user.id, oldPassword, newPassword);
    // Revoke all device tokens on password change for safety
    users.revokeAllDevices(req.session.user.id);
    auth.clearDeviceCookie(res);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
});

// ── Discord OAuth ────────────────────────────────────────────────
// Two intents: 'signup' (start signup-via-Discord), 'login' (sign in if linked),
// 'link' (attach Discord to current account).
app.get('/api/auth/discord/start', (req, res) => {
  if (!oauth.isConfigured()) {
    return res.status(503).send('Discord OAuth not configured. Set DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET.');
  }
  const intent = ['signup', 'login', 'link'].includes(req.query.intent) ? req.query.intent : 'login';
  if (intent === 'link' && !req.session?.user) {
    return res.status(401).send('Sign in first to link Discord.');
  }
  const state = oauth.newState();
  req.session.oauthState = state;
  req.session.oauthIntent = intent;
  const url = oauth.authorizeUrl(req, state);
  res.redirect(url);
});

app.get('/api/auth/discord/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query || {};
    if (error) return res.redirect(`/login?error=${encodeURIComponent(String(error))}`);
    if (!code || !state || state !== req.session?.oauthState) {
      return res.redirect('/login?error=invalid_state');
    }
    const intent = req.session.oauthIntent || 'login';
    delete req.session.oauthState;
    delete req.session.oauthIntent;

    const tokenResp = await oauth.exchangeCode(req, String(code));
    const me = await oauth.fetchMe(tokenResp.access_token);
    const discordIdentity = { id: me.id, username: me.username, avatar: me.avatar };

    // Linking Discord to an *already signed-in* account is a one-step write.
    if (intent === 'link' && req.session?.user) {
      try {
        users.linkDiscord(req.session.user.id, discordIdentity);
        return res.redirect('/?linked=discord');
      } catch (e) {
        return res.redirect(`/?error=${encodeURIComponent(e.message)}`);
      }
    }

    // For login/signup intents we NEVER bypass the password step. Discord here
    // is only used to identify which account the user wants to sign into (or
    // to start a signup pre-filled with their Discord identity). The password
    // is still required so a friend with access to their Discord cannot take
    // over their managed-token vault.
    const existing = users.findByDiscordId(me.id);
    if (existing) {
      // Refresh stored discord profile (avatar may have changed) and stash a
      // short-lived "discord verified" hint so the login form can pre-fill the
      // username and show whose account they're signing into.
      users.linkDiscord(existing.id, discordIdentity);
      req.session.discordVerifiedFor = {
        userId: existing.id,
        username: existing.username,
        avatar: discordIdentity.avatar,
        discordUsername: discordIdentity.username,
        ts: Date.now(),
      };
      return res.redirect('/login?mode=login&discord_verified=1');
    }

    // Unknown Discord account → signup pre-filled with the Discord identity.
    // The user must still pick a username and password.
    req.session.pendingDiscord = discordIdentity;
    return res.redirect('/login?mode=signup&discord=1');
  } catch (e) {
    return res.redirect(`/login?error=${encodeURIComponent(e.message || 'oauth_failed')}`);
  }
});

app.post('/api/auth/discord/unlink', (req, res) => {
  if (!req.session?.user) return res.status(401).json({ success: false, error: 'unauthorized' });
  try { users.unlinkDiscord(req.session.user.id); res.json({ success: true }); }
  catch (e) { res.status(400).json({ success: false, error: e.message }); }
});

// Public build-stamp endpoint (no auth needed). The renderer polls this to
// detect when the server has been redeployed and the browser is still running
// stale JS — see watchBuildStamp() in src/api.js. Must be declared BEFORE the
// auth gate or the unauthenticated stale-version check would just trip the
// 401-redirect logic in api.js and silently break.
// Defined here (rather than further down) so the public route can register
// above the auth gate. Reused by the index.html cache-busting rewriter below.
const BUILD_STAMP = String(Date.now());
app.get('/api/build-stamp', (req, res) => res.json({ stamp: BUILD_STAMP }));

// ── Bot-Studio only mode: no auth, always run as system user ──────────
app.use((req, res, next) => {
  userCtx.run({ userId: SYSTEM_UID }, next);
});

// /api/me — current authenticated user (with Discord link, if any)
app.get('/api/me', (req, res) => {
  const u = users.findById(req.session.user.id);
  if (!u) return res.status(401).json({ success: false, error: 'unauthorized' });
  res.json({
    success: true,
    user: users.publicUser(u),
    devices: users.listDevices(u.id),
    discordOAuth: oauth.isConfigured(),
  });
});

// In dev, disable static caching so users always see fresh code without manual refreshes.
// Production keeps default caching for performance.
const IS_PROD = process.env.NODE_ENV === 'production';

// Build stamp is defined above the auth gate (used by /api/build-stamp).
// We rewrite index.html so every <script src="..."> gets a `?v=BUILD_STAMP`
// query, which forces mobile browsers (Chrome/Safari on iOS/Android cache
// aggressively even with no-cache headers) to refetch JS whenever the server
// restarts. Critical because the app loads through a Replit dev proxy that
// can also cache.
function _serveIndexWithCacheBust(res) {
  try {
    const fs = require('fs');
    let html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
    // Append ?v=STAMP (or replace existing one) on every local <script src="...">.
    // Skip absolute URLs (http://, https://, //cdn...) so we don't break CDN scripts.
    html = html.replace(
      /<script\b([^>]*?)\bsrc=(["'])(?!https?:|\/\/)([^"']+?)(?:\?[^"']*)?\2/g,
      (_m, attrs, q, src) => `<script${attrs}src=${q}${src}?v=${BUILD_STAMP}${q}`
    );
    // Expose the stamp to the renderer so it can detect when the server has
    // been redeployed and the user's browser is still running stale JS.
    html = html.replace(
      /<\/head>/i,
      `<script>window.__BUILD_STAMP__=${JSON.stringify(BUILD_STAMP)};</script></head>`
    );
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (e) {
    res.status(500).send('index.html load failed: ' + (e?.message || e));
  }
}
app.get('/', (req, res) => _serveIndexWithCacheBust(res));
app.get('/index.html', (req, res) => _serveIndexWithCacheBust(res));

app.use(express.static(path.join(__dirname), {
  etag: !IS_PROD,
  lastModified: !IS_PROD,
  setHeaders(res, filePath) {
    if (!IS_PROD) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));

// ── Persistent stores (per-user, scoped via AsyncLocalStorage) ─────────
// Each user's data lives under data/users/<userId>/. The scoped wrappers
// transparently resolve to the right per-user JsonStore based on the
// current user context (lib/userScope.js).
const tokensStore = scopedStore('saved_tokens.json', []);
const botTokensStore = scopedStore('bot_tokens.json', []);

// ───────────────────────────────────────────────
// Multi-token client pool — scoped per user (AsyncLocalStorage)
// `clients` is the per-user namespaced view of the global pool. The same
// Map-like API as before, but the current user's id is implicit.
// ───────────────────────────────────────────────
const clients = clientsPool;            // scoped wrapper, see lib/userScope.js

// Per-user "active client name" backed by AsyncLocalStorage.
const _activeProxy = new Proxy({}, {});
// Use accessors instead of bare variable references — required because
// "active" is now per-user. We keep `activeName` and `discordClient`
// identifiers as no-op writable bindings so legacy code that *assigns*
// to them still parses, but reads route through the helpers below.
let activeName = null;                  // legacy mirror — DO NOT READ DIRECTLY
let discordClient = null;               // legacy mirror — DO NOT READ DIRECTLY
function _clearActive() { activeRef.set(null); }

function getActive() { return getActiveClient(); }
function getActiveClient() {
  const n = activeRef.get();
  if (!n) return null;
  const entry = clients.get(n);
  return entry ? entry.client : null;
}
function getClientByName(name) {
  const entry = clients.get(name);
  return entry ? entry.client : null;
}
// True when `userId` belongs to ANY of THIS USER's currently-connected accounts.
// Used to skip self-driven loops (mirror reactions, mention echoes…).
function isOwnConnectedUserId(userId) {
  if (!userId) return false;
  for (const e of clients.values()) {
    if (e?.client?.user?.id === userId) return true;
  }
  return false;
}
function setActive(name) {
  const entry = clients.get(name);
  if (!entry) return false;
  activeRef.set(name);
  return true;
}
// Helper: pick client from `?account=NAME` or `req.body.account`, fall back to active.
function pickClient(req) {
  const name = (req.query?.account || req.body?.account || '').trim();
  if (name) {
    const c = getClientByName(name);
    if (c) return c;
  }
  return getActiveClient();
}

// Default avatar fallback URL Discord uses (based on discriminator/index).
function defaultAvatarUrl(idOrIdx = 0) {
  const i = typeof idOrIdx === 'string' ? Number(BigInt(idOrIdx) >> 22n) % 6 : idOrIdx % 6;
  return `https://cdn.discordapp.com/embed/avatars/${i}.png`;
}

// ───────────────────────────────────────────────
// Anti-detection helpers
// ───────────────────────────────────────────────
function jitter(min, max) {
  return Math.floor(min + Math.random() * (max - min));
}
function sleep(ms) { 
  // Add 10% jitter to all sleeps to avoid fixed patterns
  const jitter = ms * 0.1;
  const finalMs = ms + (Math.random() * jitter * 2 - jitter);
  return new Promise(r => setTimeout(r, finalMs)); 
}

// Browser-like headers so axios calls blend in with the official Discord client.
// Used everywhere we hit the REST API directly (instead of going through
// discord.js-selfbot-v13). Reduces hCaptcha / Cloudflare detection signals.
const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9050 Chrome/124.0.6367.243 Electron/30.2.0 Safari/537.36';
const SUPER_PROPS_B64 = Buffer.from(JSON.stringify({
  os: 'Windows', browser: 'Discord Client', release_channel: 'stable',
  client_version: '1.0.9050', os_version: '10.0.19045', os_arch: 'x64',
  app_arch: 'x64', system_locale: 'en-US', browser_user_agent: BROWSER_UA,
  browser_version: '30.2.0', client_build_number: 312855, native_build_number: 50890,
  client_event_source: null
})).toString('base64');
function discordHeaders(token, extra = {}) {
  return {
    'Authorization': token,
    'User-Agent': BROWSER_UA,
    'Accept': '*/*',
    'Accept-Language': 'en-US',
    'Content-Type': 'application/json',
    'X-Discord-Locale': 'en-US',
    'X-Discord-Timezone': 'Etc/UTC',
    'X-Super-Properties': SUPER_PROPS_B64,
    'X-Debug-Options': 'bugReporterEnabled',
    'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="124", "Discord Client";v="1"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'Origin': 'https://discord.com',
    'Referer': 'https://discord.com/channels/@me',
    ...extra
  };
}

async function humanizedSend(channel, text, { typing = true } = {}) {
  if (typing && channel.sendTyping) {
    try {
      await channel.sendTyping();
      // typing speed ~ 4-7 chars/sec; cap at 4s
      const delay = Math.min(4000, Math.max(600, text.length * jitter(120, 200)));
      await sleep(delay);
    } catch (e) {}
  }
  return channel.send(text);
}

// ───────────────────────────────────────────────
// Smart per-account / per-action cooldown
// Mimics natural human pacing for destructive / spammy operations
// (leave server, close DM, delete message, unfriend, send) so Discord's
// anti-abuse heuristics don't flag the account for "tool-like" speed.
// ───────────────────────────────────────────────
const _coolStore = new Map(); // key → { last:number, recent:number[] }

const COOLDOWN_PROFILES = {
  'leave-server':  { min: 2400, max: 4200, hardMinGap: 2200 },
  'leave-group':   { min: 2400, max: 4200, hardMinGap: 2200 },
  'close-dm':      { min: 2000, max: 3600, hardMinGap: 1900 },
  'delete-msg':    { min: 1800, max: 3200, hardMinGap: 1600 },
  'unfriend':      { min: 2000, max: 3800, hardMinGap: 1900 },
  'send-msg':      { min: 1200, max: 2600, hardMinGap: 1100 },
  'react':         { min:  900, max: 2000, hardMinGap:  800 },
};

function _coolKey(token, action) {
  // Use the last chars of the token as an in-memory id (token is not persisted).
  const id = (typeof token === 'string' ? token : 'anon').slice(-14);
  return `${id}|${action}`;
}

async function humanCooldown(token, action) {
  const prof = COOLDOWN_PROFILES[action];
  if (!prof) return;
  const k = _coolKey(token, action);
  const now = Date.now();
  let st = _coolStore.get(k);
  if (!st) { st = { last: 0, recent: [] }; _coolStore.set(k, st); }

  // keep only last 60 seconds of activity
  st.recent = st.recent.filter(t => now - t < 60000);

  // base wait with jitter
  let wait = jitter(prof.min, prof.max);

  // fatigue: each recent op in the last 60s adds ~8% (capped at +120%)
  const fatigue = Math.min(1.2, st.recent.length * 0.08);
  wait = Math.floor(wait * (1 + fatigue));

  // burst guard: every 7–12 ops inject a longer "breather" (2–5s extra)
  if (st.recent.length > 0 && st.recent.length % jitter(7, 13) === 0) {
    wait += jitter(2000, 5000);
  }

  // enforce hard minimum gap from the previous same-action call
  const sinceLast = now - st.last;
  if (sinceLast < prof.hardMinGap) {
    wait = Math.max(wait, prof.hardMinGap - sinceLast);
  }

  if (wait > 0) await sleep(wait);
  st.last = Date.now();
  st.recent.push(st.last);
}

// periodic cleanup of stale cooldown entries
setInterval(() => {
  const now = Date.now();
  for (const [k, st] of _coolStore) {
    if (now - st.last > 300000) _coolStore.delete(k);
  }
}, 60000).unref?.();

// Standardized error handler
function ok(res, payload = {}) { res.json({ success: true, ...payload }); }
function fail(res, err) {
  const msg = err?.response?.data?.message || err?.message || String(err);
  res.json({ success: false, error: msg });
}

// ───────────────────────────────────────────────
// Validation helpers (used by token save / bio / avatar)
// ───────────────────────────────────────────────
function isLikelyDiscordToken(t) {
  // Discord tokens are base64-ish, ~70+ chars, with two dots separating
  // header.payload.signature. Bot tokens start with `Bot ` typically.
  if (typeof t !== 'string') return false;
  const s = t.trim();
  if (s.length < 50 || s.length > 200) return false;
  // user tokens: 3-part dot-separated, payload ≈ snowflake base64
  return /^[A-Za-z0-9_\-.]{50,200}$/.test(s);
}
function dataUrlSizeBytes(dataUrl) {
  // returns approx decoded byte count for a base64 data: URL
  if (typeof dataUrl !== 'string') return 0;
  const m = dataUrl.match(/^data:([^;]+);base64,(.+)$/);
  if (!m) return 0;
  const b64 = m[2];
  // base64 → bytes: floor(len*3/4) minus padding
  const pad = (b64.endsWith('==') ? 2 : (b64.endsWith('=') ? 1 : 0));
  return Math.max(0, Math.floor(b64.length * 3 / 4) - pad);
}
function dataUrlMime(dataUrl) {
  if (typeof dataUrl !== 'string') return null;
  const m = dataUrl.match(/^data:([^;]+);/);
  return m ? m[1].toLowerCase() : null;
}
const ALLOWED_AVATAR_MIMES = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp'];
const MAX_AVATAR_BYTES = 8 * 1024 * 1024; // Discord caps avatars at ~10MB; keep safety margin
const MAX_BANNER_BYTES = 10 * 1024 * 1024; // Discord caps banners at ~10MB
const MAX_BIO_LEN = 190;
const MAX_CUSTOM_STATUS_LEN = 128;

// ═══════════════════════════════════════════════
//  CONNECT / DISCONNECT (multi-token aware)
// ═══════════════════════════════════════════════

async function connectOne(token, name, proxy) {
  // Capture the owning user once so all derived listeners/timers can run
  // inside this user's AsyncLocalStorage scope.
  const ownerUid = currentUserId();
  const finalName = (name || `acc_${clients.size + 1}`).trim();
  if (clients.has(finalName)) {
    // disconnect previous before re-binding name
    try { await clients.get(finalName).client.destroy(); } catch (e) {}
    clients.delete(finalName);
  }
  const opts = { checkUpdate: false, fetchAllMembers: false };
  if (proxy) {
    try {
      const a = buildProxyAgents(proxy);
      if (a) {
        opts.http = { agent: a.http };
        opts.ws   = { agent: a.ws };
        console.log(`[proxy] ${finalName} → ${maskProxy(proxy)}`);
      }
    } catch (e) {
      throw new Error(`Proxy invalid for ${finalName}: ${e.message}`);
    }
  }
  const client = new Client(opts);
  await client.login(token);
  clients.set(finalName, { client, token, name: finalName, proxy: proxy || null, ownerUid });
  if (!activeRef.get()) setActive(finalName);
  // Auto-bind realtime listeners — wrapped so async events keep user scope.
  // Each attach* helper closes over the captured ownerUid via withUser() inside.
  try { if (typeof attachDMListener === 'function') attachDMListener(finalName, client, ownerUid); } catch (e) {}
  try { if (typeof attachMentionListener === 'function') attachMentionListener(finalName, client, ownerUid); } catch (e) {}
  try { if (typeof attachPicListener === 'function') attachPicListener(finalName, client, ownerUid); } catch (e) {}
  try { if (typeof attachAntiPruneListener === 'function') attachAntiPruneListener(finalName, client, ownerUid); } catch (e) {}
  try { if (typeof attachDMDeleteListener === 'function') attachDMDeleteListener(finalName, client, ownerUid); } catch (e) {}

  // ── Auto-rejoin voice sessions from previous run ──
  // Randomize the initial voice rejoin delay (3s - 7s)
  const rejoinDelay = 3000 + Math.random() * 4000;
  setTimeout(() => withUser(ownerUid, () => {
    try {
      const saved = loadVoicePersist();
      const mine  = saved.filter(s => s.name === finalName);
      for (const s of mine) {
        try {
          const shard = client.ws?.shards?.first?.() || client.ws?.shards?.get?.(0);
          if (!shard) continue;
          shard.send({ op: 4, d: { guild_id: s.guildId, channel_id: s.channelId, self_mute: !!s.selfMute, self_deaf: !!s.selfDeaf, self_video: !!s.selfVideo, self_stream: !!s.selfStream } });
          voiceSessions.set(voiceSessionKey(finalName, s.guildId), { ...s, joinedAt: Date.now() });
        } catch (e) { /* skip failed guild */ }
      }
    } catch (e) { /* non-fatal */ }
  }), rejoinDelay);

  return { name: finalName, username: client.user.tag, id: client.user.id };
}

app.post('/api/discord/connect', async (req, res) => {
  try {
    const { token, name, proxy } = req.body;
    const info = await connectOne(token, name, proxy);
    setActive(info.name);
    try { recordHistory({ account: info.name, type: 'connect', target: { username: info.username, id: info.id }, status: 'success' }); } catch (e) {}
    ok(res, { username: info.username, name: info.name, id: info.id });
  } catch (e) { fail(res, e); }
});

app.post('/api/discord/disconnect', async (req, res) => {
  try {
    if (getActiveClient() && activeRef.get()) {
      const wasName = activeRef.get();
      try { await getActiveClient().destroy(); } catch (e) {}
      clients.delete(activeRef.get());
      activeRef.set(null);
      /* getActiveClient() cleared via activeRef */;
      // promote first remaining client
      const next = clients.keys().next().value;
      if (next) setActive(next);
      try { recordHistory({ account: wasName, type: 'disconnect', target: {}, status: 'success' }); } catch (e) {}
    }
    ok(res);
  } catch (e) { fail(res, e); }
});

app.post('/api/discord/disconnect-all', async (req, res) => {
  try {
    for (const [n, entry] of clients.entries()) {
      try { await entry.client.destroy(); } catch (e) {}
    }
    clients.clear();
    /* getActiveClient() cleared via activeRef */;
    activeRef.set(null);
    ok(res);
  } catch (e) { fail(res, e); }
});

app.get('/api/discord/clients', (req, res) => {
  const list = Array.from(clients.entries()).map(([name, e]) => ({
    name,
    username: e.client.user?.tag || null,
    displayName: e.client.user?.globalName || e.client.user?.username || null,
    id: e.client.user?.id || null,
    avatar: e.client.user?.displayAvatarURL?.() || null,
    status: e.client.user?.presence?.status || 'unknown',
    active: name === activeRef.get()
  }));
  ok(res, { clients: list, active: activeRef.get() });
});

app.post('/api/discord/active', (req, res) => {
  const { name } = req.body;
  if (setActive(name)) return ok(res, { active: activeRef.get() });
  fail(res, new Error('Client not found'));
});

// Auto-connect saved tokens that are flagged autoConnect — for ALL users.
// Each user's tokens are processed inside their own AsyncLocalStorage scope
// so per-user storage and the scoped client pool resolve correctly.
async function autoConnectSaved() {
  try {
    const ids = users.allUserIds();
    for (const uid of ids) {
      await runWithUser(uid, async () => {
        try {
          // Lazy migration of any plaintext-stored tokens for this user.
          migrateTokenEncryptionForCurrentUser();
          const tokens = readTokens();
          for (const t of tokens) {
            if (t.autoConnect) {
              try {
                await connectOne(t.token, t.name, t.proxy);
                console.log(`[auto-connect] ${uid}/${t.name} ✓`);
              } catch (e) {
                console.log(`[auto-connect] ${uid}/${t.name} ✗ ${e.message}`);
              }
            }
          }
        } catch (e) { /* per-user errors should not abort the loop */ }
      });
    }
  } catch (e) {}
}

// ═══════════════════════════════════════════════
//  FRIENDS
// ═══════════════════════════════════════════════
app.get('/api/discord/friends', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected to Discord'));
    const r = await axios.get('https://discord.com/api/v9/users/@me/relationships', {
      headers: { Authorization: c.token }
    });
    const friends = r.data.filter(x => x.type === 1).map(f => ({
      id: f.user.id,
      username: f.user.username,
      displayName: f.user.global_name || f.user.username,
      avatar: f.user.avatar
        ? `https://cdn.discordapp.com/avatars/${f.user.id}/${f.user.avatar}.png?size=64`
        : defaultAvatarUrl(f.user.id),
      bot: !!f.user.bot
    }));
    ok(res, { friends });
  } catch (e) { fail(res, e); }
});

app.delete('/api/discord/friends/:friendId', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    await humanCooldown(c.token, 'unfriend');
    await axios.delete(`https://discord.com/api/v9/users/@me/relationships/${req.params.friendId}`, {
      headers: discordHeaders(c.token)
    });
    ok(res);
  } catch (e) { fail(res, e); }
});

// ═══════════════════════════════════════════════
//  SERVERS
// ═══════════════════════════════════════════════
app.get('/api/discord/servers', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.guilds) return fail(res, new Error('Not connected'));
    // Owners need to manage their own servers too — filtering them out
    // hid them from the entire UI (Servers, Messages, Reactions, Clone…).
    const servers = Array.from(c.guilds.cache.values())
      .filter(s => !!s)
      .map(s => ({
        id: s.id,
        name: s.name,
        icon: s.iconURL({ size: 64, forceStatic: false }) || '/discord.png',
        members: s.memberCount || 0,
        owned: s.ownerId === c.user.id
      }));
    ok(res, { servers });
  } catch (e) { fail(res, e); }
});

app.get('/api/discord/servers/:serverId/channels', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    const r = await axios.get(`https://discord.com/api/v9/guilds/${req.params.serverId}/channels`, {
      headers: discordHeaders(c.token)
    });
    const channels = r.data
      .filter(ch => ch.type === 0 || ch.type === 5) // text + announcement
      .map(ch => ({ id: ch.id, name: ch.name, parent: ch.parent_id }));
    ok(res, { channels });
  } catch (e) { fail(res, e); }
});

app.post('/api/discord/servers/:serverId/leave', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.guilds) return fail(res, new Error('Not connected'));
    const guild = c.guilds.cache.get(req.params.serverId);
    if (!guild) return fail(res, new Error('Server not found'));
    await humanCooldown(c.token, 'leave-server');
    await guild.leave();
    ok(res);
  } catch (e) { fail(res, e); }
});

app.post('/api/discord/servers/:serverId/mute', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    await axios.patch(`https://discord.com/api/v9/users/@me/guilds/${req.params.serverId}/settings`,
      { muted: true },
      { headers: discordHeaders(c.token) });
    ok(res);
  } catch (e) { fail(res, e); }
});

app.post('/api/discord/servers/:serverId/unmute', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    await axios.patch(`https://discord.com/api/v9/users/@me/guilds/${req.params.serverId}/settings`,
      { muted: false },
      { headers: discordHeaders(c.token) });
    ok(res);
  } catch (e) { fail(res, e); }
});

app.post('/api/discord/read-all', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    const guilds = Array.from(c.guilds.cache.values());
    for (const g of guilds) { try { await g.markAsRead(); } catch (e) {} }
    ok(res);
  } catch (e) { fail(res, e); }
});

app.post('/api/discord/servers/:id/read', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    const guild = c.guilds.cache.get(req.params.id);
    if (!guild) return fail(res, new Error('Server not found'));
    try { await guild.markAsRead(); } catch (e) {}
    ok(res);
  } catch (e) { fail(res, e); }
});

// ═══════════════════════════════════════════════
//  DMs
// ═══════════════════════════════════════════════
app.get('/api/discord/dms', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const botsOnly = req.query.botsOnly === 'true' || req.query.botsOnly === '1';
    const list = Array.from(c.channels.cache.values())
      .filter(ch => ch.type === 'DM' && ch.recipient)
      .filter(ch => !botsOnly || !!ch.recipient?.bot);
    const dms = list.map(d => {
      const r = d.recipient;
      const av = r?.displayAvatarURL?.({ size: 64, forceStatic: false })
              || r?.avatarURL?.({ size: 64 })
              || defaultAvatarUrl(r?.id || '0');
      return {
        id: d.id,
        userId: r?.id || '',
        username: r?.username || 'Unknown',
        displayName: r?.globalName || r?.username || 'Unknown',
        avatar: av,
        bot: !!r?.bot
      };
    });
    ok(res, { dms });
  } catch (e) { fail(res, e); }
});

app.get('/api/discord/dms/:channelId/messages', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const channel = await c.channels.fetch(req.params.channelId);
    if (!channel || channel.type !== 'DM') return fail(res, new Error('Invalid DM channel'));
    const { before } = req.query;
    const opts = before ? { before, limit: 100 } : { limit: 100 };
    const msgs = await channel.messages.fetch(opts);
    res.json({
      success: true,
      currentUserId: c.user.id,
      messages: Array.from(msgs.values()).map(m => ({
        id: m.id,
        content: m.content,
        isDeletable: m.author.id === c.user.id && !m.system,
        author: { id: m.author.id }
      }))
    });
  } catch (e) { fail(res, e); }
});

app.delete('/api/discord/dms/:channelId/messages/:messageId', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const channel = await c.channels.fetch(req.params.channelId);
    if (!channel || channel.type !== 'DM') return fail(res, new Error('Invalid DM channel'));
    const m = await channel.messages.fetch(req.params.messageId);
    await humanCooldown(c.token, 'delete-msg');
    await m.delete();
    ok(res);
  } catch (e) { fail(res, e); }
});

app.post('/api/discord/dms/:channelId/close', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const channel = await c.channels.fetch(req.params.channelId);
    if (!channel || channel.type !== 'DM') return fail(res, new Error('Invalid DM channel'));
    await humanCooldown(c.token, 'close-dm');
    await channel.delete();
    ok(res);
  } catch (e) { fail(res, e); }
});

// Open (or find) a DM channel with a user by their userId
app.post('/api/discord/dm/open', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const { userId } = req.body || {};
    if (!userId) return fail(res, new Error('userId required'));
    const user = await c.users.fetch(userId);
    const dm = await user.createDM();
    ok(res, { channelId: dm.id, userId: user.id, username: user.username });
  } catch (e) { fail(res, e); }
});

// ═══════════════════════════════════════════════
//  GROUPS
// ═══════════════════════════════════════════════
app.get('/api/discord/groups', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const groups = Array.from(c.channels.cache.values())
      .filter(ch => ch.type === 'GROUP_DM')
      .map(g => {
        // Generate fallback avatar from recipient names
        const firstNames = Array.from(g.recipients?.values?.() || [])
          .slice(0, 3).map(u => (u.username || '?')[0].toUpperCase()).join('');
        return {
          id: g.id,
          name: g.name || (Array.from(g.recipients?.values?.() || [])
            .slice(0, 3).map(u => u.username).join(', ') || 'Group'),
          icon: g.iconURL?.({ size: 64, forceStatic: false }) || null,
          fallback: firstNames || 'G',
          recipients: g.recipients?.size || 0
        };
      });
    ok(res, { groups });
  } catch (e) { fail(res, e); }
});

app.post('/api/discord/groups/:groupId/leave', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const g = await c.channels.fetch(req.params.groupId);
    if (!g || g.type !== 'GROUP_DM') return fail(res, new Error('Invalid group'));
    await humanCooldown(c.token, 'leave-group');
    await g.delete();
    ok(res);
  } catch (e) { fail(res, e); }
});

app.get('/api/discord/groups/:channelId/messages', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    const { before } = req.query;
    const url = `https://discord.com/api/v9/channels/${req.params.channelId}/messages?limit=100${before ? `&before=${before}` : ''}`;
    const r = await axios.get(url, {
      headers: discordHeaders(c.token)
    });
    res.json({
      success: true,
      currentUserId: c.user.id,
      messages: r.data.map(m => ({ id: m.id, content: m.content, author: { id: m.author.id } }))
    });
  } catch (e) { fail(res, e); }
});

app.delete('/api/discord/groups/:channelId/messages/:messageId', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    await humanCooldown(c.token, 'delete-msg');
    await axios.delete(`https://discord.com/api/v9/channels/${req.params.channelId}/messages/${req.params.messageId}`, {
      headers: discordHeaders(c.token)
    });
    ok(res);
  } catch (e) { fail(res, e); }
});

// ═══════════════════════════════════════════════
//  TOKEN STORAGE (saved tokens with autoConnect)
//  Tokens are encrypted at rest with AES-256-GCM via lib/crypto.js.
//  readTokens()  → decrypted in-memory copies (safe for internal use)
//  writeTokens() → encrypts before persisting
// ═══════════════════════════════════════════════
function readTokens() {
  const raw = tokensStore.read() || [];
  return raw.map(t => ({
    ...t,
    token: t?.token ? (tryDecrypt(t.token) ?? t.token) : t?.token,
    proxy: t?.proxy ? (tryDecrypt(t.proxy) ?? t.proxy) : (t?.proxy || null),
    // Discord account password (used for captcha-protected actions like creating
    // bots, deleting apps, resetting bot tokens). Encrypted at rest.
    accountPassword: t?.accountPassword ? (tryDecrypt(t.accountPassword) ?? t.accountPassword) : '',
  }));
}
function writeTokens(arr) {
  const encrypted = (arr || []).map(t => ({
    ...t,
    token: t?.token ? (isEncrypted(t.token) ? t.token : encrypt(t.token)) : t?.token,
    proxy: t?.proxy ? (isEncrypted(t.proxy) ? t.proxy : encrypt(t.proxy)) : (t?.proxy || null),
    accountPassword: t?.accountPassword
      ? (isEncrypted(t.accountPassword) ? t.accountPassword : encrypt(t.accountPassword))
      : '',
  }));
  tokensStore.write(encrypted);
}

function normalizeAccountName(name) {
  return String(name || '').trim().toLocaleLowerCase();
}

function findSavedTokenByName(name) {
  const target = normalizeAccountName(name);
  if (!target) return null;
  const tokens = readTokens();
  return tokens.find(t => normalizeAccountName(t.name) === target) || null;
}

function discordAuthHint(errLike = {}) {
  const body = errLike?.response?.data || errLike?.body || {};
  const msg = String(body?.message || errLike?.message || '');
  const code = Number(body?.code || 0);
  // Discord can return "2FA required" style errors even when account 2FA is off;
  // this is often step-up verification/challenge for sensitive actions.
  if (code === 60003 || /two[- ]factor|2fa|mfa/i.test(msg)) {
    return 'Discord requested additional account verification for this action (not necessarily that 2FA is enabled).';
  }
  if (/password/i.test(msg)) {
    return 'Discord requested the account password for this action.';
  }
  return '';
}

// One-shot migration runs lazily, the first time a user touches their
// own tokens store. With per-user storage the migration is per-user and
// idempotent (encrypted entries are left alone).
function migrateTokenEncryptionForCurrentUser() {
  try {
    const raw = tokensStore.read() || [];
    const needsMigration = raw.some(t => t?.token && !isEncrypted(t.token));
    if (!needsMigration) return;
    const re = raw.map(t => ({
      ...t,
      token: t?.token && !isEncrypted(t.token) ? encrypt(t.token) : t?.token,
    }));
    tokensStore.write(re);
    console.log(`[security] migrated ${raw.length} saved token(s) to encrypted storage`);
  } catch (e) {
    console.warn('[security] token migration failed:', e.message);
  }
}

app.get('/api/tokens', (req, res) => {
  try {
    const tokens = readTokens();
    // Mark which are connected; mask proxy URL & account password so credentials
    // never reach the UI. Only expose hasPassword so the UI can show a badge.
    const enriched = tokens.map(t => {
      const { accountPassword, ...rest } = t;
      return {
        ...rest,
        connected: clients.has(t.name),
        proxy: t.proxy ? maskProxy(t.proxy) : null,
        hasProxy: !!t.proxy,
        hasPassword: !!(accountPassword && String(accountPassword).length),
      };
    });
    ok(res, { tokens: enriched });
  } catch (e) { fail(res, e); }
});

app.post('/api/tokens', (req, res) => {
  try {
    const { name, token, autoConnect = false, proxy } = req.body;
    const cleanName = String(name || '').trim();
    const cleanToken = String(token || '').trim();
    const cleanProxy = (proxy ?? '').toString().trim() || null;
    if (!cleanName) return fail(res, new Error('Name is required'));
    if (cleanName.length > 64) return fail(res, new Error('Name is too long (max 64 chars)'));
    if (!cleanToken) return fail(res, new Error('Token is required'));
    if (!isLikelyDiscordToken(cleanToken)) {
      return fail(res, new Error('Token does not look like a valid Discord token. Re-copy it from your client/devtools.'));
    }
    if (cleanProxy) {
      try { buildProxyAgents(cleanProxy); }
      catch (e) { return fail(res, new Error('Invalid proxy: ' + e.message)); }
    }
    const tokens = readTokens();
    if (tokens.some(t => t.name === cleanName)) {
      return fail(res, new Error('A token with this name already exists'));
    }
    if (tokens.some(t => t.token === cleanToken)) {
      const dupe = tokens.find(t => t.token === cleanToken);
      return fail(res, new Error(`This token is already saved under "${dupe.name}". Delete the duplicate first.`));
    }
    tokens.push({ name: cleanName, token: cleanToken, autoConnect: !!autoConnect, proxy: cleanProxy });
    writeTokens(tokens);
    try { recordHistory({ account: cleanName, type: 'save_token', target: { name: cleanName }, status: 'success' }); } catch (e) {}
    ok(res);
  } catch (e) { fail(res, e); }
});

app.patch('/api/tokens/:name', (req, res) => {
  try {
    const tokens = readTokens();
    const idx = tokens.findIndex(t => t.name === req.params.name);
    if (idx === -1) return fail(res, new Error('Token not found'));
    // Whitelist patchable fields. Never let arbitrary req.body fields overwrite
    // sensitive credentials (token / accountPassword) — use the dedicated
    // endpoints for those instead.
    const allowed = ['autoConnect'];
    const patch = {};
    for (const k of allowed) if (k in req.body) patch[k] = req.body[k];
    tokens[idx] = { ...tokens[idx], ...patch };
    writeTokens(tokens);
    ok(res);
  } catch (e) { fail(res, e); }
});

// Set or clear the Discord account password for a saved account. The password
// is encrypted at rest and never returned to the UI — only its presence
// (`hasPassword: true/false`) is exposed via GET /api/tokens.
app.put('/api/tokens/:name/password', (req, res) => {
  try {
    const tokens = readTokens();
    const idx = tokens.findIndex(t => t.name === req.params.name);
    if (idx === -1) return fail(res, new Error('Account not found'));
    const pw = String(req.body?.password ?? '').trim();
    tokens[idx].accountPassword = pw; // writeTokens will encrypt
    writeTokens(tokens);
    ok(res, { hasPassword: !!pw });
  } catch (e) { fail(res, e); }
});

app.delete('/api/tokens/:name', (req, res) => {
  try {
    const tokens = readTokens().filter(t => t.name !== req.params.name);
    writeTokens(tokens);
    try { recordHistory({ account: req.params.name, type: 'delete_token', target: { name: req.params.name }, status: 'success' }); } catch (e) {}
    ok(res);
  } catch (e) { fail(res, e); }
});

// Connect a saved token (without putting it as the active one if there is one already)
app.post('/api/tokens/:name/connect', async (req, res) => {
  try {
    const t = readTokens().find(x => x.name === req.params.name);
    if (!t) return fail(res, new Error('Token not found'));
    const info = await connectOne(t.token, t.name, t.proxy);
    try { recordHistory({ account: info.name, type: 'connect', target: { username: info.username, id: info.id }, status: 'success' }); } catch (e) {}
    ok(res, info);
  } catch (e) { fail(res, e); }
});

// ── Proxy management for a saved account
// If the account is currently connected, transparently reconnect through the
// new proxy so the user does not need to manually disconnect/reconnect.
app.put('/api/tokens/:name/proxy', async (req, res) => {
  try {
    const tokens = readTokens();
    const idx = tokens.findIndex(t => t.name === req.params.name);
    if (idx === -1) return fail(res, new Error('Token not found'));
    const raw = (req.body?.proxy ?? '').toString().trim();
    if (raw) {
      // Validate by attempting to build the agents (throws on bad URL/scheme).
      try { buildProxyAgents(raw); }
      catch (e) { return fail(res, new Error('Invalid proxy: ' + e.message)); }
      tokens[idx].proxy = raw;
    } else {
      tokens[idx].proxy = null;
    }
    writeTokens(tokens);

    // ── Auto-reconnect if the account is currently connected ──
    let reconnected = false;
    const entry = clients.get(req.params.name);
    if (entry?.client) {
      const wasActive = activeRef.get() === req.params.name;
      try { await entry.client.destroy(); } catch (e) {}
      clients.delete(req.params.name);
      try {
        const decryptedToken = isEncrypted(tokens[idx].token) ? decrypt(tokens[idx].token) : tokens[idx].token;
        await connectOne(decryptedToken, tokens[idx].name, tokens[idx].proxy);
        if (wasActive) setActive(tokens[idx].name);
        reconnected = true;
      } catch (e) {
        console.warn(`[proxy] auto-reconnect failed for ${tokens[idx].name}: ${e.message}`);
      }
    }
    ok(res, {
      proxy: tokens[idx].proxy ? maskProxy(tokens[idx].proxy) : null,
      reconnected,
    });
  } catch (e) { fail(res, e); }
});

app.post('/api/tokens/:name/proxy/test', async (req, res) => {
  try {
    // Allow ad-hoc test (body.proxy) OR test the currently-saved one.
    let raw = (req.body?.proxy ?? '').toString().trim();
    if (!raw) {
      const t = readTokens().find(x => x.name === req.params.name);
      if (!t || !t.proxy) return fail(res, new Error('No proxy set for this account'));
      raw = t.proxy;
    }
    const r = await testProxy(raw);
    ok(res, { ok: true, ip: r.ip, masked: maskProxy(raw) });
  } catch (e) { fail(res, e); }
});

app.post('/api/tokens/:name/disconnect', async (req, res) => {
  try {
    const entry = clients.get(req.params.name);
    if (!entry) return fail(res, new Error('Not connected'));
    try { await entry.client.destroy(); } catch (e) {}
    clients.delete(req.params.name);
    if (activeName === req.params.name) {
      activeRef.set(null);
      /* getActiveClient() cleared via activeRef */;
      const next = clients.keys().next().value;
      if (next) setActive(next);
    }
    try { recordHistory({ account: req.params.name, type: 'disconnect', target: {}, status: 'success' }); } catch (e) {}
    ok(res);
  } catch (e) { fail(res, e); }
});

// ═══════════════════════════════════════════════
//  PRESENCE / STATUS / BIO
// ═══════════════════════════════════════════════
const statusRotations = new Map();   // name -> intervalId

function resolvePresence(s) {
  const v = String(s || '').toLowerCase();
  if (['online','idle','dnd','invisible','offline'].includes(v)) return v === 'offline' ? 'invisible' : v;
  return 'online';
}
function resolveTargetsOrFail(tokens = []) {
  const targets = (Array.isArray(tokens) && tokens.length ? tokens : (activeRef.get() ? [activeRef.get()] : []));
  return targets;
}

// ── Streaming URL validator — Discord only shows the streaming badge for Twitch / YouTube
function isValidStreamUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const h = new URL(url).hostname.replace(/^www\./, '');
    return ['twitch.tv', 'youtube.com', 'youtu.be'].includes(h);
  } catch { return false; }
}

app.post('/api/presence/set', async (req, res) => {
  try {
    const { tokens = [], status, customStatus, activity, emoji } = req.body;
    const targets = resolveTargetsOrFail(tokens);
    if (!targets.length) return fail(res, new Error('No target accounts selected'));
    if (activity) {
      if (!activity.name || typeof activity.name !== 'string' || activity.name.trim().length < 2) {
        return fail(res, new Error('Activity name must be at least 2 characters'));
      }
      // Validate buttons early
      if (Array.isArray(activity.buttons)) {
        if (activity.buttons.length > 2) return fail(res, new Error('Maximum 2 buttons allowed'));
        for (const btn of activity.buttons) {
          if (!btn.name || !btn.url) return fail(res, new Error('Each button needs name and url'));
          try { new URL(btn.url); } catch { return fail(res, new Error(`Invalid button URL: ${btn.url}`)); }
        }
      }
    }
    if (customStatus !== undefined && typeof customStatus !== 'string') return fail(res, new Error('customStatus must be a string'));
    if (emoji !== undefined && typeof emoji !== 'string') return fail(res, new Error('emoji must be a string'));
    const results = [];
    for (const n of targets) {
      const c = getClientByName(n);
      if (!c) { results.push({ name: n, ok: false, error: 'not connected' }); continue; }
      try {
        const resolvedStatus = status ? resolvePresence(status) : undefined;

        if (customStatus !== undefined) {
          if (resolvedStatus) c.user.setStatus(resolvedStatus);
          const cs = new CustomStatus(c).setState(customStatus || null);
          if (emoji) cs.setEmoji(emoji);
          c.user.setActivity(cs.toJSON ? cs.toJSON() : cs);
        } else if (activity) {
          // Determine whether to use RichPresence builder (supports buttons, images, details…)
          const hasRich = !!(
            activity.details || activity.state ||
            activity.largeImage || activity.smallImage ||
            (activity.buttons && activity.buttons.length) ||
            activity.startTimestamp || activity.endTimestamp
          );

          if (hasRich) {
            const rp = new RichPresence(c)
              .setName(activity.name.trim())
              .setType(activity.type || 0);

            // Streaming URL — must be Twitch or YouTube for the purple badge
            if (activity.type === 1) {
              const streamUrl = isValidStreamUrl(activity.url)
                ? activity.url
                : 'https://twitch.tv/discord'; // safe fallback so streaming badge still appears
              try { rp.setURL(streamUrl); } catch (_) {}
            }

            if (activity.details)    try { rp.setDetails(String(activity.details).slice(0, 128)); }    catch (_) {}
            if (activity.state)      try { rp.setState(String(activity.state).slice(0, 128)); }        catch (_) {}
            if (activity.largeImage) try { rp.setAssetsLargeImage(String(activity.largeImage)); }      catch (_) {}
            if (activity.largeText)  try { rp.setAssetsLargeText(String(activity.largeText).slice(0, 128)); }  catch (_) {}
            if (activity.smallImage) try { rp.setAssetsSmallImage(String(activity.smallImage)); }      catch (_) {}
            if (activity.smallText)  try { rp.setAssetsSmallText(String(activity.smallText).slice(0, 128)); }  catch (_) {}
            if (activity.startTimestamp) try { rp.setStartTimestamp(Number(activity.startTimestamp)); } catch (_) {}
            if (activity.endTimestamp)   try { rp.setEndTimestamp(Number(activity.endTimestamp)); }     catch (_) {}
            if (Array.isArray(activity.buttons)) {
              for (const btn of activity.buttons.slice(0, 2)) {
                try { if (btn.name && btn.url) rp.addButton(String(btn.name).slice(0, 32), btn.url); } catch (_) {}
              }
            }
            if (activity.partySize && activity.partyMax) {
              try {
                const partyId = activity.partyId || `party_${Date.now()}`;
                rp.setParty(partyId, parseInt(activity.partySize), parseInt(activity.partyMax));
              } catch (_) {}
            }
            if (activity.platform)       try { rp.setPlatform(String(activity.platform)); }       catch (_) {}
            if (activity.applicationId)  try { rp.setApplicationId(String(activity.applicationId)); } catch (_) {}
            if (activity.joinSecret)     try { rp.setJoinSecret(String(activity.joinSecret)); }     catch (_) {}

            // setPresence lets us set status + activity atomically
            const payload = { activities: [rp] };
            if (resolvedStatus) payload.status = resolvedStatus;
            c.user.setPresence(payload);
          } else {
            // Simple activity — no rich fields needed
            if (resolvedStatus) c.user.setStatus(resolvedStatus);
            const opts = { type: activity.type || 0 };
            if (activity.type === 1) {
              opts.url = isValidStreamUrl(activity.url) ? activity.url : 'https://twitch.tv/discord';
            }
            c.user.setActivity(activity.name, opts);
          }
        } else {
          // Status-only change
          if (resolvedStatus) c.user.setStatus(resolvedStatus);
        }

        results.push({ name: n, ok: true });
      } catch (e) { results.push({ name: n, ok: false, error: e.message }); }
    }
    const okCount = results.filter(r => r.ok).length;
    ok(res, { results, summary: { total: results.length, ok: okCount, failed: results.length - okCount } });
  } catch (e) { fail(res, e); }
});

app.post('/api/presence/bio', async (req, res) => {
  try {
    const { tokens = [], bio = '' } = req.body;
    // Discord rejects bios > 190 chars with a 400 — surface a clean error early
    if (typeof bio !== 'string') return fail(res, new Error('Bio must be a string'));
    if (bio.length > MAX_BIO_LEN) {
      return fail(res, new Error(`Bio is too long: ${bio.length}/${MAX_BIO_LEN} chars. Discord rejects anything longer.`));
    }
    const targets = resolveTargetsOrFail(tokens);
    if (!targets.length) return fail(res, new Error('No target accounts selected'));
    const results = [];
    for (const n of targets) {
      const entry = clients.get(n);
      if (!entry) { results.push({ name: n, ok: false, error: 'not connected' }); continue; }
      try {
        await axios.patch('https://discord.com/api/v9/users/@me/profile',
          { bio },
          { headers: discordHeaders(entry.client.token) });
        results.push({ name: n, ok: true });
      } catch (e) { results.push({ name: n, ok: false, error: e.response?.data?.message || e.message }); }
      await sleep(jitter(300, 800));
    }
    ok(res, { results });
  } catch (e) { fail(res, e); }
});

app.post('/api/presence/profile', async (req, res) => {
  try {
    const { token } = req.body || {};
    const target = token || activeRef.get();
    if (!target) return fail(res, new Error('No target token selected'));
    const entry = clients.get(target);
    if (!entry?.client?.token) return fail(res, new Error('Target is not connected'));
    const headers = discordHeaders(entry.client.token);
    const [me, profile] = await Promise.all([
      axios.get('https://discord.com/api/v9/users/@me', { headers }),
      axios.get('https://discord.com/api/v9/users/@me/profile', { headers })
    ]);
    const d = me.data || {};
    const p = profile.data || {};
    const avatar = d.avatar ? `https://cdn.discordapp.com/avatars/${d.id}/${d.avatar}.${String(d.avatar).startsWith('a_') ? 'gif' : 'png'}?size=256` : null;
    const banner = d.banner ? `https://cdn.discordapp.com/banners/${d.id}/${d.banner}.${String(d.banner).startsWith('a_') ? 'gif' : 'png'}?size=512` : null;
    ok(res, {
      profile: {
        token: target,
        bio: p?.user_profile?.bio ?? '',
        status: entry.client.user?.presence?.status || 'unknown',
        avatar,
        banner
      }
    });
  } catch (e) { fail(res, e); }
});

// Status rotation — PERSISTED so it survives restarts
function _persistRotations() {
  try {
    const d = readData();
    const out = {};
    for (const [n, info] of statusRotations.entries()) {
      // info may be either the legacy timer id (number) or the new {timer, states, intervalMs} shape
      if (info && info.states) out[n] = { states: info.states, intervalMs: info.intervalMs };
    }
    d.statusRotations = out;
    writeData(d);
  } catch (_) {}
}
function _startRotationFor(n, states, intervalMs) {
  const old = statusRotations.get(n);
  if (old?.timer) clearInterval(old.timer);
  let i = 0;
  const tick = async () => {
    const c = getClientByName(n);
    if (!c) return;
    const s = states[i % states.length]; i++;
    try {
      if (s.status) c.user.setStatus(resolvePresence(s.status));
      if (s.customStatus !== undefined) {
        const cs = new CustomStatus(c).setState(s.customStatus || null);
        if (s.emoji) cs.setEmoji(s.emoji);
        c.user.setActivity(cs.toJSON ? cs.toJSON() : cs);
      }
    } catch (e) {}
  };
  tick();
  const safe = Math.max(15000, intervalMs); // min 15s to be safe
  const timer = setInterval(tick, safe);
  statusRotations.set(n, { timer, states, intervalMs: safe });
}
app.post('/api/presence/rotate/start', (req, res) => {
  try {
    const { tokens = [], states = [], intervalMs = 60000 } = req.body;
    if (!states.length) return fail(res, new Error('No states provided'));
    const targets = resolveTargetsOrFail(tokens);
    if (!targets.length) return fail(res, new Error('No target accounts selected'));
    const safeStates = states.map((s) => ({
      status: resolvePresence(s?.status),
      customStatus: typeof s?.customStatus === 'string' ? s.customStatus.slice(0, 128) : '',
      emoji: typeof s?.emoji === 'string' ? s.emoji.slice(0, 64) : ''
    }));
    const safeInterval = Math.max(15000, parseInt(intervalMs || 60000) || 60000);
    for (const n of targets) _startRotationFor(n, safeStates, safeInterval);
    _persistRotations();
    ok(res, { rotating: targets, intervalMs: safeInterval, states: safeStates.length });
  } catch (e) { fail(res, e); }
});

app.post('/api/presence/rotate/stop', (req, res) => {
  try {
    const { tokens = [] } = req.body;
    const targets = (tokens.length ? tokens : Array.from(statusRotations.keys()));
    for (const n of targets) {
      const info = statusRotations.get(n);
      if (info?.timer) { clearInterval(info.timer); }
      statusRotations.delete(n);
    }
    _persistRotations();
    ok(res, { stopped: targets, count: targets.length });
  } catch (e) { fail(res, e); }
});

// Restore rotations after clients connect (give autoConnect a head start)
setTimeout(() => {
  try {
    const d = readData();
    const r = d.statusRotations || {};
    let restored = 0;
    for (const [name, info] of Object.entries(r)) {
      if (!info?.states?.length) continue;
      _startRotationFor(name, info.states, info.intervalMs || 60000);
      restored++;
    }
    if (restored) console.log(`[rotation] restored ${restored} status rotation(s)`);
  } catch (_) {}
}, 12000);

// ── Avatar update (single or many tokens)
app.post('/api/presence/avatar', async (req, res) => {
  try {
    const { tokens = [], avatar } = req.body; // avatar = data URL or http URL
    if (!avatar) return fail(res, new Error('No avatar provided'));
    // Validate format + size for data URLs (URLs are passed through as-is)
    if (typeof avatar === 'string' && avatar.startsWith('data:')) {
      const mime = dataUrlMime(avatar);
      if (!mime || !ALLOWED_AVATAR_MIMES.includes(mime)) {
        return fail(res, new Error(`Unsupported image type "${mime || 'unknown'}". Use PNG, JPG, GIF, or WebP.`));
      }
      const sz = dataUrlSizeBytes(avatar);
      if (sz <= 0) return fail(res, new Error('Could not read image data — re-upload the file.'));
      if (sz > MAX_AVATAR_BYTES) {
        return fail(res, new Error(`Image is too large: ${(sz / (1024*1024)).toFixed(2)} MB. Max ${(MAX_AVATAR_BYTES/(1024*1024)).toFixed(0)} MB.`));
      }
    }
    const targets = resolveTargetsOrFail(tokens);
    if (!targets.length) return fail(res, new Error('No target accounts selected'));
    const results = [];
    for (const n of targets) {
      const c = getClientByName(n);
      if (!c) { results.push({ name: n, ok: false, error: 'not connected' }); continue; }
      try {
        await c.user.setAvatar(avatar);
        results.push({ name: n, ok: true });
      } catch (e) {
        results.push({ name: n, ok: false, error: e.message });
      }
      await sleep(jitter(400, 1000));
    }
    ok(res, { results });
  } catch (e) { fail(res, e); }
});

// ── Banner update (Nitro required by Discord)
app.post('/api/presence/banner', async (req, res) => {
  try {
    const { tokens = [], banner } = req.body; // banner = data URL (data:image/...;base64,...) or null to remove
    // Validate format + size for data URLs (URLs and null are passed through as-is)
    if (typeof banner === 'string' && banner.startsWith('data:')) {
      const mime = dataUrlMime(banner);
      if (!mime || !ALLOWED_AVATAR_MIMES.includes(mime)) {
        return fail(res, new Error(`Unsupported image type "${mime || 'unknown'}". Use PNG, JPG, GIF, or WebP.`));
      }
      const sz = dataUrlSizeBytes(banner);
      if (sz <= 0) return fail(res, new Error('Could not read image data — re-upload the file.'));
      if (sz > MAX_BANNER_BYTES) {
        return fail(res, new Error(`Banner is too large: ${(sz / (1024*1024)).toFixed(2)} MB. Max ${(MAX_BANNER_BYTES/(1024*1024)).toFixed(0)} MB.`));
      }
    }
    const targets = resolveTargetsOrFail(tokens);
    if (!targets.length) return fail(res, new Error('No target accounts selected'));
    const results = [];
    for (const n of targets) {
      const entry = clients.get(n);
      if (!entry) { results.push({ name: n, ok: false, error: 'not connected' }); continue; }
      try {
        await axios.patch('https://discord.com/api/v9/users/@me',
          { banner: banner || null },
          { headers: discordHeaders(entry.client.token) });
        results.push({ name: n, ok: true });
      } catch (e) {
        const msg = e.response?.data?.message || e.message;
        const detail = e.response?.data?.errors?.banner?._errors?.[0]?.message;
        results.push({ name: n, ok: false, error: detail || msg });
      }
      await sleep(jitter(400, 1000));
    }
    ok(res, { results });
  } catch (e) { fail(res, e); }
});

// ── Human-like activity simulator (online ↔ idle ↔ invisible at random intervals)
// Persisted across restarts — tracking "running" matters because users start
// it and forget; a server reboot would silently leave their accounts stuck on
// whatever status they had.
const activitySims = new Map(); // name -> { timer, modes, minMs, maxMs }
function _persistActivitySims() {
  try {
    const d = readData();
    const out = {};
    for (const [n, info] of activitySims.entries()) {
      if (info?.modes) out[n] = { modes: info.modes, minMs: info.minMs, maxMs: info.maxMs };
    }
    d.activitySims = out;
    writeData(d);
  } catch (_) {}
}
function _scheduleNextCycle(name, modes, minMs, maxMs) {
  const c = getClientByName(name);
  if (!c) return;
  const next = jitter(minMs, maxMs);
  const id = setTimeout(() => {
    try {
      const cur = c.user.presence?.status || 'online';
      const choices = modes.filter(m => m !== cur);
      const pick = choices.length ? choices[Math.floor(Math.random() * choices.length)] : modes[0];
      c.user.setStatus(resolvePresence(pick));
    } catch (e) {}
    _scheduleNextCycle(name, modes, minMs, maxMs);
  }, next);
  const info = activitySims.get(name) || {};
  activitySims.set(name, { ...info, timer: id, modes, minMs, maxMs });
}

app.post('/api/presence/activity/start', (req, res) => {
  try {
    const { tokens = [], modes = ['online','idle','invisible'], minSec = 60, maxSec = 600 } = req.body;
    const minMs = Math.max(15, parseInt(minSec)) * 1000;
    const maxMs = Math.max(minMs + 1000, parseInt(maxSec) * 1000);
    const targets = (tokens.length ? tokens : (activeRef.get() ? [activeRef.get()] : []));
    for (const n of targets) {
      const old = activitySims.get(n);
      if (old?.timer) clearTimeout(old.timer);
      _scheduleNextCycle(n, modes, minMs, maxMs);
    }
    _persistActivitySims();
    ok(res, { simulating: targets });
  } catch (e) { fail(res, e); }
});

app.post('/api/presence/activity/stop', (req, res) => {
  try {
    const { tokens = [] } = req.body;
    const targets = (tokens.length ? tokens : Array.from(activitySims.keys()));
    for (const n of targets) {
      const info = activitySims.get(n);
      if (info?.timer) clearTimeout(info.timer);
      activitySims.delete(n);
    }
    _persistActivitySims();
    ok(res, { stopped: targets });
  } catch (e) { fail(res, e); }
});

app.get('/api/presence/activity/list', (req, res) => {
  ok(res, { running: Array.from(activitySims.keys()) });
});

// Restore activity simulators after clients reconnect (give autoConnect time)
setTimeout(() => {
  try {
    const d = readData();
    const r = d.activitySims || {};
    let restored = 0;
    for (const [name, info] of Object.entries(r)) {
      if (!info?.modes?.length) continue;
      _scheduleNextCycle(name, info.modes, info.minMs || 60000, info.maxMs || 600000);
      restored++;
    }
    if (restored) console.log(`[activity] restored ${restored} simulator(s)`);
  } catch (_) {}
}, 12000);

// ═══════════════════════════════════════════════
//  MESSAGES MANAGER (send / repeat / schedule)
// ═══════════════════════════════════════════════
const messageJobs = new Map(); // jobId -> { type, timer, info }
let jobCounter = 1;

// Persisted scheduled jobs survive restarts. Repeating jobs are NOT persisted
// because they would silently keep running after a crash without the user
// knowing — schedules are one-shots so we know exactly when they should fire.
function _persistSchedules() {
  try {
    const d = readData();
    const out = {};
    for (const [id, j] of messageJobs.entries()) {
      if (j.type === 'schedule') out[id] = { info: j.info };
    }
    d.scheduledJobs = out;
    writeData(d);
  } catch (_) {}
}
function _restoreSchedules() {
  try {
    const d = readData();
    const sj = d.scheduledJobs || {};
    let restored = 0, expired = 0;
    for (const [id, j] of Object.entries(sj)) {
      const info = j.info;
      if (!info?.runAt) continue;
      const ms = new Date(info.runAt).getTime() - Date.now();
      if (ms < 0) { expired++; continue; }
      // Re-create the timer on this fresh process
      const timer = setTimeout(async () => {
        try {
          await executeSend({ tokens: info.tokens, scope: info.scope, messages: info.messages, mode: info.mode });
        } catch (_) {}
        messageJobs.delete(id);
        _persistSchedules();
      }, ms);
      messageJobs.set(id, { type: 'schedule', timer, info });
      // Keep id-counter ahead of restored ids so new ones don't collide
      const n = parseInt(id, 10);
      if (Number.isFinite(n) && n >= jobCounter) jobCounter = n + 1;
      restored++;
    }
    if (restored || expired) console.log(`[schedule] restored ${restored}, dropped ${expired} expired`);
    if (expired) _persistSchedules();
  } catch (_) {}
}
// Run once at startup (clients may not be ready yet but executeSend handles that)
setTimeout(_restoreSchedules, 5000);

async function resolveTargets(client, scope) {
  // scope: { type: 'channel'|'all_channels'|'all_dms'|'all_groups', serverId?, channelIds?[] }
  if (!client) return [];
  const out = [];
  if (scope.type === 'channel' && scope.channelIds?.length) {
    for (const id of scope.channelIds) {
      try { out.push(await client.channels.fetch(id)); } catch (e) {}
    }
  } else if (scope.type === 'all_channels' && scope.serverId) {
    try {
      const r = await axios.get(`https://discord.com/api/v9/guilds/${scope.serverId}/channels`, {
        headers: { Authorization: client.token }
      });
      const ids = r.data.filter(c => c.type === 0 || c.type === 5).map(c => c.id);
      for (const id of ids) {
        try { out.push(await client.channels.fetch(id)); } catch (e) {}
      }
    } catch (e) {}
  } else if (scope.type === 'all_dms') {
    out.push(...Array.from(client.channels.cache.values()).filter(c => c.type === 'DM'));
  } else if (scope.type === 'all_groups') {
    out.push(...Array.from(client.channels.cache.values()).filter(c => c.type === 'GROUP_DM'));
  }
  return out.filter(Boolean);
}

async function executeSend({ tokens, scope, messages, mode }) {
  // mode: { type: 'fast'|'natural', perMessageDelayMs?, betweenMessagesMs? }
  const targets = (tokens?.length ? tokens : (activeRef.get() ? [activeRef.get()] : []));
  const results = [];
  for (const tName of targets) {
    const client = getClientByName(tName);
    if (!client) { results.push({ token: tName, ok: false, error: 'not connected' }); continue; }
    const channels = await resolveTargets(client, scope);
    for (const ch of channels) {
      for (const text of messages) {
        try {
          if (mode?.type === 'natural') {
            await humanizedSend(ch, text);
          } else {
            await ch.send(text);
          }
          results.push({ token: tName, channel: ch.id, ok: true });
        } catch (e) {
          results.push({ token: tName, channel: ch.id, ok: false, error: e.message });
        }
        // gap between messages (faster default while still staying polite)
        const gap = mode?.type === 'natural'
          ? jitter(1100, 2600)
          : (mode?.perMessageDelayMs ?? 500);
        await sleep(gap);
      }
      // gap between channels
      await sleep(jitter(400, 900));
    }
  }
  return results;
}

app.post('/api/messages/send', async (req, res) => {
  try {
    const { tokens = [], scope, messages = [], mode = { type: 'natural' } } = req.body;
    if (!scope || !messages.length) return fail(res, new Error('scope and messages required'));
    const results = await executeSend({ tokens, scope, messages, mode });
    const targets = (tokens?.length ? tokens : (activeRef.get() ? [activeRef.get()] : []));
    for (const tn of targets) {
      const tr = results.filter(r => r.token === tn);
      recordHistory({
        account: tn, type: 'send', target: scope,
        messages: messages.length, channels: new Set(tr.map(r => r.channel)).size,
        status: tr.length === 0 ? 'failed' : (tr.every(r => r.ok) ? 'success' : (tr.some(r => r.ok) ? 'partial' : 'failed')),
        ok: tr.filter(r => r.ok).length,
        fail: tr.filter(r => !r.ok).length,
        error: tr.find(r => !r.ok)?.error || null
      });
    }
    ok(res, { results });
  } catch (e) { fail(res, e); }
});

app.post('/api/messages/repeat/start', (req, res) => {
  try {
    const { tokens = [], scope, messages = [], mode = { type: 'natural' }, intervalMs = 60000, count = 0 } = req.body;
    if (!scope || !messages.length) return fail(res, new Error('scope and messages required'));
    const id = String(jobCounter++);
    let runs = 0;
    const tick = async () => {
      runs++;
      try { await executeSend({ tokens, scope, messages, mode }); } catch (e) {}
      if (count > 0 && runs >= count) {
        const job = messageJobs.get(id);
        if (job?.timer) clearInterval(job.timer);
        messageJobs.delete(id);
      }
    };
    tick();
    const timer = setInterval(tick, Math.max(2000, intervalMs));
    messageJobs.set(id, { type: 'repeat', timer, info: { tokens, scope, messages, mode, intervalMs, count } });
    ok(res, { jobId: id });
  } catch (e) { fail(res, e); }
});

app.post('/api/messages/schedule', (req, res) => {
  try {
    const { tokens = [], scope, messages = [], mode = { type: 'natural' }, runAt } = req.body;
    if (!scope || !messages.length || !runAt) return fail(res, new Error('scope, messages, runAt required'));
    const ms = new Date(runAt).getTime() - Date.now();
    if (ms < 0) return fail(res, new Error('runAt is in the past'));
    const id = String(jobCounter++);
    const targets = (tokens?.length ? tokens : (activeRef.get() ? [activeRef.get()] : []));
    for (const tn of targets) {
      recordHistory({ account: tn, type: 'schedule', target: scope, messages: messages.length, status: 'pending', runAt });
    }
    const timer = setTimeout(async () => {
      try {
        const r = await executeSend({ tokens, scope, messages, mode });
        for (const tn of targets) {
          const tr = r.filter(x => x.token === tn);
          recordHistory({
            account: tn, type: 'schedule_run', target: scope, messages: messages.length,
            status: tr.length === 0 ? 'failed' : (tr.every(x => x.ok) ? 'success' : (tr.some(x => x.ok) ? 'partial' : 'failed')),
            ok: tr.filter(x => x.ok).length, fail: tr.filter(x => !x.ok).length
          });
        }
      } catch (e) {}
      messageJobs.delete(id);
      _persistSchedules();
    }, ms);
    messageJobs.set(id, { type: 'schedule', timer, info: { tokens, scope, messages, mode, runAt } });
    _persistSchedules();
    ok(res, { jobId: id, runIn: ms });
  } catch (e) { fail(res, e); }
});

app.get('/api/messages/jobs', (req, res) => {
  const list = Array.from(messageJobs.entries()).map(([id, j]) => ({
    id, type: j.type, info: j.info
  }));
  ok(res, { jobs: list });
});

app.post('/api/messages/jobs/:id/stop', (req, res) => {
  const job = messageJobs.get(req.params.id);
  if (!job) return fail(res, new Error('Job not found'));
  if (job.timer) {
    if (job.type === 'repeat') clearInterval(job.timer);
    else clearTimeout(job.timer);
  }
  messageJobs.delete(req.params.id);
  if (job.type === 'schedule') _persistSchedules();
  ok(res);
});

// ═══════════════════════════════════════════════
//  REACTION MANAGER (auto-react / auto-button)
// ═══════════════════════════════════════════════
// One handler per (token, scope) combo
const reactionListeners = new Map(); // listenerId -> { tokens, dispose }

function scopeMatches(scope, msg) {
  if (scope.type === 'all') return true;
  if (scope.type === 'server' && msg.guild?.id === scope.id) return true;
  if (scope.type === 'group' && msg.channel?.type === 'GROUP_DM' && msg.channel.id === scope.id) return true;
  if (scope.type === 'dm' && msg.channel?.type === 'DM' && msg.channel.id === scope.id) return true;
  if (scope.type === 'all_dms' && msg.channel?.type === 'DM') return true;
  if (scope.type === 'all_groups' && msg.channel?.type === 'GROUP_DM') return true;
  if (scope.type === 'all_servers' && msg.guild) return true;
  return false;
}

function attachReactionListener({ tokens, scope, mode, emojis = [], buttonNames = [] }) {
  // mode: 'mirror' | 'specific' (mirror => react with whatever emoji someone else used; specific => use given emojis)
  const id = String(jobCounter++);
  const handlers = [];

  for (const tName of tokens) {
    const c = getClientByName(tName);
    if (!c) continue;
    const clickByCustomIdFallback = async (msg, customId) => {
      try {
        if (!msg?.channel?.id || !msg?.id || !customId || !c?.token) return false;
        await axios.post(`https://discord.com/api/v9/interactions`, {
          type: 3,
          guild_id: msg.guild?.id || null,
          channel_id: msg.channel.id,
          message_id: msg.id,
          application_id: msg.applicationId || msg.author?.id,
          session_id: c.ws?.sessionId || undefined,
          data: { component_type: 2, custom_id: customId }
        }, { headers: discordHeaders(c.token) });
        return true;
      } catch (_) { return false; }
    };

    // Auto-react on new messages
    const onMessage = async (msg) => {
      try {
        if (msg.author?.id === c.user.id) return;
        // Don't auto-react to messages from any of OUR connected accounts
        // (otherwise mirror mode creates a self-reinforcing loop)
        if (isOwnConnectedUserId(msg.author?.id)) return;
        if (!scopeMatches(scope, msg)) return;

        if (mode === 'specific' && emojis.length) {
          for (const em of emojis) {
            try { await msg.react(em); } catch (e) {}
            await sleep(jitter(300, 700));
          }
        }

        // Auto-click buttons — exact label match (case-insensitive, trimmed)
        // to avoid clicking unrelated buttons that happen to contain the keyword
        if (buttonNames.length && msg.components?.length) {
          const wanted = buttonNames.map(n => String(n).trim().toLowerCase()).filter(Boolean);
          for (const row of msg.components) {
            for (const comp of row.components || []) {
              const label = String(comp.label || '').trim().toLowerCase();
              if (label && wanted.includes(label)) {
                try {
                  let clicked = false;
                  if (typeof comp.click === 'function') { await comp.click(msg); clicked = true; }
                  if (!clicked && comp.customId) clicked = await clickByCustomIdFallback(msg, comp.customId);
                } catch (e) {}
                await sleep(jitter(400, 900));
              }
            }
          }
        }
      } catch (e) {}
    };

    // Mirror reactions when others react
    const onReactionAdd = async (reaction, user) => {
      try {
        if (user.id === c.user.id) return;
        // Skip if reactor is one of OUR connected accounts → prevents
        // ping-pong between two accounts watching the same channel.
        if (isOwnConnectedUserId(user.id)) return;
        if (!scopeMatches(scope, reaction.message)) return;
        if (mode === 'mirror') {
          const em = reaction.emoji.id ? `${reaction.emoji.name}:${reaction.emoji.id}` : reaction.emoji.name;
          try { await reaction.message.react(em); } catch (e) {}
        }
      } catch (e) {}
    };

    c.on('messageCreate', onMessage);
    c.on('messageReactionAdd', onReactionAdd);
    handlers.push({ client: c, onMessage, onReactionAdd });
  }

  reactionListeners.set(id, {
    tokens, scope, mode, emojis, buttonNames,
    dispose: () => {
      for (const h of handlers) {
        h.client.off('messageCreate', h.onMessage);
        h.client.off('messageReactionAdd', h.onReactionAdd);
      }
    }
  });
  return id;
}

app.post('/api/reactions/start', (req, res) => {
  try {
    const { tokens = [], scope, mode = 'mirror', emojis = [], buttonNames = [] } = req.body;
    if (!scope) return fail(res, new Error('scope required'));
    if (!['mirror', 'specific'].includes(mode)) return fail(res, new Error('mode must be mirror or specific'));
    if (mode === 'specific' && !emojis.length && !buttonNames.length) return fail(res, new Error('specific mode requires emojis or buttonNames'));
    const targets = (tokens.length ? tokens : (activeRef.get() ? [activeRef.get()] : []));
    if (!targets.length) return fail(res, new Error('No target accounts selected'));
    const saneEmojis = (Array.isArray(emojis) ? emojis : []).map(e => String(e).trim()).filter(Boolean).slice(0, 20);
    const saneButtons = (Array.isArray(buttonNames) ? buttonNames : []).map(b => String(b).trim()).filter(Boolean).slice(0, 20);
    // Prevent duplicated listeners for the exact same payload.
    const key = JSON.stringify({ tokens: [...targets].sort(), scope, mode, emojis: saneEmojis, buttonNames: saneButtons });
    for (const [existingId, l] of reactionListeners.entries()) {
      const k2 = JSON.stringify({ tokens: [...(l.tokens || [])].sort(), scope: l.scope, mode: l.mode, emojis: l.emojis || [], buttonNames: l.buttonNames || [] });
      if (k2 === key) return ok(res, { listenerId: existingId, deduped: true });
    }
    const id = attachReactionListener({ tokens: targets, scope, mode, emojis: saneEmojis, buttonNames: saneButtons });
    ok(res, { listenerId: id, deduped: false });
  } catch (e) { fail(res, e); }
});

app.get('/api/reactions/list', (req, res) => {
  const list = Array.from(reactionListeners.entries()).map(([id, l]) => ({
    id, tokens: l.tokens, scope: l.scope, mode: l.mode, emojis: l.emojis, buttonNames: l.buttonNames
  }));
  ok(res, { listeners: list });
});

app.post('/api/reactions/:id/stop', (req, res) => {
  const l = reactionListeners.get(req.params.id);
  if (!l) return fail(res, new Error('Listener not found'));
  l.dispose();
  reactionListeners.delete(req.params.id);
  ok(res);
});

// ═══════════════════════════════════════════════
//  HISTORY (Old Manager) - kept from before
// ═══════════════════════════════════════════════
function snowflakeToMs(id) { return Number(BigInt(id) >> 22n) + 1420070400000; }

function fmtMsg(msg, channel, guild) {
  const ts = msg.timestamp ? new Date(msg.timestamp).getTime() : snowflakeToMs(msg.id);
  const av = msg.author.avatar
    ? `https://cdn.discordapp.com/avatars/${msg.author.id}/${msg.author.avatar}.png`
    : '/discord.png';
  return {
    id: msg.id,
    content: msg.content || (msg.attachments?.length ? '[Attachment]' : '[Empty message]'),
    timestamp: ts,
    author: {
      id: msg.author.id,
      username: msg.author.username,
      displayName: msg.author.global_name || msg.author.username,
      avatar: av
    },
    channel: channel || null,
    guild: guild || null
  };
}

app.get('/api/history/user/:userId', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    const r = await axios.get(`https://discord.com/api/v9/users/${req.params.userId}`, {
      headers: discordHeaders(c.token)
    });
    const u = r.data;
    ok(res, {
      user: {
        id: u.id,
        username: u.username,
        displayName: u.global_name || u.username,
        avatar: u.avatar ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png` : '/discord.png'
      }
    });
  } catch (e) { res.json({ success: false, error: 'User not found' }); }
});

app.get('/api/history/user-search', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    const query = (req.query.q || '').toLowerCase().replace('@', '');
    const frResp = await axios.get('https://discord.com/api/v9/users/@me/relationships', {
      headers: discordHeaders(c.token)
    });
    const friend = frResp.data.filter(x => x.type === 1).find(r =>
      r.user.username.toLowerCase().includes(query) ||
      (r.user.global_name || '').toLowerCase().includes(query));
    if (friend) {
      const u = friend.user;
      return ok(res, { user: { id: u.id, username: u.username, displayName: u.global_name || u.username, avatar: u.avatar ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png` : '/discord.png' } });
    }
    const dmMatch = Array.from(c.channels.cache.values())
      .filter(ch => ch.type === 'DM' && ch.recipient)
      .find(ch => ch.recipient.username.toLowerCase().includes(query) || (ch.recipient.globalName || '').toLowerCase().includes(query));
    if (dmMatch) {
      const u = dmMatch.recipient;
      return ok(res, { user: { id: u.id, username: u.username, displayName: u.globalName || u.username, avatar: u.avatarURL() || '/discord.png' } });
    }
    fail(res, new Error('User not found in your friends or DMs'));
  } catch (e) { fail(res, e); }
});

app.get('/api/history/dm-first-with/:userId', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    let dm = Array.from(c.channels.cache.values())
      .find(ch => ch.type === 'DM' && ch.recipient?.id === req.params.userId);
    if (!dm) {
      try {
        const user = await c.users.fetch(req.params.userId);
        dm = await user.createDM();
      } catch (e) { return fail(res, new Error('No DM conversation with this user')); }
    }
    const r = await axios.get(`https://discord.com/api/v9/channels/${dm.id}/messages?limit=1&after=0`, { headers: discordHeaders(c.token) });
    if (!r.data.length) return fail(res, new Error('No messages found'));
    ok(res, { message: fmtMsg(r.data[0], { id: dm.id, name: `DM with @${dm.recipient?.username || 'Unknown'}` }, null) });
  } catch (e) { fail(res, e); }
});

app.get('/api/history/oldest-dm', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    const dms = Array.from(c.channels.cache.values())
      .filter(ch => ch.type === 'DM')
      .sort((a, b) => (BigInt(a.id) < BigInt(b.id) ? -1 : 1))
      .slice(0, 30);
    let oldest = null;
    for (const dm of dms) {
      try {
        const r = await axios.get(`https://discord.com/api/v9/channels/${dm.id}/messages?limit=1&after=0`, { headers: discordHeaders(c.token) });
        if (r.data.length) {
          const m = fmtMsg(r.data[0], { id: dm.id, name: `DM with @${dm.recipient?.username || 'Unknown'}` }, null);
          if (!oldest || m.timestamp < oldest.timestamp) oldest = m;
        }
        await sleep(120);
      } catch (e) {}
    }
    if (!oldest) return fail(res, new Error('No messages found'));
    ok(res, { message: oldest });
  } catch (e) { fail(res, e); }
});

app.get('/api/history/server-my-first/:serverId', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    const myId = c.user.id;
    const guild = c.guilds.cache.get(req.params.serverId);
    const sr = await axios.get(
      `https://discord.com/api/v9/guilds/${req.params.serverId}/messages/search?sort_by=timestamp&sort_order=asc&author_id=${myId}&limit=25`,
      { headers: discordHeaders(c.token) });
    const results = sr.data.messages;
    if (!results?.length) return fail(res, new Error('No messages found'));
    const target = results[0].find(m => m.author.id === myId) || results[0][0];
    let chName = target.channel_id;
    try {
      const cr = await axios.get(`https://discord.com/api/v9/channels/${target.channel_id}`, { headers: discordHeaders(c.token) });
      chName = cr.data.name;
    } catch (e) {}
    ok(res, { message: fmtMsg(target, { id: target.channel_id, name: chName }, guild ? { id: guild.id, name: guild.name } : null) });
  } catch (e) { fail(res, e); }
});

app.get('/api/history/server-first/:serverId', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    const guild = c.guilds.cache.get(req.params.serverId);
    if (!guild) return fail(res, new Error('Server not found'));
    const cr = await axios.get(`https://discord.com/api/v9/guilds/${req.params.serverId}/channels`, { headers: discordHeaders(c.token) });
    const channels = cr.data.filter(ch => ch.type === 0 || ch.type === 5).slice(0, 15);
    let oldest = null;
    for (const ch of channels) {
      try {
        const r = await axios.get(`https://discord.com/api/v9/channels/${ch.id}/messages?limit=1&after=0`, { headers: discordHeaders(c.token) });
        if (Array.isArray(r.data) && r.data.length) {
          const m = fmtMsg(r.data[0], { id: ch.id, name: ch.name }, { id: guild.id, name: guild.name });
          if (!oldest || m.timestamp < oldest.timestamp) oldest = m;
        }
        await sleep(120);
      } catch (e) {}
    }
    if (!oldest) return fail(res, new Error('No accessible messages'));
    ok(res, { message: oldest });
  } catch (e) { fail(res, e); }
});

// ═══════════════════════════════════════════════
//  PRIVATE MANAGER — chat-style realtime DM hub
// ═══════════════════════════════════════════════
// Per-account in-memory unread/last-message store
const dmState = new Map(); // key: account|channelId -> { lastMsg, unread, ts }
const DM_STATE_MAX = 5000; // cap so a 24/7 server with thousands of DMs doesn't leak
const sseClients = new Set(); // { res, account }
const SSE_PRIVATE_MAX = 200;  // hard cap on concurrent listeners

function bumpDM(accountName, channelId, msg, fromMe = false) {
  const k = `${accountName}|${channelId}`;
  const prev = dmState.get(k) || { unread: 0 };
  // Re-insert at the end so LRU eviction below favours dropping cold entries.
  if (dmState.has(k)) dmState.delete(k);
  dmState.set(k, {
    lastMsg: msg.content || (msg.attachments?.size ? '[attachment]' : ''),
    lastAuthor: msg.author?.id,
    fromMe,
    unread: fromMe ? 0 : (prev.unread || 0) + 1,
    ts: msg.createdTimestamp || Date.now()
  });
  if (dmState.size > DM_STATE_MAX) {
    const drop = dmState.size - DM_STATE_MAX;
    const it = dmState.keys();
    for (let i = 0; i < drop; i++) dmState.delete(it.next().value);
  }
}

function attachDMListener(name, client, ownerUid) {
  ownerUid = ownerUid || currentUserId();
  if (client.__dmListenerBound) return;
  client.__dmListenerBound = true;
  client.on('messageCreate', (msg) => withUser(ownerUid, () => {
    try {
      if (!msg.channel || msg.channel.type !== 'DM') return;
      const fromMe = msg.author?.id === client.user.id;
      bumpDM(name, msg.channel.id, msg, fromMe);
      const payload = JSON.stringify({
        type: 'dm',
        account: name,
        channelId: msg.channel.id,
        userId: msg.channel.recipient?.id,
        username: msg.channel.recipient?.username,
        avatar: msg.channel.recipient?.displayAvatarURL?.({ size: 64 }) || defaultAvatarUrl(msg.channel.recipient?.id || '0'),
        fromMe,
        message: {
          id: msg.id,
          content: msg.content || '',
          ts: msg.createdTimestamp,
          author: { id: msg.author.id, username: msg.author.username }
        }
      });
      for (const sc of sseClients) {
        if (!sc.account || sc.account === name) {
          try { sc.res.write(`data: ${payload}\n\n`); } catch (e) {}
        }
      }
    } catch (e) {}
  }));
}

// NOTE: skipping "bind for already-connected clients" auto-loop —
// listeners are bound during connectOne() which is the only entry point now,
// and attempting to iterate the scoped pool here (outside any user ctx)
// would resolve to an empty namespace anyway.

app.get('/api/private/stream', (req, res) => {
  res.set({
    'Content-Type':  'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection':    'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders?.();
  res.write(`: connected\n\n`);
  const account = (req.query.account || '').trim();
  const sc = { res, account };

  // Drop the oldest listener if we're at the cap so a runaway client can't OOM us.
  if (sseClients.size >= SSE_PRIVATE_MAX) {
    const oldest = sseClients.values().next().value;
    if (oldest) {
      try { oldest.res.end(); } catch {}
      sseClients.delete(oldest);
    }
  }
  sseClients.add(sc);

  const ping = setInterval(() => { try { res.write(`: ping\n\n`); } catch (e) {} }, 25000);
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    clearInterval(ping);
    sseClients.delete(sc);
  };
  req.on('close', cleanup);
  req.on('error', cleanup);
  res.on('close', cleanup);
  res.on('error', cleanup);
});

app.get('/api/private/dms', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const accountName = (req.query.account || activeRef.get() || '').trim();
    const dms = Array.from(c.channels.cache.values())
      .filter(ch => ch.type === 'DM' && ch.recipient)
      .map(d => {
        const r = d.recipient;
        const k = `${accountName}|${d.id}`;
        const st = dmState.get(k);
        let preview = st?.lastMsg || '';
        let ts = st?.ts || 0;
        if (!st) {
          const last = d.lastMessage || (d.messages?.cache?.last?.());
          if (last) { preview = last.content || ''; ts = last.createdTimestamp || 0; }
        }
        return {
          id: d.id,
          userId: r?.id || '',
          username: r?.username || 'Unknown',
          displayName: r?.globalName || r?.username || 'Unknown',
          avatar: r?.displayAvatarURL?.({ size: 64, forceStatic: false }) || defaultAvatarUrl(r?.id || '0'),
          bot: !!r?.bot,
          unread: st?.unread || 0,
          preview,
          ts
        };
      })
      .sort((a, b) => (b.ts || 0) - (a.ts || 0));
    ok(res, { dms, account: accountName });
  } catch (e) { fail(res, e); }
});

app.get('/api/private/messages/:channelId', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const ch = await c.channels.fetch(req.params.channelId);
    if (!ch || ch.type !== 'DM') return fail(res, new Error('Invalid DM channel'));
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
    const opts = req.query.before ? { before: req.query.before, limit } : { limit };
    const msgs = await ch.messages.fetch(opts);
    const arr = Array.from(msgs.values())
      .map(m => ({
        id: m.id,
        content: m.content || '',
        ts: m.createdTimestamp,
        author: {
          id: m.author.id,
          username: m.author.username,
          displayName: m.author.globalName || m.author.username,
          avatar: m.author.displayAvatarURL?.({ size: 64 }) || defaultAvatarUrl(m.author.id),
          bot: !!m.author.bot
        },
        replyTo: m.reference?.messageId || null,
        attachments: Array.from(m.attachments?.values?.() || []).map(a => ({
          url: a.url, name: a.name, contentType: a.contentType || '',
          width: a.width || null, height: a.height || null, size: a.size || 0
        })),
        reactions: Array.from(m.reactions?.cache?.values?.() || []).map(r => ({
          emoji: r.emoji.id ? `<:${r.emoji.name}:${r.emoji.id}>` : r.emoji.name,
          name: r.emoji.name,
          id: r.emoji.id || null,
          count: r.count,
          me: !!r.me
        }))
      }))
      .sort((a, b) => a.ts - b.ts);
    res.json({ success: true, currentUserId: c.user.id, messages: arr });
  } catch (e) { fail(res, e); }
});

app.post('/api/private/send', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const { channelId, content, replyTo, files } = req.body || {};
    if (!channelId) return fail(res, new Error('channelId required'));
    if (!content && !(files && files.length)) return fail(res, new Error('content or file required'));
    const ch = await c.channels.fetch(channelId);
    if (!ch || ch.type !== 'DM') return fail(res, new Error('Invalid DM channel'));
    const opts = {};
    if (content) opts.content = content;
    if (replyTo) opts.reply = { messageReference: replyTo, failIfNotExists: false };
    if (files && files.length) {
      const extFor = (mime) => {
        const map = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/jpg': 'jpg',
          'image/gif': 'gif', 'image/webp': 'webp', 'image/bmp': 'bmp' };
        return map[(mime || '').toLowerCase()] || null;
      };
      opts.files = files.map(f => {
        if (f.dataUrl) {
          const m = String(f.dataUrl).match(/^data:([^;]+);base64,(.+)$/);
          if (!m) return null;
          const mime = m[1];
          const ext = extFor(mime);
          let name = f.name || 'file';
          // Force a proper image extension so Discord renders as inline preview (embed-style)
          if (ext && !/\.(png|jpe?g|gif|webp|bmp)$/i.test(name)) name = `image.${ext}`;
          return { attachment: Buffer.from(m[2], 'base64'), name, contentType: mime };
        }
        if (f.url) {
          const ext = (String(f.url).match(/\.(png|jpe?g|gif|webp|bmp)(?:\?|$)/i) || [])[1];
          let name = f.name || (ext ? `image.${ext}` : 'file');
          return { attachment: f.url, name };
        }
        return null;
      }).filter(Boolean);
    }
    await humanCooldown(c.token, 'send-msg');
    // optional typing simulation for short messages (only if pure text, no files)
    if (content && !(files && files.length) && ch.sendTyping) {
      try {
        await ch.sendTyping();
        const tDelay = Math.min(2500, Math.max(400, String(content).length * jitter(60, 130)));
        await sleep(tDelay);
      } catch (_) {}
    }
    const m = await ch.send(opts);
    ok(res, { id: m.id, ts: m.createdTimestamp });
  } catch (e) { fail(res, e); }
});

app.post('/api/private/react', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const { channelId, messageId, emoji, remove } = req.body || {};
    if (!channelId || !messageId || !emoji) return fail(res, new Error('channelId, messageId, emoji required'));
    const ch = await c.channels.fetch(channelId);
    const m = await ch.messages.fetch(messageId);
    await humanCooldown(c.token, 'react');
    if (remove) {
      const r = m.reactions?.cache?.find(x => x.emoji.name === emoji || (x.emoji.id && `<:${x.emoji.name}:${x.emoji.id}>` === emoji));
      if (r) await r.users.remove(c.user.id);
    } else {
      await m.react(emoji);
    }
    ok(res);
  } catch (e) { fail(res, e); }
});

app.post('/api/private/read/:channelId', (req, res) => {
  const accountName = (req.body?.account || activeRef.get() || '').trim();
  const k = `${accountName}|${req.params.channelId}`;
  const st = dmState.get(k);
  if (st) { st.unread = 0; dmState.set(k, st); }
  ok(res);
});

// ─── Private Manager: Strong global search ──────────────────────────
// Strategy (Discord-style):
//   1) FAST PASS — instantly match against locally-cached messages so the user
//      gets results in <50ms while the server makes the deeper call.
//   2) DEEP PASS — call Discord's NATIVE per-channel search API
//      (`GET /channels/:id/messages/search?content=<q>`) in parallel with a
//      concurrency cap. This covers the FULL message history for each DM, not
//      just what's cached. Results are merged + de-duplicated and returned.
//   3) CACHE — keep a 60-second per-(account|query) result cache so repeated
//      typing/scrolling reuses the deep results instantly.
const _pmSearchCache = new Map(); // key = account|q  -> { ts, matches }
const _PM_SEARCH_TTL = 60 * 1000;

async function _runPoolP(items, limit, fn) {
  const out = []; let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++; try { out[idx] = await fn(items[idx], idx); }
      catch (e) { out[idx] = null; }
    }
  });
  await Promise.all(workers);
  return out;
}

function _mkMatch(ch, m) {
  const recip = ch.recipient || (ch.recipients && ch.recipients.first?.());
  const channelAvatar = recip?.displayAvatarURL?.({ size: 64 })
    || (m.author?.displayAvatarURL?.({ size: 64 }))
    || defaultAvatarUrl(recip?.id || ch.id || '0');
  return {
    channelId: ch.id,
    channelType: ch.type,
    channelName: recip?.username || ch.name || 'DM',
    channelAvatar,
    messageId: m.id,
    content: String(m.content || ''),
    author: {
      id: m.author?.id,
      username: m.author?.username || '',
      avatar: m.author?.displayAvatarURL?.({ size: 32 })
        || (m.author?.id ? defaultAvatarUrl(m.author.id) : null),
    },
    ts: m.createdTimestamp || (m.timestamp ? new Date(m.timestamp).getTime() : Date.now()),
  };
}

// Convert Discord's native search hit (raw API JSON) into our match shape.
function _mkMatchFromRaw(ch, raw) {
  const recip = ch.recipient || (ch.recipients && ch.recipients.first?.());
  const author = raw.author || {};
  const authorAvatar = author.avatar
    ? `https://cdn.discordapp.com/avatars/${author.id}/${author.avatar}.${author.avatar.startsWith('a_') ? 'gif' : 'png'}?size=64`
    : defaultAvatarUrl(author.id || '0');
  const channelAvatar = recip?.displayAvatarURL?.({ size: 64 })
    || authorAvatar
    || defaultAvatarUrl(recip?.id || ch.id || '0');
  return {
    channelId: ch.id,
    channelType: ch.type,
    channelName: recip?.username || ch.name || 'DM',
    channelAvatar,
    messageId: raw.id,
    content: String(raw.content || ''),
    author: { id: author.id, username: author.username || '', avatar: authorAvatar },
    ts: raw.timestamp ? new Date(raw.timestamp).getTime() : Date.now(),
  };
}

app.get('/api/private/search', async (req, res) => {
  try {
    const q = (req.query.q || '').toString().trim();
    if (q.length < 2) return ok(res, { matches: [], total: 0, source: 'short' });
    const account = (req.query.account || '').toString().trim();
    const includeGroups = req.query.groups === '1' || req.query.groups === 'true';
    const limit = Math.min(80, Math.max(5, parseInt(req.query.limit || '40', 10)));
    const deep = req.query.deep !== '0'; // default: deep search ON

    const c = account ? getClientByName(account) : (getActiveClient() || null);
    if (!c?.token) return fail(res, new Error('Not connected'));

    const cacheKey = `${account || activeRef.get() || '_'}|${q.toLowerCase()}|${includeGroups ? 'g' : ''}`;
    const cached = _pmSearchCache.get(cacheKey);
    if (cached && (Date.now() - cached.ts) < _PM_SEARCH_TTL) {
      return ok(res, { matches: cached.matches.slice(0, limit), total: cached.matches.length, source: 'cache' });
    }

    const ql = q.toLowerCase();
    const channels = Array.from(c.channels.cache.values()).filter(ch =>
      ch.type === 'DM' || (includeGroups && ch.type === 'GROUP_DM'));

    // ── 1) FAST PASS: scan local cache (no network) ──────────────────
    const seen = new Set();
    const matches = [];
    for (const ch of channels) {
      const recipName = (ch.recipient?.username || ch.name || '').toLowerCase();
      const recipNick = (ch.recipient?.globalName || '').toLowerCase();
      // Surface channels matching by name/handle even when they have no message hits
      const channelHitByName = recipName.includes(ql) || recipNick.includes(ql);
      const cached = Array.from(ch.messages?.cache?.values?.() || []);
      for (const m of cached) {
        const cn = String(m.content || '').toLowerCase();
        const an = (m.author?.username || '').toLowerCase();
        if (cn.includes(ql) || an.includes(ql)) {
          if (seen.has(m.id)) continue;
          seen.add(m.id);
          matches.push(_mkMatch(ch, m));
        }
      }
      if (channelHitByName && !matches.some(x => x.channelId === ch.id)) {
        // Synthetic "channel" hit so DM still appears in messages section
        const last = cached.sort((a, b) => (b.createdTimestamp||0)-(a.createdTimestamp||0))[0];
        if (last) { seen.add(last.id); matches.push(_mkMatch(ch, last)); }
      }
    }

    // ── 2) DEEP PASS: native Discord search API in parallel ──────────
    if (deep && c?.token && channels.length) {
      const headers = { Authorization: c.token, 'Content-Type': 'application/json' };
      // Run searches in parallel, with a tight concurrency cap to be polite.
      const PAR = 8;
      const perChannelLimit = 25;
      const t0 = Date.now();
      const TIMEOUT_MS = 8000; // hard cap so the request stays snappy
      await _runPoolP(channels, PAR, async (ch) => {
        if ((Date.now() - t0) > TIMEOUT_MS) return;
        try {
          const url = `https://discord.com/api/v9/channels/${ch.id}/messages/search`
            + `?content=${encodeURIComponent(q)}&limit=${perChannelLimit}`;
          const r = await axios.get(url, { headers, timeout: 6000, validateStatus: () => true });
          if (r.status === 429) return;
          if (r.status >= 400 || !r.data) return;
          const groups = r.data.messages || [];
          for (const grp of groups) {
            const hit = (grp || []).find(x => x?.hit) || (grp || [])[0];
            if (!hit || seen.has(hit.id)) continue;
            seen.add(hit.id);
            matches.push(_mkMatchFromRaw(ch, hit));
          }
        } catch (e) {}
      });
    }

    // Sort by recency, hard cap, cache
    matches.sort((a, b) => (b.ts || 0) - (a.ts || 0));
    const final = matches.slice(0, 200);
    _pmSearchCache.set(cacheKey, { ts: Date.now(), matches: final });
    if (_pmSearchCache.size > 200) {
      const oldest = [..._pmSearchCache.entries()].sort((a,b)=>a[1].ts-b[1].ts)[0]?.[0];
      if (oldest) _pmSearchCache.delete(oldest);
    }
    ok(res, { matches: final.slice(0, limit), total: final.length, source: 'fresh' });
  } catch (e) { fail(res, e); }
});

// ═══════════════════════════════════════════════
//  STATS DASHBOARD
// ═══════════════════════════════════════════════
app.get('/api/stats/summary', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const dms = Array.from(c.channels.cache.values()).filter(ch => ch.type === 'DM');
    const groups = Array.from(c.channels.cache.values()).filter(ch => ch.type === 'GROUP_DM');
    const guilds = Array.from(c.guilds.cache.values());
    const owned = guilds.filter(g => g.ownerId === c.user.id);
    const bots = dms.filter(d => d.recipient?.bot).length;
    // Top DMs by recent unread + activity (from dmState)
    const accountName = (req.query.account || activeRef.get() || '').trim();
    // Live-fallback: if dmState hasn't observed this DM yet (e.g. fresh boot),
    // use the channel's lastMessage timestamp so the dashboard isn't empty.
    const topDMs = dms.map(d => {
      const k = `${accountName}|${d.id}`;
      const st = dmState.get(k);
      let ts = st?.ts || 0;
      if (!ts) {
        const last = d.lastMessage || d.messages?.cache?.last?.();
        if (last) ts = last.createdTimestamp || 0;
      }
      return {
        username: d.recipient?.username || 'unknown',
        avatar: d.recipient?.displayAvatarURL?.({ size: 64 }) || defaultAvatarUrl(d.recipient?.id || '0'),
        ts,
        unread: st?.unread || 0
      };
    }).filter(x => x.ts > 0).sort((a,b)=>b.ts-a.ts).slice(0, 6);

    const totalMembers = guilds.reduce((s,g)=>s+(g.memberCount||0),0);
    ok(res, {
      stats: {
        accountName,
        username: c.user.tag,
        avatar: c.user.displayAvatarURL?.({ size: 128 }) || null,
        accounts:    clients.size,
        connected:   Array.from(clients.values()).filter(e => e.client?.user).length,
        servers:     guilds.length,
        ownedServers: owned.length,
        members:     totalMembers,
        dms:         dms.length,
        botDMs:      bots,
        humanDMs:    dms.length - bots,
        groups:      groups.length,
        topDMs
      }
    });
  } catch (e) { fail(res, e); }
});

// ═══════════════════════════════════════════════
//  SERVER LOOKUP
// ═══════════════════════════════════════════════
// Boosts required for each tier (Discord constants)
const _BOOST_TIER_REQ = { 0: 2, 1: 7, 2: 14, 3: 0 };
function _verifNum(v) {
  // Discord.js v13 maps strings; handle both
  const map = { NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, VERY_HIGH: 4 };
  if (typeof v === 'number') return v;
  return map[v] ?? null;
}
function _verifLabel(v) { return ['NONE','LOW','MEDIUM','HIGH','VERY_HIGH'][_verifNum(v) ?? 0] || null; }
function _filterLabel(v) {
  if (typeof v === 'number') return ['DISABLED','MEMBERS_WITHOUT_ROLES','ALL_MEMBERS'][v] || null;
  return v || null;
}
function _nsfwLabel(v) {
  if (typeof v === 'number') return ['DEFAULT','EXPLICIT','SAFE','AGE_RESTRICTED'][v] || null;
  return v || null;
}

app.get('/api/lookup/server/:id', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    const id = req.params.id;
    const guild = c.guilds.cache.get(id);

    if (guild) {
      const me = guild.members.cache.get(c.user.id);
      // Channel breakdown
      const isText  = ch => ch.type === 'GUILD_TEXT'  || ch.type === 0;
      const isVoice = ch => ch.type === 'GUILD_VOICE' || ch.type === 2;
      const isCat   = ch => ch.type === 'GUILD_CATEGORY' || ch.type === 4;
      const isAnn   = ch => ch.type === 'GUILD_NEWS' || ch.type === 5;
      const isStage = ch => ch.type === 'GUILD_STAGE_VOICE' || ch.type === 13;
      const isForum = ch => ch.type === 'GUILD_FORUM' || ch.type === 15;
      const allCh = Array.from(guild.channels.cache.values());
      const visibleText = allCh.filter(ch => isText(ch) && ch.viewable).length;
      const totalText   = allCh.filter(isText).length;
      const totalVoice  = allCh.filter(isVoice).length;
      const totalCats   = allCh.filter(isCat).length;
      const totalAnn    = allCh.filter(isAnn).length;
      const totalStage  = allCh.filter(isStage).length;
      const totalForum  = allCh.filter(isForum).length;

      // Roles
      const roles = Array.from(guild.roles.cache.values())
        .filter(r => r.id !== guild.id)  // exclude @everyone
        .sort((a, b) => (b.position||0) - (a.position||0));
      const myRoles = me?.roles?.cache
        ? Array.from(me.roles.cache.values())
            .filter(r => r.id !== guild.id)
            .sort((a, b) => (b.position||0) - (a.position||0))
            .map(r => ({ id: r.id, name: r.name, color: r.hexColor || null, position: r.position }))
        : [];
      const myHighest = myRoles[0] || null;

      // Owner
      const owner = await guild.members.fetch(guild.ownerId).catch(()=>null);

      // Try to get extra preview data (online count, description) in parallel —
      // even when we're already a member.
      const headers = { Authorization: c.token };
      const [previewRes, vanityRes] = await Promise.all([
        axios.get(`https://discord.com/api/v9/guilds/${guild.id}/preview`, { headers, validateStatus: () => true })
          .catch(() => ({ status: 0, data: null })),
        guild.vanityURLCode
          ? axios.get(`https://discord.com/api/v9/guilds/${guild.id}/vanity-url`, { headers, validateStatus: () => true })
              .catch(() => ({ status: 0, data: null }))
          : Promise.resolve({ status: 0, data: null }),
      ]);
      const preview = previewRes?.status === 200 ? previewRes.data : null;
      const vanityData = vanityRes?.status === 200 ? vanityRes.data : null;

      // Boost progress to next tier
      const tier = guild.premiumTier || 0;
      const boosts = guild.premiumSubscriptionCount || 0;
      let nextTierAt = null, boostProgress = null;
      const tierNum = typeof tier === 'number' ? tier : (parseInt(tier, 10) || 0);
      if (tierNum < 3) {
        nextTierAt = _BOOST_TIER_REQ[tierNum];
        boostProgress = nextTierAt > 0 ? Math.min(1, boosts / nextTierAt) : null;
      }

      // Resolve special channels by id
      const _chName = (cid) => cid ? (guild.channels.cache.get(cid)?.name || null) : null;

      // My permissions (admin-style summary)
      let myPermsList = null;
      try {
        if (me?.permissions?.toArray) myPermsList = me.permissions.toArray();
      } catch (e) {}

      ok(res, {
        joined: true,
        server: {
          id: guild.id,
          name: guild.name,
          icon: guild.iconURL?.({ size: 256, forceStatic: false }) || null,
          banner: guild.bannerURL?.({ size: 600 }) || null,
          splash: guild.splashURL?.({ size: 600 }) || null,
          discoverySplash: guild.discoverySplashURL?.({ size: 600 }) || null,
          createdAt: guild.createdTimestamp,
          description: guild.description || preview?.description || '',
          // members / presence
          members: guild.memberCount || preview?.approximate_member_count || 0,
          online: preview?.approximate_presence_count || null,
          maximum: guild.maximumMembers || null,
          // channels
          visibleText, totalText, totalVoice, totalCats, totalAnn, totalStage, totalForum,
          totalChannels: allCh.length,
          // roles
          totalRoles: roles.length,
          topRoles: roles.slice(0, 8).map(r => ({ id: r.id, name: r.name, color: r.hexColor || null, members: r.members?.size ?? null })),
          // owner
          ownerId: guild.ownerId,
          ownerName: owner?.user?.tag || null,
          ownerAvatar: owner?.user?.displayAvatarURL?.({ size: 64 }) || null,
          // my membership
          myRoles: myRoles.length,
          // Cap the embedded list at 50 to avoid sending massive payloads
          // for accounts with hundreds of roles (UI only shows ~10 at a time)
          myRolesList: myRoles.slice(0, 50),
          myRolesTruncated: myRoles.length > 50,
          myHighestRole: myHighest,
          myNickname: me?.nickname || null,
          myJoinedAt: me?.joinedTimestamp || null,
          myPermissions: myPermsList,
          isOwner: guild.ownerId === c.user.id,
          // boosts
          boosts, tier: tierNum, nextTierAt, boostProgress,
          boostBarEnabled: guild.premiumProgressBarEnabled ?? null,
          // settings
          verificationLevel: _verifLabel(guild.verificationLevel),
          explicitFilter: _filterLabel(guild.explicitContentFilter),
          nsfwLevel: _nsfwLabel(guild.nsfwLevel),
          mfaLevel: typeof guild.mfaLevel === 'number' ? (guild.mfaLevel === 1 ? 'ELEVATED' : 'NONE') : (guild.mfaLevel || null),
          preferredLocale: guild.preferredLocale || null,
          region: guild.region || null,
          // special channels
          afkChannelId: guild.afkChannelId || null,
          afkChannelName: _chName(guild.afkChannelId),
          afkTimeout: guild.afkTimeout || null,
          systemChannelId: guild.systemChannelId || null,
          systemChannelName: _chName(guild.systemChannelId),
          rulesChannelId: guild.rulesChannelId || null,
          rulesChannelName: _chName(guild.rulesChannelId),
          publicUpdatesChannelId: guild.publicUpdatesChannelId || null,
          publicUpdatesChannelName: _chName(guild.publicUpdatesChannelId),
          widgetEnabled: guild.widgetEnabled ?? null,
          widgetChannelId: guild.widgetChannelId || null,
          // emojis / stickers
          emojiCount:    guild.emojis?.cache?.size ?? null,
          animatedEmojis: guild.emojis?.cache ? Array.from(guild.emojis.cache.values()).filter(e => e.animated).length : null,
          stickerCount:  guild.stickers?.cache?.size ?? null,
          // vanity / invite
          vanityCode:    guild.vanityURLCode || null,
          vanityUses:    vanityData?.uses ?? null,
          // features
          features: guild.features || [],
          // partner / verified flags surfaced from features
          partnered: (guild.features || []).includes('PARTNERED'),
          verified:  (guild.features || []).includes('VERIFIED'),
          community: (guild.features || []).includes('COMMUNITY'),
        }
      });
      return;
    }

    // ── Not joined — public preview + invite info (parallel) ────────
    const headers = discordHeaders(c.token);
    const [previewRes] = await Promise.all([
      axios.get(`https://discord.com/api/v9/guilds/${id}/preview`, { headers, validateStatus: () => true }),
    ]);
    if (previewRes.status >= 400 || !previewRes.data) {
      // Uniform "not found" reply — do NOT distinguish 403 (private/non-discoverable)
      // from 404 (does not exist) so we don't leak guild existence to ID-scrapers.
      return ok(res, { joined: false, found: false, server: null });
    }
    const d = previewRes.data;
    ok(res, {
      joined: false,
      server: {
        id: d.id, name: d.name,
        icon: d.icon ? `https://cdn.discordapp.com/icons/${d.id}/${d.icon}.png?size=256` : null,
        banner: d.banner ? `https://cdn.discordapp.com/banners/${d.id}/${d.banner}.png?size=600` : null,
        splash: d.splash ? `https://cdn.discordapp.com/splashes/${d.id}/${d.splash}.png?size=600` : null,
        discoverySplash: d.discovery_splash ? `https://cdn.discordapp.com/discovery-splashes/${d.id}/${d.discovery_splash}.png?size=600` : null,
        createdAt: Number((BigInt(d.id) >> 22n) + 1420070400000n),
        members: d.approximate_member_count || 0,
        online: d.approximate_presence_count || 0,
        description: d.description || '',
        emojiCount: (d.emojis || []).length,
        animatedEmojis: (d.emojis || []).filter(e => e.animated).length,
        stickerCount: (d.stickers || []).length,
        features: d.features || [],
        partnered: (d.features || []).includes('PARTNERED'),
        verified:  (d.features || []).includes('VERIFIED'),
        community: (d.features || []).includes('COMMUNITY'),
      }
    });
  } catch (e) { fail(res, e); }
});

// ═══════════════════════════════════════════════
//  APP DATA + FEATURE SSE
// ═══════════════════════════════════════════════
// Per-user app data store — see lib/userScope.js. Resolves to
// data/users/<currentUserId>/app_data.json based on async context.
const dataStore = scopedStore('app_data.json', {});
function readData() { return dataStore.read(); }
function writeData(_d) { dataStore.touch(); } // mutations are on the cached object — just mark dirty
function ensureData() {
  const d = dataStore.read();
  if (!d.history) d.history = [];
  if (!d.tokenHealth) d.tokenHealth = {};
  if (!d.cloneSnapshots) d.cloneSnapshots = [];
  if (!d.picConfig) d.picConfig = { enabled: false, accounts: [], scope: 'all', servers: [], webhook: '', inApp: true };
  if (!d.picBuffer) d.picBuffer = [];
  if (!d.antiPruneConfig) d.antiPruneConfig = { enabled: false, accounts: [], scope: 'all', servers: [], message: 'You were removed from {server} by mistake — please rejoin: {invite}', distribute: true };
  if (!d.antiPruneLog) d.antiPruneLog = [];
  if (!Array.isArray(d.tsAccounts)) d.tsAccounts = [];
  if (typeof d.tsLastNumber !== 'number') d.tsLastNumber = 0;
  dataStore.touch();
  return d;
}
ensureData();

const featureSSE = new Set();
function sseBroadcast(type, payload) {
  const data = JSON.stringify({ type, ...payload });
  for (const s of featureSSE) {
    if (!s.types || s.types.includes(type)) {
      try { s.res.write(`data: ${data}\n\n`); } catch (e) {}
    }
  }
}
// ═══════════════════════════════════════════════
//  TRUE-STUDIO — TOTP-based account & bot automation engine
// ═══════════════════════════════════════════════
const tsCrypto = require('crypto');
const ts = require('./lib/trueStudio');

  // Per-user session state (one active automation per user).
  // Key: currentUserId() · Value: ts.makeSession()
  const _tsSessions = new Map();
  function tsSession() {
    const uid = currentUserId();
    if (!_tsSessions.has(uid)) _tsSessions.set(uid, ts.makeSession());
    return _tsSessions.get(uid);
  }

  const TS_LOG_MAX = 250;
  function tsLog(level, msg, meta = null) {
    const s = tsSession();
    const entry = { ts: Date.now(), level, msg: String(msg).slice(0, 500) };
    if (meta && typeof meta === 'object') Object.assign(entry, meta);
    s.log.push(entry);
    if (s.log.length > TS_LOG_MAX) s.log.splice(0, s.log.length - TS_LOG_MAX);
    pushTsEvent('ts_log', { entry: s.log[s.log.length - 1] });
  }

  function tsSnapshot() {
    const s = tsSession();
    return {
      state: s.state,
      account: s.account,
      rules: s.rules,
      total: s.total,
      done: s.done,
      failed: s.failed,
      current: s.current,
      teamId: s.teamId,
      teamName: s.teamName,
      waitUntilTs: s.waitUntilTs,
      waitTotalMs: s.waitTotalMs,
      startedAt: s.startedAt,
      finishedAt: s.finishedAt,
      bots: (s.bots || []).map(b => ({ name: b.name, appId: b.appId, botUserId: b.botUserId, hasToken: !!b.token })),
      lastError: s.lastError,
      log: s.log.slice(-50),
      // Pending manual captcha challenge (if any). Frontend renders an hCaptcha
      // widget pointing at this sitekey and POSTs the token back via /api/ts/captcha-resolve.
      pendingCaptcha: s.pendingCaptcha
        ? { id: s.pendingCaptcha.id, sitekey: s.pendingCaptcha.sitekey, service: s.pendingCaptcha.service,
            context: s.pendingCaptcha.context, createdAt: s.pendingCaptcha.createdAt,
            // rqdata is request-specific data Discord includes in the captcha
            // challenge. The hCaptcha widget MUST receive it via render({ rqdata })
            // for the produced token to be accepted by Discord — otherwise Discord
            // returns { captcha_key: ["invalid-response"] } even on a valid solve.
            // (rqtoken stays server-side; we attach it to the retry request.)
            rqdata: s.pendingCaptcha.rqdata || null,
            attempts: s.pendingCaptcha.attempts || 0 }
        : null,
    };
  }

  function pushTsEvent(type, payload = {}) {
    // Tag each event with the user id so the SSE filter can route it.
    sseBroadcast(type, { ...payload, snapshot: tsSnapshot(), _uid: currentUserId() });
  }

  // ── Account storage (per-user, encrypted at rest) ───────────────
  function tsAccountsRaw() {
    const d = ensureData();
    if (!Array.isArray(d.tsAccounts)) d.tsAccounts = [];
    return d.tsAccounts;
  }

  function tsAccountsPublic() {
    return tsAccountsRaw().map(a => ({
      email: a.email,
      hasPassword: !!a.password,
      hasTotp: !!a.totpSecret,
      hasDirectToken: !!a.directToken,
      addedAt: a.addedAt || 0,
      verify: a.verify || null,
    }));
  }

  function tsFindAccount(email) {
    const list = tsAccountsRaw();
    return list.find(a => a.email && a.email.toLowerCase() === String(email || '').toLowerCase()) || null;
  }

  function tsDecryptAccount(rec) {
    if (!rec) return null;
    return {
      email: rec.email,
      password: tryDecrypt(rec.password) || rec.password || '',
      totpSecret: tryDecrypt(rec.totpSecret) || rec.totpSecret || '',
      directToken: tryDecrypt(rec.directToken) || rec.directToken || '',
    };
  }

  // ── Short-lived token cache (so repeated library refreshes don't hammer
  //    Discord with full email+TOTP logins). Key: lowercase email.
  const TS_TOKEN_TTL = 12 * 60 * 1000; // 12 minutes
  const _tsTokenCache = new Map();
  function tsCachedToken(email) {
    const e = _tsTokenCache.get(email);
    if (!e) return null;
    if (Date.now() > e.expires) { _tsTokenCache.delete(email); return null; }
    return { token: e.token, client: e.client || null };
  }
  function tsStoreToken(email, token, client) {
    _tsTokenCache.set(email, { token, client: client || null, expires: Date.now() + TS_TOKEN_TTL });
  }
  function tsClearToken(email) { _tsTokenCache.delete(email); }

  // Resolve a usable user-token + the warmed client (cookie jar, fingerprint).
  // Priority:
  //   1. In-memory cached token (still fresh) — fastest, no requests
  //   2. Direct token saved by user — skip login, warm session only
  //   3. Email + password login — full login flow with captcha handling
  async function tsGetToken(email) {
    const hit = tsCachedToken(email);
    if (hit) return hit;
    const acct = tsFindAccount(email);
    if (!acct) throw new Error('Account not found — save it first');
    const creds = tsDecryptAccount(acct);

    // ── Option A: Direct token (warm client, skip login) ──────────
    if (creds.directToken) {
      const client = ts.createClient();
      tsLog('info', 'استخدام التوكن المباشر — جاري تسخين الجلسة…');
      try { await ts.warmUpClient(client); } catch (e) {
        tsLog('warn', 'تعذر تسخين الجلسة: ' + (e.message || e));
      }
      tsStoreToken(email, creds.directToken, client);
      tsLog('info', 'جاهز — التوكن المباشر مع جلسة دافئة ✓');
      return { token: creds.directToken, client };
    }

    // ── Option B: Email + password login ─────────────────────────
    if (!creds.password) throw new Error('Saved account has no password and no direct token — re-save it');
    const client = ts.createClient();
    const netOpts = { solveCaptcha: buildSolveCaptcha(), client };
    const r = await ts.login({ email: creds.email, password: creds.password, totpSecret: creds.totpSecret, netOpts });
    tsStoreToken(email, r.token, client);
    return { token: r.token, client };
  }

  // ── Async sleep that respects cancel flag ──────────────────────
  async function tsSleep(ms) {
    const s = tsSession();
    s.waitUntilTs = Date.now() + ms;
    s.waitTotalMs = ms;
    s.state = 'waiting';
    pushTsEvent('ts_progress');
    const tickEvery = 1000;
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (s.cancelRequested) break;
      const left = Math.max(0, end - Date.now());
      await new Promise(r => setTimeout(r, Math.min(tickEvery, left)));
    }
    s.waitUntilTs = 0;
    s.waitTotalMs = 0;
    if (s.cancelRequested) return;
    s.state = 'running';
    pushTsEvent('ts_progress');
  }

  // ── Captcha settings (per-user, encrypted) ─────────────────────
  // Holds the user's hCaptcha solver service key (e.g. 2Captcha) plus the
  // manual-fallback toggle. When the API key is missing we always fall back
  // to manual solving so the project never stalls.
  function tsCaptchaSettings() {
    const d = ensureData();
    if (!d.tsCaptcha || typeof d.tsCaptcha !== 'object') d.tsCaptcha = {};
    return d.tsCaptcha;
  }
  function tsCaptchaSettingsPublic() {
    const c = tsCaptchaSettings();
    const provider = c.provider || '2captcha';
    const LABELS = { capsolver: 'CapSolver', capmonster: 'CapMonster', '2captcha': '2Captcha' };
    return {
      provider,
      hasApiKey: !!c.apiKey,
      manualFallback: c.manualFallback !== false,
      providerLabel: LABELS[provider] || '2Captcha',
    };
  }
  function tsCaptchaApiKey() {
    const c = tsCaptchaSettings();
    if (!c.apiKey) return '';
    return tryDecrypt(c.apiKey) || c.apiKey || '';
  }

  // CapSolver solver — Discord hCaptcha Enterprise
  //
  // الحقائق المؤكدة من أبحاث GitHub ومجتمع المطورين:
  //  • websiteURL يجب أن يكون https://discord.com وليس أي مسار API أو صفحة أخرى
  //  • userAgent مطلوب — يحسّن نتائج الحل للـ Enterprise
  //  • enterprisePayload.rqdata مطلوب لـ Discord — يجب وضعه هنا فقط
  //  • isEnterprise + isInvisible كلاهما حقول صالحة لـ HCaptchaTaskProxyLess
  //  • نجرب HCaptchaEnterpriseTaskProxyLess أولاً (الأفضل لـ Discord)
  //  • إذا رفضها الحساب (خطة غير مدعومة) نتراجع لـ HCaptchaTaskProxyLess + isEnterprise
  //  • نسجّل errorCode + errorDescription معاً لتسهيل التشخيص مستقبلاً
  //
  // Docs: https://docs.capsolver.com/en/guide/captcha/HCaptcha/
  async function solveWithCapSolver({ apiKey, sitekey, pageUrl, rqdata, rqtoken }) {
    const axios = require('axios');

    // websiteURL يجب أن يكون صفحة Discord حقيقية — لا مسار API ولا صفحة المطورين.
    // CapSolver يتحقق من أن الـ captcha موجود فعلاً على هذه الصفحة.
    const DISCORD_PAGE_URL = 'https://discord.com';
    const browserPageUrl = (pageUrl && !pageUrl.includes('/api/') && pageUrl.startsWith('https://discord.com'))
      ? pageUrl
      : DISCORD_PAGE_URL;

    const USER_AGENT =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
      'AppleWebKit/537.36 (KHTML, like Gecko) ' +
      'Chrome/124.0.0.0 Safari/537.36';

    // دالة مساعدة لتحويل أخطاء CapSolver لرسائل عربية واضحة
    function capsolvErr(data) {
      const code = data.errorCode || '';
      const desc = data.errorDescription || '';
      const detail = [code, desc].filter(Boolean).join(' — ');
      if (code === 'ERROR_ZERO_BALANCE')        return 'CapSolver: رصيد صفر — يرجى شحن الحساب على capsolver.com';
      if (code === 'ERROR_KEY_DOES_NOT_EXIST')  return 'CapSolver: مفتاح API غير موجود';
      if (code === 'ERROR_WRONG_USER_KEY')      return 'CapSolver: مفتاح API غير صالح';
      if (code === 'ERROR_BLOCKED_USER')        return 'CapSolver: الحساب موقوف — تواصل مع دعم CapSolver';
      return 'CapSolver خطأ: ' + (detail || JSON.stringify(data));
    }

    // إرسال مهمة بنوع محدد — يُرجع taskId أو يرمي خطأ
    async function trySubmit(type) {
      const task = {
        type,
        websiteURL:   browserPageUrl,
        websiteKey:   sitekey,
        isEnterprise: true,
        isInvisible:  false,
        userAgent:    USER_AGENT,
      };
      // rqdata يذهب داخل enterprisePayload فقط — خارجه يسبب ERROR_INVALID_TASK_DATA
      if (rqdata) task.enterprisePayload = { rqdata };

      const res = await axios.post('https://api.capsolver.com/createTask',
        { clientKey: apiKey, task },
        { headers: { 'Content-Type': 'application/json' }, timeout: 20_000, validateStatus: () => true }
      );

      if (!res.data) throw new Error('CapSolver: ردّ فارغ (HTTP ' + res.status + ')');
      if (res.data.errorId) {
        const code = res.data.errorCode || '';
        const desc = res.data.errorDescription || '';
        // هذا النوع غير مدعوم على الخطة الحالية — جرّب البديل
        if (desc.includes('not supported') || desc.includes('invalid task') || code === 'ERROR_INVALID_TASK_DATA') {
          const e = new Error('[unsupported_type] ' + type + ': ' + desc);
          e.unsupportedType = true;
          throw e;
        }
        throw new Error(capsolvErr(res.data));
      }
      if (!res.data.taskId) throw new Error('CapSolver: لم يُرجع taskId');
      return res.data.taskId;
    }

    // الترتيب: الأنواع المدعومة على جميع الخطط أولاً، غير المدعومة آخراً.
    // HCaptchaTaskProxyLess → يعمل على كل الخطط
    // HCaptchaEnterpriseTaskProxyLess → يحتاج خطة مدفوعة، يُجرَّب آخراً فقط
    const TYPES_TO_TRY = [
      'HCaptchaTaskProxyLess',
      'HCaptchaEnterpriseTaskProxyLess',
    ];

    let taskId = null;
    for (const type of TYPES_TO_TRY) {
      try {
        taskId = await trySubmit(type);
        tsLog('info', `CapSolver: تم إرسال المهمة بنوع "${type}" — taskId: ${taskId}`);
        break;
      } catch (e) {
        if (e.unsupportedType && type !== TYPES_TO_TRY[TYPES_TO_TRY.length - 1]) {
          tsLog('warn', `CapSolver: "${type}" غير مدعوم — جاري تجربة "${TYPES_TO_TRY[TYPES_TO_TRY.indexOf(type) + 1]}"…`);
          continue;
        }
        throw e;
      }
    }
    if (!taskId) throw new Error('CapSolver: فشل إنشاء المهمة بكل الأنواع المتاحة');

    // استطلاع النتيجة — انتظار 5 ث أولاً ثم كل 4 ث (hCaptcha يُحلّ عادةً خلال 8-20 ث)
    const startedAt  = Date.now();
    const TIMEOUT_MS = 180_000;
    await new Promise(r => setTimeout(r, 5_000));

    while (Date.now() - startedAt < TIMEOUT_MS) {
      const r = await axios.post('https://api.capsolver.com/getTaskResult',
        { clientKey: apiKey, taskId },
        { timeout: 15_000, validateStatus: () => true }
      );
      const body = r.data || {};
      if (body.errorId) throw new Error(capsolvErr(body));
      if (body.status === 'ready' && body.solution?.gRecaptchaResponse) {
        return String(body.solution.gRecaptchaResponse);
      }
      await new Promise(r => setTimeout(r, 4_000));
    }
    throw new Error('CapSolver: انتهت مهلة الانتظار (180 ث) بدون حل');
  }

  // 2Captcha solver — submits Discord's hCaptcha Enterprise challenge and polls for a token.
  //
  // Key facts about Discord hCaptcha (sourced from 2captcha docs + community research):
  //  • Discord always uses hCaptcha Enterprise → enterprise=1 is mandatory
  //  • Discord uses invisible mode → invisible=1 is mandatory
  //  • captcha_rqdata from Discord's 400 response MUST be forwarded as "data" param
  //  • pageurl must be a real browser-facing Discord URL, never an API endpoint path
  //  • userAgent should be a real Chrome UA — affects solve quality on Enterprise challenges
  //  • Initial poll wait: 5 s (hCaptcha), NOT 20 s (that is for reCAPTCHA only)
  //  • Poll interval: 5 s minimum per 2captcha docs
  //  • ERROR_CAPTCHA_UNSOLVABLE → free retry (not charged), retry up to 2 times
  //  • ERROR_NO_SLOT_AVAILABLE → worker queue full, wait 5 s and retry submission
  //  • ERROR_ZERO_BALANCE → surface a clear message so the user can top up
  //  • CAPCHA_NOT_READY → normal polling status, NOT an error — keep polling
  //
  // Docs: https://2captcha.com/2captcha-api#solving_hcaptcha
  //       https://2captcha.com/api-docs/error-codes
  async function solveWith2Captcha({ apiKey, sitekey, pageUrl, rqdata }) {
    const axios = require('axios');

    // pageurl must be a browser page, never a Discord REST API path.
    const DISCORD_BROWSER_URL = 'https://discord.com/login';
    const browserPageUrl = (pageUrl && !pageUrl.includes('/api/'))
      ? pageUrl
      : DISCORD_BROWSER_URL;

    // A realistic Chrome UA improves solve quality for Enterprise invisible challenges.
    const USER_AGENT =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
      'AppleWebKit/537.36 (KHTML, like Gecko) ' +
      'Chrome/124.0.0.0 Safari/537.36';

    // Fatal error codes — no point retrying the same submission.
    const FATAL_CODES = new Set([
      'ERROR_WRONG_USER_KEY',
      'ERROR_KEY_DOES_NOT_EXIST',
      'ERROR_ZERO_BALANCE',
      'ERROR_IP_NOT_ALLOWED',
      'IP_BANNED',
      'ERROR_PAGEURL',
      'ERROR_WRONG_ID_FORMAT',
      'ERROR_WRONG_CAPTCHA_ID',
    ]);

    // Human-readable Arabic messages for common fatal errors.
    const FRIENDLY = {
      ERROR_ZERO_BALANCE:       'رصيد 2Captcha صفر — يرجى شحن الحساب على 2captcha.com',
      ERROR_WRONG_USER_KEY:     'مفتاح 2Captcha غير صالح (تحقق من أنه 32 حرفاً بالضبط)',
      ERROR_KEY_DOES_NOT_EXIST: 'مفتاح 2Captcha غير موجود — تحقق من لوحة التحكم',
      ERROR_IP_NOT_ALLOWED:     'عنوان IP هذا غير مسموح به في إعدادات 2Captcha',
      IP_BANNED:                'تم حظر IP من 2Captcha مؤقتاً — انتظر بضع دقائق',
    };

    // ── Step 1: Submit the task (retry on ERROR_NO_SLOT_AVAILABLE) ────────
    async function submitTask() {
      const MAX_SLOT_RETRIES = 3;
      for (let attempt = 0; attempt < MAX_SLOT_RETRIES; attempt++) {
        const form = new URLSearchParams();
        form.append('key',        apiKey);
        form.append('method',     'hcaptcha');
        form.append('sitekey',    sitekey);
        form.append('pageurl',    browserPageUrl);
        form.append('enterprise', '1');   // Discord always uses hCaptcha Enterprise
        form.append('invisible',  '1');   // Discord uses invisible mode
        form.append('userAgent',  USER_AGENT);
        form.append('json',       '1');
        // rqdata is Discord's per-request challenge token — required when present.
        if (rqdata) form.append('data', rqdata);

        const res = await axios.post('https://2captcha.com/in.php', form.toString(), {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 20_000,
          validateStatus: () => true,
        });

        if (!res.data) throw new Error('2captcha: ردّ فارغ عند الإرسال (HTTP ' + res.status + ')');

        const body = res.data;
        // Slot unavailable — worker queue full, wait and retry submission.
        if (body.request === 'ERROR_NO_SLOT_AVAILABLE') {
          if (attempt < MAX_SLOT_RETRIES - 1) {
            tsLog('warn', '2Captcha: قائمة الانتظار ممتلئة، إعادة المحاولة خلال 5 ثوانٍ…');
            await new Promise(r => setTimeout(r, 5_000));
            continue;
          }
          throw new Error('2Captcha: قائمة الانتظار ممتلئة بشكل متكرر — حاول لاحقاً');
        }

        if (Number(body.status) !== 1) {
          const code = body.request || JSON.stringify(body);
          throw new Error(FRIENDLY[code] || ('2captcha رفض الإرسال: ' + code));
        }

        return String(body.request); // taskId
      }
    }

    // ── Step 2: Poll for the result ───────────────────────────────────────
    async function pollResult(captchaId) {
      const POLL_INTERVAL_MS = 5_000;  // 5 s min per 2captcha docs
      const TIMEOUT_MS       = 160_000; // 160 s (hCaptcha typical: 15-90 s)
      const startedAt        = Date.now();

      // Initial wait: 5 s for hCaptcha (2captcha docs; 20 s is only for reCAPTCHA).
      await new Promise(r => setTimeout(r, 5_000));

      while (Date.now() - startedAt < TIMEOUT_MS) {
        const res = await axios.get('https://2captcha.com/res.php', {
          params: { key: apiKey, action: 'get', id: captchaId, json: 1 },
          timeout: 15_000,
          validateStatus: () => true,
        });

        const body = res.data || {};
        const req  = body.request || '';

        // Solved successfully.
        if (Number(body.status) === 1 && req) return String(req);

        // Still solving — keep polling.
        if (req === 'CAPCHA_NOT_READY') {
          await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
          continue;
        }

        // Fatal errors — stop immediately with a clear message.
        if (FATAL_CODES.has(req)) {
          throw new Error(FRIENDLY[req] || ('2captcha خطأ فادح: ' + req));
        }

        // ERROR_CAPTCHA_UNSOLVABLE — not charged; signal caller to retry.
        if (req === 'ERROR_CAPTCHA_UNSOLVABLE') {
          const err = new Error('2captcha: العمال فشلوا في الحل (لن يتم خصم رصيد) — إعادة المحاولة');
          err.unsolvable = true;
          throw err;
        }

        // Any other unexpected error code.
        if (req) throw new Error('2captcha خطأ غير متوقع: ' + req);

        await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
      }

      throw new Error('2captcha: انتهت مهلة الانتظار (160 ثانية) بدون حل');
    }

    // ── Orchestrate with retry on ERROR_CAPTCHA_UNSOLVABLE (free re-solve) ─
    const MAX_UNSOLVABLE_RETRIES = 2;
    for (let attempt = 0; attempt <= MAX_UNSOLVABLE_RETRIES; attempt++) {
      let captchaId;
      try {
        captchaId = await submitTask();
      } catch (e) {
        throw e; // submission errors are not retryable here
      }

      try {
        return await pollResult(captchaId);
      } catch (e) {
        if (e.unsolvable && attempt < MAX_UNSOLVABLE_RETRIES) {
          tsLog('warn', `2Captcha: فشل الحل (محاولة ${attempt + 1}/${MAX_UNSOLVABLE_RETRIES}) — إعادة إرسال المهمة…`);
          continue;
        }
        throw e;
      }
    }

    throw new Error('2captcha: استنفدت جميع محاولات إعادة الحل');
  }

  // CapMonster Cloud solver — نفس API تماماً كـ CapSolver لكن بدون حظر Discord.
  // CapMonster لا يطبق قيود سياسة الاستخدام على Discord hCaptcha.
  // Docs: https://docs.capmonster.cloud/docs/captchas/h-captcha
  async function solveWithCapMonster({ apiKey, sitekey, pageUrl, rqdata }) {
    const axios = require('axios');
    const BASE   = 'https://api.capmonster.cloud';

    const DISCORD_PAGE_URL = 'https://discord.com';
    const browserPageUrl   = (pageUrl && !pageUrl.includes('/api/') && pageUrl.startsWith('https://discord.com'))
      ? pageUrl : DISCORD_PAGE_URL;

    const USER_AGENT =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

    // إرسال المهمة
    const task = {
      type:        'HCaptchaTaskProxyless',  // CapMonster يستخدم lowercase 'l'
      websiteURL:  browserPageUrl,
      websiteKey:  sitekey,
      isInvisible: false,
      userAgent:   USER_AGENT,
    };
    if (rqdata) task.enterprisePayload = { rqdata };

    const create = await axios.post(`${BASE}/createTask`,
      { clientKey: apiKey, task },
      { headers: { 'Content-Type': 'application/json' }, timeout: 20_000, validateStatus: () => true }
    );

    if (!create.data) throw new Error('CapMonster: ردّ فارغ (HTTP ' + create.status + ')');
    if (create.data.errorId) {
      const code = create.data.errorCode || '';
      const desc = create.data.errorDescription || '';
      if (code === 'ERROR_ZERO_BALANCE' || desc.includes('zero balance') || desc.includes('balance'))
        throw new Error('CapMonster: رصيد صفر — يرجى شحن الحساب على capmonster.cloud');
      if (code === 'ERROR_KEY_DOES_NOT_EXIST' || desc.includes('key'))
        throw new Error('CapMonster: مفتاح API غير صالح أو غير موجود');
      throw new Error('CapMonster خطأ: ' + ([code, desc].filter(Boolean).join(' — ') || JSON.stringify(create.data)));
    }

    const taskId = create.data.taskId;
    if (!taskId) throw new Error('CapMonster: لم يُرجع taskId');

    // استطلاع النتيجة — انتظار 5 ث ثم كل 4 ث
    const startedAt  = Date.now();
    const TIMEOUT_MS = 180_000;
    await new Promise(r => setTimeout(r, 5_000));

    while (Date.now() - startedAt < TIMEOUT_MS) {
      const r = await axios.post(`${BASE}/getTaskResult`,
        { clientKey: apiKey, taskId },
        { timeout: 15_000, validateStatus: () => true }
      );
      const body = r.data || {};
      if (body.errorId) throw new Error('CapMonster poll error: ' + (body.errorCode || body.errorDescription));
      if (body.status === 'ready' && body.solution?.gRecaptchaResponse) {
        return String(body.solution.gRecaptchaResponse);
      }
      await new Promise(r => setTimeout(r, 4_000));
    }
    throw new Error('CapMonster: انتهت مهلة الانتظار (180 ث) بدون حل');
  }

  // Manual solver — exposes the challenge over SSE, awaits the user clicking
  // the hCaptcha widget in the UI and POSTing the token to /api/ts/captcha-resolve.
  // Times out after MANUAL_TIMEOUT_MS so a forgotten challenge cannot wedge the session.
  const MANUAL_CAPTCHA_TIMEOUT_MS = 5 * 60 * 1000;
  function solveCaptchaManual({ sitekey, service, rqdata, rqtoken, url, context }) {
    const s = tsSession();
    return new Promise((resolve, reject) => {
      const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
      const challenge = {
        id, sitekey, service: service || 'hcaptcha',
        rqdata, rqtoken, url, context,
        createdAt: Date.now(),
        attempts: (s.pendingCaptcha?.attempts || 0) + 1,
        resolve, reject,
        timer: null,
      };
      challenge.timer = setTimeout(() => {
        if (s.pendingCaptcha && s.pendingCaptcha.id === id) {
          s.pendingCaptcha = null;
          tsLog('error', 'انتهت مهلة الكابتشا اليدوية بدون حل');
          pushTsEvent('ts_captcha_timeout', { id });
          pushTsEvent('ts_progress');
          reject(new Error('Manual captcha timed out (5 min)'));
        }
      }, MANUAL_CAPTCHA_TIMEOUT_MS);
      s.pendingCaptcha = challenge;
      // Diagnostic: surface whether Discord actually sent rqdata so the user
      // can tell from the UI log alone if the "invalid-response" failure mode
      // is a missing-rqdata problem vs a stale-cached frontend problem.
      const _rqLen = rqdata ? String(rqdata).length : 0;
      tsLog('warn', `مطلوب حل كابتشا يدوياً — افتح النافذة المنبثقة (rqdata: ${_rqLen ? `موجود ${_rqLen} حرف` : 'غير موجود'})`);
      pushTsEvent('ts_captcha', { challenge: {
        id, sitekey, service: challenge.service, context, attempts: challenge.attempts,
        // Forward rqdata so the modal can pass it to hcaptcha.render().
        // Without this the produced token is generic and Discord rejects it.
        rqdata: rqdata || null,
      } });
      pushTsEvent('ts_progress');
    });
  }

  // The unified solver passed into every Discord call. Tries the configured
  // provider first (2Captcha or CapSolver), then falls back to manual unless
  // the user explicitly disabled the manual fallback in settings.
  function buildSolveCaptcha() {
    return async function solveCaptcha({ sitekey, service, rqdata, rqtoken, url, context }) {
      const settings = tsCaptchaSettings();
      const apiKey   = tsCaptchaApiKey();
      const provider = settings.provider || '2captcha';

      if (apiKey && provider === 'capsolver') {
        try {
          tsLog('info', 'محاولة حل الكابتشا تلقائياً عبر CapSolver…');
          const token = await solveWithCapSolver({ apiKey, sitekey, pageUrl: url, rqdata, rqtoken });
          if (token) { tsLog('success', 'تم حل الكابتشا عبر CapSolver ✓'); return token; }
        } catch (e) { tsLog('warn', 'CapSolver فشل: ' + (e.message || e)); }
      }

      if (apiKey && provider === 'capmonster') {
        try {
          tsLog('info', 'محاولة حل الكابتشا تلقائياً عبر CapMonster…');
          const token = await solveWithCapMonster({ apiKey, sitekey, pageUrl: url, rqdata });
          if (token) { tsLog('success', 'تم حل الكابتشا عبر CapMonster ✓'); return token; }
        } catch (e) { tsLog('warn', 'CapMonster فشل: ' + (e.message || e)); }
      }

      if (apiKey && provider === '2captcha') {
        try {
          tsLog('info', 'محاولة حل الكابتشا تلقائياً عبر 2Captcha…');
          const token = await solveWith2Captcha({ apiKey, sitekey, pageUrl: url, rqdata });
          if (token) { tsLog('success', 'تم حل الكابتشا عبر 2Captcha ✓'); return token; }
        } catch (e) { tsLog('warn', '2Captcha فشل: ' + (e.message || e)); }
      }

      if (apiKey || settings.manualFallback === false) {
        throw new Error(
          apiKey
            ? 'الحل التلقائي فشل ولا يوجد رجوع يدوي عند وجود API key — تحقق من رصيدك أو صحة المفتاح'
            : 'No automatic solver succeeded and manual fallback is disabled'
        );
      }
      return await solveCaptchaManual({ sitekey, service, rqdata, rqtoken, url, context });
    };
  }

  // ─── Endpoints ─────────────────────────────────────────────────

  // Captcha settings — view / update the hCaptcha solver configuration.
  app.get('/api/ts/captcha-settings', (req, res) => {
    ok(res, { settings: tsCaptchaSettingsPublic() });
  });
  app.post('/api/ts/captcha-settings', (req, res) => {
    const { provider, apiKey, manualFallback, clearKey } = req.body || {};
    const d = ensureData();
    if (!d.tsCaptcha || typeof d.tsCaptcha !== 'object') d.tsCaptcha = {};
    if (typeof provider === 'string' && provider) {
      const allowed = ['2captcha', 'capsolver', 'capmonster'];
      if (!allowed.includes(provider)) return fail(res, new Error('Unsupported provider'));
      d.tsCaptcha.provider = provider;
    }
    if (clearKey === true) {
      d.tsCaptcha.apiKey = '';
    } else if (typeof apiKey === 'string' && apiKey.trim()) {
      const trimmed = apiKey.trim();
      if (trimmed.length < 10 || trimmed.length > 256) return fail(res, new Error('Invalid API key length'));
      d.tsCaptcha.apiKey = encrypt(trimmed);
    }
    if (typeof manualFallback === 'boolean') d.tsCaptcha.manualFallback = manualFallback;
    writeData(d);
    ok(res, { settings: tsCaptchaSettingsPublic() });
  });

  // Captcha key verification — checks balance and validity for the saved key.
  app.get('/api/ts/captcha-verify', async (req, res) => {
    const apiKey = tsCaptchaApiKey();
    const settings = tsCaptchaSettings();
    const provider = settings.provider || '2captcha';
    if (!apiKey) return fail(res, new Error('لا يوجد API key محفوظ'));
    try {
      if (provider === 'capsolver') {
        const r = await axios.post('https://api.capsolver.com/getBalance',
          { clientKey: apiKey }, { timeout: 12000, validateStatus: () => true });
        if (r.data && r.data.errorId === 0) {
          return ok(res, { ok: true, balance: r.data.balance, currency: 'USD', provider: 'CapSolver' });
        }
        return ok(res, { ok: false, error: r.data?.errorDescription || 'مفتاح غير صالح', provider: 'CapSolver' });
      } else if (provider === 'capmonster') {
        const r = await axios.post('https://api.capmonster.cloud/getBalance',
          { clientKey: apiKey }, { timeout: 12000, validateStatus: () => true });
        if (r.data && r.data.errorId === 0) {
          return ok(res, { ok: true, balance: r.data.balance, currency: 'USD', provider: 'CapMonster' });
        }
        const errDesc = r.data?.errorDescription || r.data?.errorCode || 'مفتاح غير صالح';
        return ok(res, { ok: false, error: errDesc, provider: 'CapMonster' });
      } else {
        const r = await axios.get(
          `https://2captcha.com/res.php?action=getbalance&key=${encodeURIComponent(apiKey)}`,
          { timeout: 12000 });
        const text = String(r.data || '').trim();
        if (!isNaN(parseFloat(text))) {
          return ok(res, { ok: true, balance: parseFloat(text), currency: 'USD', provider: '2Captcha' });
        }
        return ok(res, { ok: false, error: text, provider: '2Captcha' });
      }
    } catch (e) {
      return fail(res, e);
    }
  });

  // Manual captcha resolution — frontend posts the hCaptcha token here after
  // the user solved the widget. We resolve the pending Promise so the request
  // chain inside trueStudio.js can continue.
  app.post('/api/ts/captcha-resolve/:id', (req, res) => {
    const s = tsSession();
    const id = String(req.params.id || '');
    const token = String((req.body && req.body.token) || '');
    if (!s.pendingCaptcha || s.pendingCaptcha.id !== id) {
      return fail(res, new Error('No matching pending captcha'));
    }
    if (!token || token.length < 10) return fail(res, new Error('Invalid captcha token'));
    const ch = s.pendingCaptcha;
    s.pendingCaptcha = null;
    if (ch.timer) clearTimeout(ch.timer);
    // Diagnostic: real hCaptcha tokens are ~700-2000 chars and start with "P1_"
    // or "E0_". A token shorter than ~200 chars or one that doesn't start with
    // those prefixes is almost certainly NOT a valid hCaptcha solve and will be
    // rejected by Discord as "invalid-response" — surface that in the UI log so
    // the user knows immediately whether the widget actually produced a token.
    const _tokPrefix = token.slice(0, 4);
    const _looksReal = token.length >= 200 && /^(P[01]_|E[01]_)/.test(token);
    tsLog('success', `تم تأكيد حل الكابتشا اليدوي ✓ (طول: ${token.length}، بداية: "${_tokPrefix}"، يبدو ${_looksReal ? 'صحيح' : '⚠️ مشبوه'})`);
    try { ch.resolve(token); } catch {}
    pushTsEvent('ts_captcha_resolved', { id });
    pushTsEvent('ts_progress');
    ok(res, { snapshot: tsSnapshot() });
  });

  // Cancel an outstanding manual captcha (user closed the popup).
  app.post('/api/ts/captcha-cancel/:id', (req, res) => {
    const s = tsSession();
    const id = String(req.params.id || '');
    if (!s.pendingCaptcha || s.pendingCaptcha.id !== id) {
      return ok(res, { snapshot: tsSnapshot() });
    }
    const ch = s.pendingCaptcha;
    s.pendingCaptcha = null;
    if (ch.timer) clearTimeout(ch.timer);
    tsLog('warn', 'تم إلغاء الكابتشا — الجلسة ستفشل');
    try { ch.reject(new Error('Captcha cancelled by user')); } catch {}
    pushTsEvent('ts_captcha_cancelled', { id });
    pushTsEvent('ts_progress');
    ok(res, { snapshot: tsSnapshot() });
  });

  app.get('/api/ts/accounts', (req, res) => {
    ok(res, { accounts: tsAccountsPublic() });
  });

  app.post('/api/ts/accounts', (req, res) => {
    const { email, password, totpSecret, directToken } = req.body || {};
    if (!email || typeof email !== 'string') return fail(res, new Error('Email is required'));
    const cleanEmail = email.trim().toLowerCase();
    if (cleanEmail.length > 254 || !cleanEmail.includes('@')) return fail(res, new Error('Invalid email'));
    if (password && typeof password !== 'string') return fail(res, new Error('Password must be a string'));
    if (totpSecret && !ts.isValidTotpSecret(totpSecret)) return fail(res, new Error('Invalid 2FA secret (must be a base32 string)'));
    if (directToken && typeof directToken !== 'string') return fail(res, new Error('Token must be a string'));

    const d = ensureData();
    if (!Array.isArray(d.tsAccounts)) d.tsAccounts = [];
    let rec = tsFindAccount(cleanEmail);
    if (!rec) {
      rec = { email: cleanEmail, password: '', totpSecret: '', directToken: '', addedAt: Date.now() };
      d.tsAccounts.push(rec);
    }
    if (typeof password === 'string' && password) rec.password = encrypt(password);
    else if (password === '') rec.password = '';
    if (typeof totpSecret === 'string' && totpSecret) rec.totpSecret = encrypt(totpSecret.replace(/\s+/g, ''));
    else if (totpSecret === '') rec.totpSecret = '';
    if (typeof directToken === 'string' && directToken.trim()) rec.directToken = encrypt(directToken.trim());
    else if (directToken === '') rec.directToken = '';
    writeData(d);
    ok(res, { account: { email: rec.email, hasPassword: !!rec.password, hasTotp: !!rec.totpSecret, hasDirectToken: !!rec.directToken, addedAt: rec.addedAt } });
  });

  app.delete('/api/ts/accounts/:email', (req, res) => {
    const target = String(req.params.email || '').toLowerCase();
    const d = ensureData();
    const before = (d.tsAccounts || []).length;
    d.tsAccounts = (d.tsAccounts || []).filter(a => (a.email || '').toLowerCase() !== target);
    if (d.tsAccounts.length === before) return fail(res, new Error('Account not found'));
    writeData(d);
    ok(res, { removed: target });
  });

  app.get('/api/ts/state', (req, res) => {
    ok(res, { snapshot: tsSnapshot(), accounts: tsAccountsPublic() });
  });

  // Pre-flight: log in (and verify TOTP if a 2FA secret is saved) WITHOUT
  // creating any team or bot. Result is stored on the account so the UI can
  // show a green "verified" badge until next session.
  app.post('/api/ts/test-account', async (req, res) => {
    const target = String((req.body && req.body.email) || '').toLowerCase();
    const acct = tsFindAccount(target);
    if (!acct) return fail(res, new Error('Account not found'));
    const creds = tsDecryptAccount(acct);
    if (!creds.password && !creds.directToken) return fail(res, new Error('Saved account has no password and no direct token — re-save it'));
    try {
      const client = ts.createClient();
      const netOpts = { solveCaptcha: buildSolveCaptcha(), client };
      const verify = { ok: false, status: 'unknown', message: '', user: null, mfa: !!creds.totpSecret, at: Date.now() };
      try {
        let token, userId;
        if (creds.directToken) {
          // Direct token path — no login needed, verify it immediately
          token = creds.directToken;
          tsLog('info', 'اختبار التوكن المباشر…');
        } else {
          const r = await ts.login({
            email: creds.email, password: creds.password, totpSecret: creds.totpSecret, netOpts,
          });
          token = r.token; userId = r.userId;
        }
        // Use the same warmed client for /users/@me so cookies match
        const meR = await client.http.get('https://discord.com/api/v9/users/@me', {
          headers: {
            Authorization: token,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'X-Super-Properties': client.superPropsB64,
            'X-Fingerprint': client.fingerprint || undefined,
            'Origin': 'https://discord.com',
            'Referer': 'https://discord.com/channels/@me',
          },
          timeout: 15000, validateStatus: () => true,
        }).catch(() => ({ status: 0, data: null }));
        if (meR.status >= 400) {
          verify.status = 'token_unusable';
          verify.message = `Login OK but /users/@me returned ${meR.status}`;
        } else {
          verify.ok = true;
          verify.status = 'verified';
          verify.user = {
            id: meR.data?.id || userId || null,
            username: meR.data?.username || '',
            globalName: meR.data?.global_name || '',
            mfa_enabled: !!meR.data?.mfa_enabled,
            verified: !!meR.data?.verified,
          };
          verify.message = 'Account verified';
          // Cache token + the warmed client so Start session reuses BOTH
          tsStoreToken(creds.email, token, client);
        }
      } catch (e) {
        verify.status = e.code || 'login_failed';
        verify.message = e.message || String(e);
      }
      // Persist the result (without exposing the token)
      const d = ensureData();
      const rec = (d.tsAccounts || []).find(a => (a.email || '').toLowerCase() === target);
      if (rec) {
        rec.verify = {
          ok: !!verify.ok,
          status: verify.status,
          message: verify.message,
          mfa: verify.mfa,
          username: verify.user?.username || '',
          userId: verify.user?.id || '',
          at: verify.at,
        };
        writeData(d);
      }
      ok(res, { verify, accounts: tsAccountsPublic() });
    } catch (e) {
      fail(res, e);
    }
  });

  // Library: fetch the account's full Discord developer state — every team
  // and every application/bot the user owns — and group apps by their team_id.
  // Powers the visual library cards (matches the screenshot mockup).
  app.get('/api/ts/library', async (req, res) => {
    const email = String(req.query.email || '').toLowerCase();
    if (!email) return fail(res, new Error('Email is required'));
    try {
      const { token, client } = await tsGetToken(email);
      const netOpts = { solveCaptcha: buildSolveCaptcha(), client };

      // Fetch teams + apps + current user in parallel
      const [teams, apps, me] = await Promise.all([
        ts.listTeams({ token, netOpts }).catch(() => []),
        ts.listApplications({ token, netOpts }).catch(() => []),
        ts.getCurrentUser({ token, netOpts }).catch(() => null),
      ]);

      const currentUserId = me?.id || null;

      // Helper to map a raw Discord application object to our card shape
      function toCard(a) {
        return {
          id: a.id,
          name: a.name,
          icon: a.icon || null,
          isBot: !!a.bot,
          botId: a.bot?.id || null,
          botUsername: a.bot?.username || null,
          createdAt: snowflakeToTs(a.id),
        };
      }

      // Index teams by id — keep member info so frontend can show owner/member badge
      const teamMap = new Map();
      for (const t of teams) {
        // Find the current user's role in this team
        let myRole = null;
        if (currentUserId && Array.isArray(t.members)) {
          const me = t.members.find(m => m.user?.id === currentUserId);
          myRole = me?.role || null;
        }
        // Fallback: if owner_user_id matches, role is owner
        if (!myRole && t.owner_user_id === currentUserId) myRole = 'owner';

        teamMap.set(t.id, {
          id: t.id,
          name: t.name,
          icon: t.icon || null,
          ownerUserId: t.owner_user_id || null,
          isOwner: t.owner_user_id === currentUserId,
          myRole: myRole || (t.owner_user_id === currentUserId ? 'owner' : 'member'),
          memberCount: Array.isArray(t.members) ? t.members.length : null,
          apps: [],
          appsFromTeamEndpoint: false,
        });
      }

      // Map apps from /applications — these are apps owned by the current user
      const personal = [];
      for (const a of apps) {
        const card = toCard(a);
        const tid = a.team?.id || a.team_id || null;
        if (tid && teamMap.has(tid)) {
          teamMap.get(tid).apps.push(card);
        } else if (tid && !teamMap.has(tid)) {
          // App references a team not in /teams — synthesize the team entry
          teamMap.set(tid, {
            id: tid,
            name: a.team?.name || ('Team ' + tid.slice(0, 6)),
            icon: a.team?.icon || null,
            ownerUserId: a.team?.owner_user_id || null,
            isOwner: a.team?.owner_user_id === currentUserId,
            myRole: a.team?.owner_user_id === currentUserId ? 'owner' : 'member',
            memberCount: null,
            apps: [card],
            appsFromTeamEndpoint: false,
          });
        } else {
          personal.push(card);
        }
      }

      // For teams where the /applications endpoint returned 0 apps (typically
      // teams where the user is a MEMBER, not the owner), fetch apps via
      // GET /teams/:teamId/applications which works for all roles.
      const emptyTeamIds = Array.from(teamMap.values())
        .filter(t => t.apps.length === 0)
        .map(t => t.id);

      if (emptyTeamIds.length) {
        const teamAppResults = await Promise.all(
          emptyTeamIds.map(tid =>
            ts.listTeamApplications({ token, teamId: tid, netOpts })
              .then(list => ({ tid, list }))
              .catch(() => ({ tid, list: [] }))
          )
        );
        for (const { tid, list } of teamAppResults) {
          if (!list.length) continue;
          const entry = teamMap.get(tid);
          if (!entry) continue;
          for (const a of list) {
            entry.apps.push(toCard(a));
          }
          entry.appsFromTeamEndpoint = true;
        }
      }

      const TEAM_APP_LIMIT = 25;
      const teamsOut = Array.from(teamMap.values()).map(t => ({
        ...t,
        appLimit: TEAM_APP_LIMIT,
        apps: t.apps.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)),
      }));

      ok(res, {
        teams: teamsOut,
        personal: personal.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)),
        currentUserId,
        totals: { teams: teamsOut.length, apps: apps.length, personalApps: personal.length },
      });
    } catch (e) {
      fail(res, e);
    }
  });

  // ── Proxy verification ──────────────────────────────────────────────────
  // Tests that a proxy URL is reachable and returns the egress IP.
  app.post('/api/ts/proxy-verify', async (req, res) => {
    const { proxyUrl } = req.body || {};
    if (!proxyUrl) return fail(res, new Error('proxyUrl is required'));
    try {
      const result = await testProxy(String(proxyUrl).trim());
      ok(res, { ok: result.ok, ip: result.ip || null, error: result.error || null });
    } catch (e) {
      ok(res, { ok: false, ip: null, error: e.message || String(e) });
    }
  });

  // ── Standalone team management ──────────────────────────────────────────
  // List teams for the selected account (used by UI team-selector dropdown).
  app.get('/api/ts/teams', async (req, res) => {
    const email = String(req.query.email || '').toLowerCase().trim();
    if (!email) return fail(res, new Error('email is required'));
    try {
      const { token, client } = await tsGetToken(email);
      const netOpts = { solveCaptcha: buildSolveCaptcha(), client };
      const teams = await ts.listTeams({ token, netOpts });
      const mapped = (teams || []).map(t => ({
        id: t.id,
        name: t.name,
        icon: t.icon || null,
        appCount: (t.apps || []).length,
        appLimit: 25,
        isOwner: !!t.isOwner,
      }));
      ok(res, { teams: mapped });
    } catch (e) { fail(res, e); }
  });

  // Create a new team without starting a full automation session.
  app.post('/api/ts/teams/create', async (req, res) => {
    const { email, name } = req.body || {};
    if (!email || !name) return fail(res, new Error('email and name are required'));
    try {
      const { token, client } = await tsGetToken(email);
      const netOpts = { solveCaptcha: buildSolveCaptcha(), client };
      // Ensure dev portal is warmed before creating team (avoids "no teams" after GET /teams)
      if (!client.devPortalLoaded) {
        try {
          await ts.simulateBrowsing({ token, netOpts });
          await ts.humanDelay(800, 1800);
          await ts.loadDevPortal({ client, token, netOpts });
        } catch (_) {}
      }
      await ts.navigateTo({ client, page: 'https://discord.com/developers/teams' });
      await ts.humanDelay(600, 1400);
      const team = await ts.createTeam({ token, name: String(name).slice(0, 32), netOpts });
      ok(res, { team: { id: team.id, name: team.name, icon: team.icon || null } });
    } catch (e) { fail(res, e); }
  });

  // Transfer an existing application to a team.
  // Requires the app to be owned by the user (personal app) and MFA if 2FA is enabled.
  app.post('/api/ts/teams/:teamId/add-app', async (req, res) => {
    const teamId = String(req.params.teamId || '').trim();
    const { email, appId } = req.body || {};
    if (!teamId || !email || !appId) return fail(res, new Error('teamId, email and appId are required'));
    try {
      const acct = tsFindAccount(email);
      if (!acct) throw new Error('Account not found — save it first');
      const creds = tsDecryptAccount(acct);
      const { token, client } = await tsGetToken(email);
      const netOpts = {
        solveCaptcha: buildSolveCaptcha(), client,
        totpSecret: creds.totpSecret || undefined,
        password: creds.password || undefined,
      };
      // Acquire MFA token if 2FA is enabled
      let mfaToken = null;
      if (creds.totpSecret) {
        try { mfaToken = await ts.acquireMfa({ token, totpSecret: creds.totpSecret, netOpts }); }
        catch (_) {}
      }
      const result = await ts.transferAppToTeam({ token, appId, teamId, mfa: mfaToken, netOpts });
      ok(res, { app: { id: result.id, name: result.name, teamId } });
    } catch (e) { fail(res, e); }
  });

  // Snowflake epoch (Discord) → ms timestamp
  function snowflakeToTs(id) {
    try { return Number(BigInt(id) >> 22n) + 1420070400000; } catch { return 0; }
  }

  // Reset a single bot's token. Used from the Library overlay so the user can
  // generate a fresh token for any bot (in any team or personal app) without
  // running the full automation session. Returns the new token in the response
  // (this is the only time it can be retrieved — the user must copy it now).
  //
  // The flow MIRRORS the creation pipeline so Discord doesn't reject the
  // request as suspicious (which manifests as an empty token in the response
  // and the user-visible "token not returned" error):
  //   1. ensure a logged-in token + dev-portal warm-up
  //   2. acquire an MFA-Authorization header when 2FA is enabled
  //   3. navigate the simulated browser to the app's bot page
  //   4. ensureBot — guarantees a bot user exists on the application
  //   5. resetBotToken — Discord returns the fresh token
  app.post('/api/ts/applications/:appId/reset-bot-token', async (req, res) => {
    const appId = String(req.params.appId || '').trim();
    const email = String((req.body && req.body.email) || '').toLowerCase();
    if (!appId) return fail(res, new Error('Application id is required'));
    if (!email) return fail(res, new Error('Email is required'));
    try {
      const acct = tsFindAccount(email);
      if (!acct) throw new Error('Account not found — save it first');
      const creds = tsDecryptAccount(acct);

      // 1) Get a working token + axios client (re-uses the cached session
      //    when valid; logs in fresh + handles captcha when not).
      const { token, client } = await tsGetToken(email);
      // Include totpSecret in netOpts so _request can auto-resolve MFA
      // challenges (code 60003 + ticket) transparently on any endpoint.
      const netOpts = {
        solveCaptcha: buildSolveCaptcha(),
        client,
        totpSecret: creds.totpSecret || undefined,
        // Password is passed so _req can auto-resolve MFA for accounts
        // that have NO 2FA enabled (Discord requires password verification
        // via POST /mfa/finish with mfa_type:"password" in that case).
        password: creds.password || undefined,
      };

      // Warm-up the dev portal once per cached client. Without this,
      // Discord sometimes returns 200 OK with an empty body on /bot/reset.
      if (!client.devPortalLoaded) {
        try {
          tsLog('info', 'محاكاة تصفح طبيعي قبل إعادة تعيين التوكن…');
          await ts.simulateBrowsing({ token, netOpts });
          await ts.humanDelay(600, 1200);
          tsLog('info', 'فتح Developer Portal…');
          await ts.loadDevPortal({ client, token, netOpts });
        } catch (e) {
          tsLog('warn', 'تعذر إكمال محاكاة التصفح: ' + (e.message || String(e)));
        }
      }

      // mfaToken is now handled automatically inside _request via the
      // 60003-ticket flow. We keep this variable for the _refreshMfa helper
      // below (used before each attempt as a best-effort pre-warm).
      let mfaToken = null;

      // Helper: map Discord MFA errors into clear user-facing messages.
      function _mapMfaError(e) {
        const code = e?.data?.code;
        const msg  = (e?.message || '').toLowerCase();
        const looksMfa = code === 60003 || /two[-\s]?factor|2fa|mfa/i.test(msg);
        if (!looksMfa) return null;
        if (!creds.totpSecret) {
          return new Error(
            'Discord rejected the reset: this account has no 2FA secret saved here. ' +
            'Open Bot-Studio → edit the account → paste the Discord 2FA TOTP secret → save → retry.'
          );
        }
        return new Error(
          'Discord rejected the reset (Two-Factor required) even though a TOTP secret is saved. ' +
          'Re-check the saved 2FA secret matches Discord (open Discord → User Settings → My Account → 2FA → reveal/copy the secret), then retry.'
        );
      }

      // Helper: ensure a fresh MFA code is available before each reset attempt.
      async function _refreshMfa() {
        if (!creds.totpSecret) return;
        try {
          mfaToken = await ts.acquireMfa({ token, totpSecret: creds.totpSecret, netOpts });
        } catch (_) { /* best-effort */ }
      }

      // 3–4) Simulate a real user clicking "Reset Token":
      //   navigate info page → click Bot sidebar → read page → click button.
      //   On retry we repeat the full click simulation so the Referer sequence
      //   looks exactly like a second human visit, not a bare API retry.
      let newToken;
      for (let attempt = 1; attempt <= 2; attempt++) {
        tsLog('info', attempt === 1
          ? 'محاكاة النقر على "Reset Token" في Developer Portal…'
          : 'إعادة المحاولة — تكرار محاكاة النقر…');

        // Simulate click navigation (info page → bot page + SPA GET requests)
        try {
          await ts.simulateResetTokenButtonClick({ client, token, appId, netOpts });
        } catch (e) {
          tsLog('warn', 'تعذرت محاكاة التصفح: ' + (e.message || String(e)));
        }

        // Ensure a bot user exists (idempotent — 400 = already a bot, ignored).
        try {
          await ts.ensureBot({ token, appId, netOpts });
          await ts.humanDelay(500, 900);
        } catch (e) {
          tsLog('warn', 'ensureBot: ' + (e.message || String(e)));
        }

        // Refresh MFA before every attempt (TOTP codes expire every 30s).
        await _refreshMfa();

        tsLog('info', `إعادة تعيين توكن البوت (محاولة ${attempt}/2)…`);
        try {
          newToken = await ts.resetBotToken({ token, appId, mfa: mfaToken, netOpts });
        } catch (e) {
          const mfaErr = _mapMfaError(e);
          if (mfaErr) throw mfaErr;
          if (attempt < 2) {
            tsLog('warn', `فشل المحاولة ${attempt} (${e.message || e}) — سيُعاد المحاولة…`);
            await ts.humanDelay(3000, 4500);
            continue;
          }
          throw e;
        }

        if (newToken && typeof newToken === 'string') break; // ✓ success

        // Discord returned 200 with empty body — wait and retry
        if (attempt < 2) {
          tsLog('warn', 'Discord أرجع استجابة فارغة — انتظار قبل إعادة المحاولة…');
          await ts.humanDelay(3000, 4500);
        }
      }

      if (!newToken || typeof newToken !== 'string') {
        throw new Error(
          'Discord لم يُرجع توكناً بعد محاولتين. ' +
          'تأكد من أن الحساب يدعم 2FA وأن TOTP Secret محفوظ، وأن التطبيق يحتوي على Bot.'
        );
      }
      tsLog('success', 'تم توليد توكن جديد بنجاح ✓');
      // Save directly to persistent store so the token appears in Bot Tokens
      // even if the client-side save call fails (network blip, page close, etc.)
      try {
        const { name: reqName, icon: reqIcon } = req.body || {};
        const tkList = await botTokensStore.get() || [];
        const tkFiltered = tkList.filter(t => t.appId !== appId);
        tkFiltered.unshift({
          appId, name: reqName || appId, icon: reqIcon || null,
          token: newToken, email, resetAt: Date.now(),
        });
        await botTokensStore.set(tkFiltered);
      } catch (_) {}
      ok(res, { token: newToken, appId });
    } catch (e) {
      fail(res, e);
    }
  });

  // ── Bot Tokens persistent store ────────────────────────────────────────
  // Saves a record for every bot whose token has been revealed/reset.
  // Stored as an array of { appId, name, icon, token, resetAt, email }.

  app.get('/api/ts/bot-tokens', async (req, res) => {
    try {
      const list = await botTokensStore.get() || [];
      ok(res, { tokens: list });
    } catch (e) { fail(res, e); }
  });

  app.post('/api/ts/bot-tokens', async (req, res) => {
    try {
      const { appId, name, icon, token, email } = req.body || {};
      if (!appId || !token) return fail(res, new Error('appId and token are required'));
      const list = await botTokensStore.get() || [];
      const filtered = list.filter(t => t.appId !== appId);
      filtered.unshift({ appId, name: name || appId, icon: icon || null, token, email: email || '', resetAt: Date.now() });
      await botTokensStore.set(filtered);
      ok(res, { tokens: filtered });
    } catch (e) { fail(res, e); }
  });

  app.delete('/api/ts/bot-tokens/:appId', async (req, res) => {
    try {
      const appId = String(req.params.appId || '').trim();
      const list = await botTokensStore.get() || [];
      const filtered = list.filter(t => t.appId !== appId);
      await botTokensStore.set(filtered);
      ok(res, { tokens: filtered });
    } catch (e) { fail(res, e); }
  });

  // ── Reset-All background session (per-user) ──────────────────────────────
  // Runs entirely on the server so it continues even when the user navigates
  // away. Frontend monitors progress via SSE (ts_reset_all_progress / ts_reset_all_done).
  const _tsResetAllSessions = new Map();
  function tsResetAllSession() {
    const uid = currentUserId();
    if (!_tsResetAllSessions.has(uid)) {
      _tsResetAllSessions.set(uid, { state: 'idle', total: 0, done: 0, failed: 0, current: '', cancelRequested: false, errors: [] });
    }
    return _tsResetAllSessions.get(uid);
  }
  function pushResetAllEvent(type, extra = {}) {
    const s = tsResetAllSession();
    sseBroadcast(type, {
      resetAll: { state: s.state, total: s.total, done: s.done, failed: s.failed, current: s.current, errors: s.errors.slice(-10) },
      _uid: currentUserId(),
      ...extra,
    });
  }

  app.get('/api/ts/reset-all/state', (req, res) => {
    const s = tsResetAllSession();
    ok(res, { state: s.state, total: s.total, done: s.done, failed: s.failed, current: s.current, errors: s.errors.slice(-10) });
  });

  app.post('/api/ts/reset-all/stop', (req, res) => {
    const s = tsResetAllSession();
    s.cancelRequested = true;
    ok(res, { state: s.state });
  });

  app.post('/api/ts/reset-all/start', async (req, res) => {
    const { email, bots } = req.body || {};
    if (!email || !Array.isArray(bots) || !bots.length) {
      return fail(res, new Error('email and bots[] are required'));
    }
    const s = tsResetAllSession();
    if (s.state === 'running') return fail(res, new Error('A reset-all is already running'));

    Object.assign(s, { state: 'running', total: bots.length, done: 0, failed: 0, current: '', cancelRequested: false, errors: [] });
    pushResetAllEvent('ts_reset_all_progress');
    ok(res, { state: s.state, total: s.total });

    const uid = currentUserId();
    withUser(uid, async () => {
      try {
        const acct = tsFindAccount(email);
        if (!acct) throw new Error('Account not found');
        const creds = tsDecryptAccount(acct);
        const { token, client } = await tsGetToken(email);
        const netOpts = {
          solveCaptcha: buildSolveCaptcha(), client,
          totpSecret: creds.totpSecret || undefined,
          password: creds.password || undefined,
        };
        // Warm-up the dev portal once per cached client
        if (!client.devPortalLoaded) {
          try {
            await ts.simulateBrowsing({ token, netOpts });
            await ts.humanDelay(600, 1200);
            await ts.loadDevPortal({ client, token, netOpts });
          } catch (_) {}
        }
        for (let i = 0; i < bots.length; i++) {
          if (s.cancelRequested) break;
          const bot = bots[i];
          s.current = bot.name;
          pushResetAllEvent('ts_reset_all_progress');
          try {
            let mfaToken = null;
            if (creds.totpSecret) {
              try { mfaToken = await ts.acquireMfa({ token, totpSecret: creds.totpSecret, netOpts }); } catch (_) {}
            }
            try { await ts.simulateResetTokenButtonClick({ client, token, appId: bot.id, netOpts }); } catch (_) {}
            try { await ts.ensureBot({ token, appId: bot.id, netOpts }); await ts.humanDelay(500, 900); } catch (_) {}
            const newToken = await ts.resetBotToken({ token, appId: bot.id, mfa: mfaToken, netOpts });
            if (!newToken) throw new Error('No token returned');
            // Save to persistent bot-tokens store
            const list = await botTokensStore.get() || [];
            const filtered = list.filter(t => t.appId !== bot.id);
            filtered.unshift({ appId: bot.id, name: bot.name, icon: bot.icon || null, token: newToken, email, resetAt: Date.now() });
            await botTokensStore.set(filtered);
            s.done++;
            pushResetAllEvent('ts_reset_all_progress', { lastBot: { appId: bot.id, name: bot.name, icon: bot.icon || null, token: newToken } });
          } catch (e) {
            s.failed++;
            s.errors.push(bot.name + ': ' + (e?.message || String(e)));
            pushResetAllEvent('ts_reset_all_progress');
          }
          // Human-like delay between bots
          if (i < bots.length - 1 && !s.cancelRequested) {
            await new Promise(r => setTimeout(r, 8000 + Math.floor(Math.random() * 10000)));
          }
        }
        s.state = s.cancelRequested ? 'cancelled' : 'done';
      } catch (e) {
        s.state = 'error';
        s.errors.push(e?.message || String(e));
      } finally {
        s.current = '';
        s.cancelRequested = false;
        pushResetAllEvent('ts_reset_all_done');
      }
    }).catch(() => {});
  });

  app.post('/api/ts/stop', (req, res) => {
    const s = tsSession();
    if (s.state === 'idle' || s.state === 'done' || s.state === 'cancelled') {
      return ok(res, { snapshot: tsSnapshot() });
    }
    s.cancelRequested = true;
    tsLog('warn', 'إيقاف الجلسة قيد التنفيذ…');
    pushTsEvent('ts_progress');
    ok(res, { snapshot: tsSnapshot() });
  });

  app.post('/api/ts/start', async (req, res) => {
    const s = tsSession();
    if (s.state === 'running' || s.state === 'waiting') {
      return fail(res, new Error('A session is already running'));
    }
    const { email, rules, count, prefix, waitMinutes, proxyUrl, speed, selectedTeamId, brightData } = req.body || {};
    const acct = tsFindAccount(email);
    if (!acct) return fail(res, new Error('Account not found — save it first'));
    const creds = tsDecryptAccount(acct);
    if (!creds.password && !creds.directToken) return fail(res, new Error('Saved account has no password and no direct token — re-save it'));

    const r = {
      createTeams: !!(rules && rules.createTeams),
      createBots:  !!(rules && rules.createBots),
      linkBots:    !!(rules && rules.linkBots),
    };
    const n = Math.max(1, Math.min(50, parseInt(count) || 1));
    const wait = Math.max(0, Math.min(60, parseInt(waitMinutes) || 0));
    const pfx = String(prefix || 'Bot').slice(0, 24).trim() || 'Bot';
    const rawProxy = typeof proxyUrl === 'string' ? proxyUrl : '';
    const proxyList = rawProxy.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
    const speedMap = { medium: 1.0, fast: 0.4, veryfast: 0.15, ultra: 0.05 };
    const speedFactor = speedMap[speed] != null ? speedMap[speed] : 1.0;
    const selTeamId = (typeof selectedTeamId === 'string' && selectedTeamId.trim()) ? selectedTeamId.trim() : null;

    // Validate Bright Data config if provided
    const bd = (brightData && brightData.enabled && brightData.customerId && brightData.zoneName && brightData.zonePassword)
      ? { customerId: String(brightData.customerId).trim(), zoneName: String(brightData.zoneName).trim(), zonePassword: String(brightData.zonePassword), protocol: brightData.protocol === 'socks5h' ? 'socks5h' : 'http' }
      : null;

    // Reset session
    Object.assign(s, ts.makeSession());
    s.account = creds.email;
    s.rules = r;
    s.total = r.createBots ? n : 0;
    s.startedAt = Date.now();
    s.state = 'running';
    s.log = [];
    pushTsEvent('ts_progress');

    // Kick off in background but reply immediately
    const uid = currentUserId();
    ok(res, { snapshot: tsSnapshot() });

    const batchSize = Math.max(1, Math.min(5, parseInt(req.body?.batchSize) || 1));
    withUser(uid, () => runTsSession({ creds, rules: r, count: n, prefix: pfx, waitMinutes: wait, proxyList, speedFactor, selectedTeamId: selTeamId, brightData: bd, batchSize })
      .catch(e => {
        const ses = tsSession();
        ses.state = 'error';
        ses.lastError = e.message || String(e);
        tsLog('error', 'فشل الجلسة: ' + ses.lastError);
        pushTsEvent('ts_done');
      }));
  });

  // ── Bright Data URL builder ──────────────────────────────────────────────
  // Builds a correctly-formatted Bright Data proxy URL.
  // username = brd-customer-<CUSTOMER_ID>-zone-<ZONE_NAME>[-session-<SID>]
  // HTTP  → http://user:pass@brd.superproxy.io:33335
  // SOCKS5 → socks5h://user:pass@brd.superproxy.io:22228   (MUST use socks5h, not socks5)
  //
  // Per-bot IP rotation: pass a unique sessionId per bot → Bright Data pins that
  // session to ONE IP for its lifetime, so the bot creation sequence stays on a
  // single IP while the NEXT bot automatically gets a different one.
  // Without sessionId the proxy is "truly rotating" (new IP on every request).
  function buildBrightDataUrl(bd, sessionId) {
    const host  = 'brd.superproxy.io';
    const sid   = sessionId ? ('-session-' + String(sessionId).replace(/[^a-z0-9_-]/gi, '')) : '';
    const user  = encodeURIComponent(`brd-customer-${bd.customerId}-zone-${bd.zoneName}${sid}`);
    const pass  = encodeURIComponent(bd.zonePassword);
    if (bd.protocol === 'socks5h') {
      return `socks5h://${user}:${pass}@${host}:22228`;
    }
    return `http://${user}:${pass}@${host}:33335`;
  }

  async function runTsSession({ creds, rules, count, prefix, waitMinutes, proxyList = [], speedFactor = 1.0, selectedTeamId, brightData: bd = null, batchSize: requestedBatchSize = 1 }) {
    const s = tsSession();
    try {
      // Reuse the token + warmed client cached by Test/verify so cookies and
      // X-Fingerprint persist across the whole session — this is what a real
      // browser does and dramatically reduces Discord's automation suspicion.
      let token, userId = null, client;
      const cached = tsCachedToken(creds.email);
      if (cached?.token && cached?.client) {
        token = cached.token;
        client = cached.client;
        tsLog('info', 'استخدام جلسة دخول محفوظة لـ ' + creds.email + ' (الكوكيز محفوظة)');
      } else if (creds.directToken) {
        token = creds.directToken;
        // For Bright Data: use a fixed session so the warm-up stays on one IP.
        const loginProxy = bd ? buildBrightDataUrl(bd, 'login') : (proxyList[0] || null);
        client = ts.createClient(loginProxy);
        if (bd)         tsLog('info', 'الجلسة عبر Bright Data — ' + (bd.protocol === 'socks5h' ? 'SOCKS5h' : 'HTTP') + ' · Zone: ' + bd.zoneName);
        else if (loginProxy) tsLog('info', 'الجلسة تمر عبر Proxy: ' + loginProxy.replace(/:[^:@]+@/, ':***@'));
        tsLog('info', 'استخدام التوكن المباشر — جاري تسخين الجلسة…');
        try { await ts.warmUpClient(client); } catch (e) {
          tsLog('warn', 'تعذر تسخين الجلسة: ' + (e.message || e));
        }
        tsStoreToken(creds.email, token, client);
        tsLog('info', 'جاهز — التوكن المباشر مع جلسة دافئة ✓');
      } else {
        tsLog('info', 'جاري تسجيل الدخول إلى ' + creds.email + '…');
        const loginProxy = bd ? buildBrightDataUrl(bd, 'login') : (proxyList[0] || null);
        client = ts.createClient(loginProxy);
        if (bd)         tsLog('info', 'الجلسة عبر Bright Data — ' + (bd.protocol === 'socks5h' ? 'SOCKS5h' : 'HTTP') + ' · Zone: ' + bd.zoneName);
        else if (loginProxy) tsLog('info', 'الجلسة تمر عبر Proxy: ' + loginProxy.replace(/:[^:@]+@/, ':***@'));
        const loginNetOpts = { solveCaptcha: buildSolveCaptcha(), client, speedFactor };
        const r = await ts.login({ email: creds.email, password: creds.password, totpSecret: creds.totpSecret, netOpts: loginNetOpts });
        token = r.token;
        userId = r.userId;
        tsStoreToken(creds.email, token, client);
        tsLog('success', 'تم تسجيل الدخول بنجاح' + (userId ? ' (uid ' + userId + ')' : ''));
      }
      // Build netOpts ONCE per session, carrying the warmed client + speedFactor.
      const netOpts = { solveCaptcha: buildSolveCaptcha(), client, totpSecret: creds.totpSecret || undefined, password: creds.password || undefined, speedFactor };
      if (bd) tsLog('info', 'Bright Data IP rotation: كل بوت ← session ID عشوائي → IP مختلف تلقائياً ✓ (Zone: ' + bd.zoneName + ')');
      else if (proxyList.length > 1) tsLog('info', 'قائمة Proxy: ' + proxyList.length + ' عنوان — سيتغير IP تلقائياً مع كل بوت ✓');
      else if (proxyList.length === 1) tsLog('info', 'Proxy ثابت: ' + proxyList[0].replace(/:[^:@]+@/, ':***@'));

      // Behavioural warm-up — once per cached client.
      if (!client.devPortalLoaded) {
        try {
          tsLog('info', 'محاكاة تصفح طبيعي بعد الدخول…');
          await ts.simulateBrowsing({ token, netOpts });
          await ts.humanDelay(2500, 6000, speedFactor);
          tsLog('info', 'فتح Developer Portal…');
          await ts.loadDevPortal({ client, token, netOpts });
        } catch (e) {
          tsLog('warn', 'تعذر إكمال محاكاة التصفح: ' + (e.message || String(e)));
        }
      }

      // Acquire MFA token once per session (sensitive endpoints need it).
      let mfaToken = null;
      if (creds.totpSecret) {
        try {
          mfaToken = await ts.acquireMfa({ token, totpSecret: creds.totpSecret, netOpts });
          if (mfaToken) tsLog('info', 'تم الحصول على رمز MFA للعمليات الحساسة');
          else tsLog('warn', 'تخطي رمز MFA — العمليات الحساسة قد تفشل');
        } catch (e) {
          tsLog('warn', 'تعذر الحصول على رمز MFA: ' + (e.message || String(e)));
        }
      } else {
        tsLog('info', 'الحساب بدون 2FA — تخطي خطوة MFA');
      }

      // ─────────────────────────────────────────────────────────
      // 1) Team setup — create new team OR load existing teams
      // ─────────────────────────────────────────────────────────
      let teamId = null;
      let availableTeams = []; // [{id, name, appCount}] for rotation
      const teamAppCounts  = {}; // teamId → apps added in this session

      if (rules.createTeams) {
        if (s.cancelRequested) return finalizeTs();
        const teamName = prefix.length >= 2 ? prefix : (prefix + '-Team');
        await ts.navigateTo({ client, page: 'https://discord.com/developers/teams' });
        await ts.humanDelay(700, 1800, speedFactor);
        // Fetch existing teams so we can include them in rotation if the new one fills up
        let existingTeams = [];
        try { existingTeams = await ts.listTeams({ token, netOpts }); } catch (_) {}
        await ts.humanDelay(900, 2200, speedFactor);
        tsLog('info', 'إنشاء تيم جديد: ' + teamName);
        const team = await ts.createTeam({ token, name: teamName, netOpts });
        s.teamId = teamId = team.id;
        s.teamName = team.name;
        teamAppCounts[team.id] = 0;
        tsLog('success', 'تم إنشاء التيم #' + team.id);
        // Include existing teams in rotation (after the new one)
        availableTeams = [{ id: team.id, name: team.name, appCount: 0 }, ...existingTeams.filter(t => t.id !== team.id).map(t => ({ id: t.id, name: t.name, appCount: 0 }))];
        await ts.navigateTo({ client, page: `https://discord.com/developers/teams/${team.id}` });
        await ts.humanDelay(1200, 2800, speedFactor);
        pushTsEvent('ts_progress');
      } else if (rules.linkBots) {
        // Load available teams for rotation
        try {
          await ts.navigateTo({ client, page: 'https://discord.com/developers/teams' });
          await ts.humanDelay(600, 1400, speedFactor);
          const teams = await ts.listTeams({ token, netOpts });
          availableTeams = teams.map(t => ({ id: t.id, name: t.name, appCount: t.apps?.length || 0 }));
          if (availableTeams.length) {
            // Use selectedTeamId if provided and valid, otherwise pick first
            const preferred = selectedTeamId ? availableTeams.find(t => t.id === selectedTeamId) : null;
            const picked = preferred || availableTeams[0];
            s.teamId = teamId = picked.id;
            s.teamName = picked.name;
            tsLog('info', 'سيتم الربط مع تيم موجود: ' + picked.name + ' (' + (picked.appCount || 0) + '/25 تطبيق)');
          } else {
            tsLog('warn', 'لا يوجد تيم متاح للربط — سيتم إنشاء البوتات بدون تيم');
          }
        } catch (e) { tsLog('warn', 'تعذر جلب التيمات: ' + e.message); }
      }

      // ─────────────────────────────────────────────────────────
      // 2) Create bots (optional)
      // ─────────────────────────────────────────────────────────
      if (rules.createBots) {
        const d = ensureData();
        await ts.navigateTo({ client, page: 'https://discord.com/developers/applications' });
        await ts.humanDelay(700, 1500, speedFactor);
        try { await ts.listApplications({ token, netOpts }); } catch (_) {}
        await ts.humanDelay(800, 1800, speedFactor);

        // ── Parallel batch mode ─────────────────────────────────────────────
        // With IP rotation (Bright Data or proxy list > 1):
        //   Each bot creation runs on a DIFFERENT IP, so concurrent creation
        //   doesn't look like one human navigating — human delays are removed.
        //
        // Without IP rotation (or batchSize=1):
        //   Old sequential behaviour — one bot at a time with natural delays.
        //
        // Discord rate limit: 50 req/sec per token.
        // Worst case: 5 bots × 3 calls = 15 concurrent requests — well within limit.
        const hasIpRotation = !!(bd || proxyList.length > 1);
        const effectiveBatch = hasIpRotation ? Math.max(1, Math.min(5, requestedBatchSize)) : 1;
        const useParallelMode = effectiveBatch > 1;

        if (useParallelMode) {
          tsLog('info', 'وضع الدُّفعات المتوازية: ' + effectiveBatch + ' بوت في نفس الوقت — التأخيرات البشرية محذوفة');
        }

        // Creates ONE bot application + bot user + token.
        // Designed to be called concurrently; each invocation uses its own
        // proxy-cloned client so requests exit from a unique IP.
        const createOneBotAsync = async (botIndex, num, name, teamIdForBot) => {
          const _botStartedAt = Date.now();
          let botClient = client;
          let botNetOpts = netOpts;
          if (bd) {
            const sessionId = 'bot' + num + '_' + Math.random().toString(36).slice(2, 8);
            const bdProxy = buildBrightDataUrl(bd, sessionId);
            botClient = ts.cloneClientWithProxy(client, bdProxy);
            botNetOpts = { ...netOpts, client: botClient };
          } else if (proxyList.length > 1) {
            const botProxy = proxyList[botIndex % proxyList.length];
            botClient = ts.cloneClientWithProxy(client, botProxy);
            botNetOpts = { ...netOpts, client: botClient };
          }

          // In parallel mode every bot exits from a different IP — no need to
          // mimic a single human's pace between page navigations.
          const pause = (min, max) => useParallelMode
            ? Promise.resolve()
            : ts.humanDelay(min, max, speedFactor);

          const linkAtCreation = rules.linkBots && teamIdForBot;
          const appPayload = await ts.createApplication({
            token, name,
            teamId: linkAtCreation ? teamIdForBot : null,
            netOpts: botNetOpts,
          });

          // Update Referer chain on the bot's own client (no HTTP /track needed)
          botClient.currentPage = `https://discord.com/developers/applications/${appPayload.id}/information`;
          if (botClient === client) client.currentPage = botClient.currentPage;
          await pause(800, 1800);

          botClient.currentPage = `https://discord.com/developers/applications/${appPayload.id}/bot`;
          if (botClient === client) client.currentPage = botClient.currentPage;
          await pause(600, 1400);

          await ts.ensureBot({ token, appId: appPayload.id, netOpts: botNetOpts });
          await pause(800, 1800);

          const botToken = await ts.resetBotToken({ token, appId: appPayload.id, mfa: mfaToken, netOpts: botNetOpts });

          if (rules.linkBots && teamIdForBot && !linkAtCreation) {
            await pause(1200, 2400);
            try {
              await ts.transferAppToTeam({ token, appId: appPayload.id, teamId: teamIdForBot, mfa: mfaToken, netOpts: botNetOpts });
            } catch (e) { tsLog('warn', 'تعذر ربط ' + name + ' بالتيم: ' + e.message); }
          }

          const durationMs = Date.now() - _botStartedAt;
          return { appPayload, botToken, durationMs };
        };

        // ── Main batch loop ──────────────────────────────────────────────────
        let i = 0;
        while (i < count) {
          if (s.cancelRequested) break;

          // Team rotation — evaluated once per batch (sequential, before parallel work)
          if (rules.linkBots && teamId && (teamAppCounts[teamId] || 0) >= 25) {
            const nextTeam = availableTeams.find(t => t.id !== teamId && (teamAppCounts[t.id] || 0) < 25);
            if (nextTeam) {
              tsLog('info', 'التيم الحالي ممتلئ — التبديل إلى: ' + nextTeam.name);
              teamId = nextTeam.id;
              s.teamId = teamId;
              s.teamName = nextTeam.name;
              pushTsEvent('ts_progress');
            } else {
              tsLog('info', 'جميع التيمات ممتلئة — إنشاء تيم Studio جديد تلقائياً…');
              const studioName = ('Studio-' + String(Date.now()).slice(-6)).slice(0, 32);
              try {
                await ts.navigateTo({ client, page: 'https://discord.com/developers/teams' });
                await ts.humanDelay(600, 1400, speedFactor);
                const newTeam = await ts.createTeam({ token, name: studioName, netOpts });
                availableTeams.push({ id: newTeam.id, name: newTeam.name, appCount: 0 });
                teamAppCounts[newTeam.id] = 0;
                teamId = newTeam.id;
                s.teamId = teamId;
                s.teamName = newTeam.name;
                tsLog('success', 'تم إنشاء تيم Studio جديد: ' + newTeam.name + ' — جاري الاستمرار…');
                pushTsEvent('ts_progress');
              } catch (e) {
                tsLog('warn', 'تعذر إنشاء تيم Studio جديد: ' + (e.message || e) + ' — سيتم الإنشاء بدون تيم');
                teamId = null;
              }
            }
          }

          // Build batch slots — pre-allocate sequential numbers BEFORE any async work
          // so that concurrent bots never generate duplicate names.
          const batchEnd   = Math.min(i + effectiveBatch, count);
          const baseNum    = (d.tsLastNumber || 0);
          const batchSlots = [];
          for (let j = i; j < batchEnd; j++) {
            const num  = baseNum + (j - i) + 1;
            const name = (prefix + '-' + String(num).padStart(3, '0')).slice(0, 32);
            batchSlots.push({ botIndex: j, num, name });
          }

          // Commit the counter advance atomically (before launching parallel work)
          d.tsLastNumber = baseNum + batchSlots.length;

          const teamIdSnapshot = teamId; // freeze — rotation only happens between batches

          if (useParallelMode) {
            tsLog('info', 'دُفعة: ' + batchSlots.map(b => b.name).join(' · '));
          } else {
            tsLog('info', 'إنشاء البوت: ' + batchSlots[0].name);
          }

          s.current = batchSlots.length === 1
            ? batchSlots[0].name
            : batchSlots.map(b => b.name).join(' + ');
          pushTsEvent('ts_progress');

          // Launch all bots in this batch concurrently
          const results = await Promise.allSettled(
            batchSlots.map(slot => createOneBotAsync(slot.botIndex, slot.num, slot.name, teamIdSnapshot))
          );

          // Process results sequentially — JS is single-threaded here so no races
          let batchHad401 = false;
          for (let k = 0; k < results.length; k++) {
            const result = results[k];
            const slot   = batchSlots[k];

            if (result.status === 'fulfilled') {
              const { appPayload, botToken, durationMs } = result.value;
              s.bots.push({ name: slot.name, appId: appPayload.id, botUserId: appPayload.bot?.id || null, token: botToken });
              s.done += 1;
              if (rules.linkBots && teamId) teamAppCounts[teamId] = (teamAppCounts[teamId] || 0) + 1;
              const durSec = durationMs ? (durationMs / 1000).toFixed(1) : null;
              const durLabel = durSec ? ` ⚡ ${durSec}s` : '';
              tsLog('success', 'تم: ' + slot.name + ' · token=' + botToken.slice(0, 12) + '…' + durLabel, { durationMs, appId: appPayload.id, botName: slot.name });
              try {
                const tkList = await botTokensStore.get() || [];
                const tkFiltered = tkList.filter(t => t.appId !== appPayload.id);
                tkFiltered.unshift({
                  appId: appPayload.id, name: slot.name,
                  icon: appPayload.icon || null,
                  token: botToken,
                  email: creds.email || '',
                  resetAt: Date.now(),
                  createdAt: Date.now(),
                });
                await botTokensStore.set(tkFiltered);
              } catch (_) {}
              pushTsEvent('ts_bot_created', { bot: { name: slot.name, appId: appPayload.id, hasToken: true, durationMs } });
            } else {
              const err = result.reason;
              const msg = err?.message || String(err);
              s.failed += 1;
              tsLog('error', 'فشل ' + slot.name + ': ' + msg);
              if (err?.status === 401 || /Unauthorized/i.test(msg)) {
                tsClearToken(creds.email);
                tsLog('error', 'تم إلغاء التوكن من Discord — توقف الجلسة. الحساب قد يكون مُعلَّقاً.');
                batchHad401 = true;
              }
              if (err?.status === 429) {
                const ra = err?.retryAfter || err?.retry_after || 5;
                tsLog('warn', 'Rate limit (429) على ' + slot.name + ' — retry_after: ' + ra + 's — إعادة محاولة تلقائية…');
                // Auto-retry once after the rate-limit window
                await new Promise(r => setTimeout(r, Math.max(ra * 1000, 3000)));
                try {
                  const _retryStart = Date.now();
                  const { appPayload: rApp, botToken: rTok } = await createOneBotAsync(slot.botIndex, slot.num, slot.name, teamIdSnapshot);
                  const rDurMs = Date.now() - _retryStart;
                  s.bots.push({ name: slot.name, appId: rApp.id, botUserId: rApp.bot?.id || null, token: rTok });
                  s.done += 1; s.failed -= 1;
                  if (rules.linkBots && teamId) teamAppCounts[teamId] = (teamAppCounts[teamId] || 0) + 1;
                  tsLog('success', 'تم (retry): ' + slot.name, { durationMs: rDurMs, appId: rApp.id, botName: slot.name });
                  pushTsEvent('ts_bot_created', { bot: { name: slot.name, appId: rApp.id, hasToken: true, durationMs: rDurMs, isRetry: true } });
                } catch (re) {
                  tsLog('error', 'فشل retry ' + slot.name + ': ' + (re?.message || re));
                }
              }
              pushTsEvent('ts_progress');
            }
          }

          writeData(d);
          pushTsEvent('ts_progress');

          if (batchHad401) break;
          i = batchEnd;

          // Inter-batch cooldown
          // Parallel mode: shorter (API pacing only, no human-mimicking needed)
          // Sequential mode: standard per-bot cooldown
          if (i < count && !s.cancelRequested) {
            const ms = useParallelMode
              ? Math.max(Math.round(1000 * speedFactor), waitMinutes * 60 * 1000)
              : Math.max(Math.round(2500 * speedFactor), waitMinutes * 60 * 1000);
            if (ms >= 60000) tsLog('info', 'انتظار ' + waitMinutes + ' دقيقة قبل الدُّفعة التالية…');
            else if (useParallelMode && ms > 300) tsLog('info', 'كولداون: ' + (ms / 1000).toFixed(1) + 's قبل الدُّفعة التالية…');
            await tsSleep(ms);
          }
        }
      }

      finalizeTs();
    } catch (e) {
      s.lastError = e.message || String(e);
      tsLog('error', 'خطأ في الجلسة: ' + s.lastError);
      finalizeTs(true);
    }
  }

  function finalizeTs(errored = false) {
    const s = tsSession();
    s.finishedAt = Date.now();
    s.current = '';
    s.waitUntilTs = 0;
    s.waitTotalMs = 0;
    if (s.cancelRequested) s.state = 'cancelled';
    else if (errored) s.state = 'error';
    else s.state = 'done';
    tsLog('info', 'انتهت الجلسة — ' + s.done + ' نجاح · ' + s.failed + ' فشل');
    pushTsEvent('ts_done');
  }

  // Per-bot token export (download all bots from the most recent session)
  app.get('/api/ts/export', (req, res) => {
    const s = tsSession();
    const list = (s.bots || []).slice();
    const fmt = (req.query.format || 'text');
    if (fmt === 'json') return ok(res, { bots: list });
    const lines = list.map((b, i) => String(i + 1).padStart(3, '0') + '\t' + b.name + '\t' + (b.token || ''));
    res.set('Content-Type', 'text/plain; charset=utf-8');
    res.set('Content-Disposition', 'attachment; filename="true_studio_tokens.txt"');
    res.send('# number\tname\ttoken\n' + lines.join('\n') + '\n');
  });
  
const SSE_FEATURES_MAX = 200;
app.get('/api/features/stream', (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.flushHeaders?.();
  res.write(`: connected\n\n`);
  const types = (req.query.types || '').split(',').filter(Boolean);
  const sc = { res, types: types.length ? types : null };

  if (featureSSE.size >= SSE_FEATURES_MAX) {
    const oldest = featureSSE.values().next().value;
    if (oldest) {
      try { oldest.res.end(); } catch {}
      featureSSE.delete(oldest);
    }
  }
  featureSSE.add(sc);

  const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) {} }, 25000);
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    clearInterval(ping);
    featureSSE.delete(sc);
  };
  req.on('close', cleanup);
  req.on('error', cleanup);
  res.on('close', cleanup);
  res.on('error', cleanup);
});

function accountAvatarMap() {
  const m = {};
  for (const [n, e] of clients.entries()) {
    m[n] = {
      avatar: e.client.user?.displayAvatarURL?.({ size: 32 }) || null,
      username: e.client.user?.tag || n
    };
  }
  return m;
}

// ═══════════════════════════════════════════════
//  1. HISTORY LOG
// ═══════════════════════════════════════════════
function recordHistory(entry) {
  try {
    const d = readData();
    const arr = d.history || [];
    arr.unshift({
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      ts: Date.now(),
      ...entry
    });
    if (arr.length > 1000) arr.length = 1000;
    d.history = arr;
    writeData(d);
    sseBroadcast('history', { entry: arr[0] });
  } catch (e) {}
}

app.get('/api/history-log', (req, res) => {
  const d = readData();
  let h = d.history || [];
  const { account, type, status, q } = req.query;
  if (account) h = h.filter(x => x.account === account);
  if (type) h = h.filter(x => x.type === type);
  if (status) h = h.filter(x => x.status === status);
  if (q) {
    const ql = String(q).toLowerCase();
    h = h.filter(x => JSON.stringify(x).toLowerCase().includes(ql));
  }
  ok(res, { history: h.slice(0, 500), accounts: accountAvatarMap() });
});

app.delete('/api/history-log', (req, res) => {
  const d = readData(); d.history = []; writeData(d); ok(res);
});

// ═══════════════════════════════════════════════
//  2. TOKEN HEALTH CHECK
// ═══════════════════════════════════════════════
// Map Discord error codes / HTTP statuses to human reasons + preventive hints
function classifyTokenFailure(httpCode, discordCode, message) {
  const m = String(message || '').toLowerCase();
  if (httpCode === 401) return { status: 'invalid', reason: 'Token revoked or invalid', hint: 'Re-login on Discord and replace this token' };
  if (httpCode === 403) {
    if (m.includes('disabled')) return { status: 'disabled', reason: 'Account disabled by Discord', hint: 'Slow down all accounts and avoid spam-like patterns' };
    if (m.includes('age'))      return { status: 'age_locked', reason: 'Age verification required', hint: 'Confirm DOB on this account from Discord client' };
    if (m.includes('phone'))    return { status: 'phone_locked', reason: 'Phone verification required', hint: 'Verify a phone number on this account' };
    if (m.includes('captcha'))  return { status: 'captcha', reason: 'Captcha challenge triggered', hint: 'Pause activity for ~10 min, reduce concurrency' };
    return { status: 'banned', reason: 'Account banned/locked', hint: 'Stop using this token; review last 50 actions to find the trigger' };
  }
  if (httpCode === 429) return { status: 'rate_limited', reason: 'Cloudflare/Discord rate-limit', hint: 'Increase per-action delay (≥ 1500ms) and stagger accounts' };
  if (discordCode === 40002) return { status: 'unverified', reason: 'Account requires verification', hint: 'Verify email/phone before further actions' };
  if (discordCode === 50035) return { status: 'invalid_input', reason: 'Invalid form body', hint: 'Re-check payload (avatar/banner/bio length)' };
  return { status: 'error', reason: message || 'Unknown error', hint: 'Retry later; check connectivity' };
}

async function checkOneToken(name, token) {
  try {
    const r = await axios.get('https://discord.com/api/v9/users/@me', {
      headers: { Authorization: token }, timeout: 10000
    });
    return {
      name, ok: true, status: 'healthy',
      user: { id: r.data.id, username: r.data.username, displayName: r.data.global_name || r.data.username,
              avatar: r.data.avatar ? `https://cdn.discordapp.com/avatars/${r.data.id}/${r.data.avatar}.png?size=64` : defaultAvatarUrl(r.data.id) },
      checkedAt: Date.now()
    };
  } catch (e) {
    const httpCode = e.response?.status;
    const discordCode = e.response?.data?.code;
    const msg = e.response?.data?.message || e.message || String(e);
    const cls = classifyTokenFailure(httpCode, discordCode, msg);
    // Apply preventive broadcast so other accounts can react (slow down, pause, etc.)
    try {
      sseBroadcast('ban_alert', {
        name, status: cls.status, reason: cls.reason, hint: cls.hint,
        httpCode, discordCode, at: Date.now()
      });
      // Persist last incident for the audit log
      const d = readData();
      d.banAlerts = d.banAlerts || [];
      d.banAlerts.unshift({ name, status: cls.status, reason: cls.reason, hint: cls.hint, httpCode, discordCode, at: Date.now() });
      if (d.banAlerts.length > 200) d.banAlerts.length = 200;
      writeData(d);
    } catch (_) {}
    return { name, ok: false, status: cls.status, error: msg, reason: cls.reason, hint: cls.hint, httpCode, discordCode, checkedAt: Date.now() };
  }
}

async function runHealthCheck() {
  try {
    const tokens = readTokens();
    const d = readData();
    d.tokenHealth = d.tokenHealth || {};
    for (const t of tokens) {
      const r = await checkOneToken(t.name, t.token);
      d.tokenHealth[t.name] = r;
      sseBroadcast('token_health', { name: t.name, result: r });
      await sleep(jitter(400, 900));
    }
    writeData(d);
  } catch (e) {}
}

app.get('/api/token-health', (req, res) => {
  const d = readData();
  ok(res, { health: d.tokenHealth || {}, accounts: accountAvatarMap() });
});

app.post('/api/token-health/check', async (req, res) => {
  try {
    const { name } = req.body || {};
    if (name) {
      const t = readTokens().find(x => x.name === name);
      if (!t) return fail(res, new Error('Token not found'));
      const r = await checkOneToken(t.name, t.token);
      const d = readData();
      d.tokenHealth = d.tokenHealth || {};
      d.tokenHealth[t.name] = r;
      writeData(d);
      sseBroadcast('token_health', { name: t.name, result: r });
      return ok(res, { result: r });
    }
    runHealthCheck();
    ok(res, { running: true });
  } catch (e) { fail(res, e); }
});

// Self-rescheduling timer with ±15% jitter so all instances of the app
// don't hammer Discord at the same wall-clock minute (and to look less
// botty). Base = 30 min, range ≈ 25.5–34.5 min.
function _scheduleNextHealthCheck() {
  const base = 30 * 60 * 1000;
  const next = base + Math.floor((Math.random() * 0.3 - 0.15) * base);
  setTimeout(async () => {
    try { await runHealthCheck(); } catch (_) {}
    _scheduleNextHealthCheck();
  }, next);
}
_scheduleNextHealthCheck();
setTimeout(runHealthCheck, 8000); // initial after start

// ═══════════════════════════════════════════════
//  3. CLONE MANAGER
// ═══════════════════════════════════════════════
app.get('/api/clone/sources', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const guilds = Array.from(c.guilds.cache.values()).map(g => ({
      id: g.id, name: g.name,
      icon: g.iconURL?.({ size: 64 }) || null,
      members: g.memberCount || 0,
      owner: g.ownerId === c.user.id
    }));
    const dms = Array.from(c.channels.cache.values()).filter(ch => ch.type === 'DM').map(d => ({
      id: d.id, type: 'dm',
      name: d.recipient?.username || 'Unknown',
      icon: d.recipient?.displayAvatarURL?.({ size: 64 }) || defaultAvatarUrl(d.recipient?.id || '0')
    }));
    const groups = Array.from(c.channels.cache.values()).filter(ch => ch.type === 'GROUP_DM').map(g => ({
      id: g.id, type: 'group',
      name: g.name || Array.from(g.recipients?.values?.() || []).slice(0, 3).map(u => u.username).join(', '),
      icon: g.iconURL?.({ size: 64 }) || null,
      recipients: g.recipients?.size || 0
    }));
    ok(res, { guilds, dms, groups });
  } catch (e) { fail(res, e); }
});

app.get('/api/clone/snapshot/server/:guildId', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.token) return fail(res, new Error('Not connected'));
    const id = req.params.guildId;
    const guild = c.guilds.cache.get(id);
    if (!guild) return fail(res, new Error('Server not found in this account'));

    const includeMessages = req.query.messages === '1' || req.query.messages === 'true';
    // Bumped cap from 200 → 5000 so power users can capture a deeper history
    // when they really need it; default stays at 50 to keep snapshots quick.
    const perChannel = Math.min(Math.max(parseInt(req.query.perChannel, 10) || 50, 1), 5000);

    const [chRes, roleRes] = await Promise.all([
      axios.get(`https://discord.com/api/v9/guilds/${id}/channels`, { headers: { Authorization: c.token } }),
      axios.get(`https://discord.com/api/v9/guilds/${id}/roles`, { headers: { Authorization: c.token } }).catch(() => ({ data: [] }))
    ]);
    const channels = chRes.data.map(ch => ({
      id: ch.id, name: ch.name, type: ch.type, parent_id: ch.parent_id || null,
      position: ch.position, topic: ch.topic || '', nsfw: !!ch.nsfw,
      rate_limit_per_user: ch.rate_limit_per_user || 0, bitrate: ch.bitrate || 0, user_limit: ch.user_limit || 0,
      permission_overwrites: (ch.permission_overwrites || []).map(po => ({
        id: po.id, type: po.type, allow: String(po.allow || '0'), deny: String(po.deny || '0')
      }))
    })).sort((a, b) => a.position - b.position);
    const categories = channels.filter(c => c.type === 4);
    const textChans = channels.filter(c => c.type === 0 || c.type === 5);
    const voiceChans = channels.filter(c => c.type === 2);
    const roles = (roleRes.data || []).map(r => ({
      id: r.id, name: r.name, color: r.color, hoist: r.hoist, permissions: String(r.permissions || '0'),
      mentionable: r.mentionable, position: r.position,
      // Role icons (Boost-tier 2 feature). icon = custom uploaded image hash,
      // unicode_emoji = a fallback emoji. Both can be sent back when re-creating.
      icon: r.icon || null,
      unicode_emoji: r.unicode_emoji || null,
      iconUrl: r.icon ? `https://cdn.discordapp.com/role-icons/${r.id}/${r.icon}.png?size=64` : null
    })).sort((a, b) => b.position - a.position);
    const emojis = Array.from(guild.emojis?.cache?.values?.() || []).map(e => ({
      id: e.id, name: e.name, animated: e.animated, url: e.url
    }));

    const channelMessages = {};
    if (includeMessages) {
      // Capture in parallel batches of 4 channels at a time to keep things fast & polite to Discord.
      const BATCH = 4;
      for (let i = 0; i < textChans.length; i += BATCH) {
        const slice = textChans.slice(i, i + BATCH);
        const results = await Promise.all(slice.map(async (ch) => {
          try {
            const raw = await fetchChannelMessages(c, ch.id, perChannel);
            return [ch.id, raw.map(m => ({
              id: m.id, content: m.content || '',
              ts: new Date(m.timestamp).getTime(),
              author: {
                id: m.author.id, username: m.author.username,
                displayName: m.author.global_name || m.author.username,
                avatar: m.author.avatar
                  ? `https://cdn.discordapp.com/avatars/${m.author.id}/${m.author.avatar}.png?size=64`
                  : defaultAvatarUrl(m.author.id)
              },
              attachments: (m.attachments || []).map(a => ({
                url: a.url, name: a.filename, contentType: a.content_type || ''
              })),
              embeds: m.embeds || []
            }))];
          } catch (e) { return [ch.id, []]; }
        }));
        for (const [cid, msgs] of results) channelMessages[cid] = msgs;
      }
    }

    ok(res, {
      snapshot: {
        kind: 'server',
        capturedAt: Date.now(),
        server: {
          id: guild.id, name: guild.name,
          icon: guild.iconURL?.({ size: 256 }) || null,
          banner: guild.bannerURL?.({ size: 600 }) || null,
          description: guild.description || '',
          features: guild.features || [],
          memberCount: guild.memberCount || 0,
          verificationLevel: guild.verificationLevel || 0,
          afkTimeout: guild.afkTimeout || 0,
          systemChannelId: guild.systemChannelId || null
        },
        categories, textChannels: textChans, voiceChannels: voiceChans,
        roles, emojis,
        channelMessages,
        hasMessages: includeMessages
      }
    });
  } catch (e) { fail(res, e); }
});

async function fetchChannelMessages(client, channelId, max = 100) {
  const out = [];
  let before = null;
  while (out.length < max) {
    const url = `https://discord.com/api/v9/channels/${channelId}/messages?limit=${Math.min(100, max - out.length)}${before ? `&before=${before}` : ''}`;
    let batch;
    try {
      const r = await axios.get(url, { headers: { Authorization: client.token } });
      batch = r.data;
    } catch (e) { break; }
    if (!Array.isArray(batch) || !batch.length) break;
    for (const m of batch) out.push(m);
    before = batch[batch.length - 1].id;
    if (batch.length < 50) break;
    await sleep(150);
  }
  return out.reverse(); // oldest first
}

app.get('/api/clone/snapshot/dm/:channelId', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const max = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const ch = await c.channels.fetch(req.params.channelId);
    if (!ch || ch.type !== 'DM') return fail(res, new Error('Invalid DM channel'));
    const raw = await fetchChannelMessages(c, ch.id, max);
    const messages = raw.map(m => ({
      id: m.id, content: m.content || '',
      ts: new Date(m.timestamp).getTime(),
      author: { id: m.author.id, username: m.author.username,
                displayName: m.author.global_name || m.author.username,
                avatar: m.author.avatar ? `https://cdn.discordapp.com/avatars/${m.author.id}/${m.author.avatar}.png?size=64` : defaultAvatarUrl(m.author.id) },
      attachments: (m.attachments || []).map(a => ({ url: a.url, name: a.filename, contentType: a.content_type || '' })),
      embeds: m.embeds || []
    }));
    ok(res, {
      snapshot: {
        kind: 'dm', capturedAt: Date.now(),
        recipient: {
          id: ch.recipient?.id, username: ch.recipient?.username,
          displayName: ch.recipient?.globalName || ch.recipient?.username,
          avatar: ch.recipient?.displayAvatarURL?.({ size: 64 }) || defaultAvatarUrl(ch.recipient?.id || '0')
        },
        messages
      }
    });
  } catch (e) { fail(res, e); }
});

app.get('/api/clone/snapshot/group/:channelId', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const max = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const ch = await c.channels.fetch(req.params.channelId);
    if (!ch || ch.type !== 'GROUP_DM') return fail(res, new Error('Invalid group'));
    const raw = await fetchChannelMessages(c, ch.id, max);
    const messages = raw.map(m => ({
      id: m.id, content: m.content || '',
      ts: new Date(m.timestamp).getTime(),
      author: { id: m.author.id, username: m.author.username,
                displayName: m.author.global_name || m.author.username,
                avatar: m.author.avatar ? `https://cdn.discordapp.com/avatars/${m.author.id}/${m.author.avatar}.png?size=64` : defaultAvatarUrl(m.author.id) },
      attachments: (m.attachments || []).map(a => ({ url: a.url, name: a.filename, contentType: a.content_type || '' })),
      embeds: m.embeds || []
    }));
    ok(res, {
      snapshot: {
        kind: 'group', capturedAt: Date.now(),
        group: {
          id: ch.id,
          name: ch.name || Array.from(ch.recipients?.values?.() || []).slice(0, 3).map(u => u.username).join(', '),
          icon: ch.iconURL?.({ size: 64 }) || null,
          recipients: Array.from(ch.recipients?.values?.() || []).map(u => ({
            id: u.id, username: u.username,
            displayName: u.globalName || u.username,
            avatar: u.displayAvatarURL?.({ size: 32 }) || defaultAvatarUrl(u.id)
          }))
        },
        messages
      }
    });
  } catch (e) { fail(res, e); }
});

app.get('/api/clone/saved', (req, res) => {
  const d = readData();
  const list = (d.cloneSnapshots || []).map(s => ({
    id: s.id, kind: s.snapshot?.kind, name: s.name, savedAt: s.savedAt,
    summary: s.snapshot?.kind === 'server'
      ? { channels: (s.snapshot.textChannels?.length || 0) + (s.snapshot.voiceChannels?.length || 0), roles: s.snapshot.roles?.length || 0 }
      : { messages: s.snapshot?.messages?.length || 0 }
  }));
  ok(res, { snapshots: list });
});

app.post('/api/clone/saved', (req, res) => {
  try {
    const { snapshot, name } = req.body || {};
    if (!snapshot) return fail(res, new Error('snapshot required'));
    const d = readData();
    d.cloneSnapshots = d.cloneSnapshots || [];
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    d.cloneSnapshots.unshift({ id, name: name || (snapshot.kind + ' ' + new Date().toLocaleString()), savedAt: Date.now(), snapshot });
    if (d.cloneSnapshots.length > 100) d.cloneSnapshots.length = 100;
    writeData(d);
    ok(res, { id });
  } catch (e) { fail(res, e); }
});

app.get('/api/clone/saved/:id', (req, res) => {
  const d = readData();
  const s = (d.cloneSnapshots || []).find(x => x.id === req.params.id);
  if (!s) return fail(res, new Error('Not found'));
  ok(res, { snapshot: s.snapshot, name: s.name, savedAt: s.savedAt });
});

app.delete('/api/clone/saved/:id', (req, res) => {
  const d = readData();
  d.cloneSnapshots = (d.cloneSnapshots || []).filter(x => x.id !== req.params.id);
  writeData(d);
  ok(res);
});

// ── Clone Presets — reusable paste configurations
app.get('/api/clone/presets', (req, res) => {
  const d = readData();
  ok(res, { presets: (d.clonePresets || []).map(p => ({
    id: p.id, name: p.name, savedAt: p.savedAt,
    accounts: (p.accounts || []).length,
    channels: (p.selectedChannels || []).length,
    options: p.options || {}
  })) });
});

app.get('/api/clone/presets/:id', (req, res) => {
  const d = readData();
  const p = (d.clonePresets || []).find(x => x.id === req.params.id);
  if (!p) return fail(res, new Error('Preset not found'));
  ok(res, { preset: p });
});

app.post('/api/clone/presets', (req, res) => {
  try {
    const { name, options = {}, selectedChannels = [], accounts = [], targetGuildId = null } = req.body || {};
    if (!name || !String(name).trim()) return fail(res, new Error('Name required'));
    const d = readData();
    d.clonePresets = d.clonePresets || [];
    // Replace existing with same name (case-insensitive) instead of duplicating
    const idx = d.clonePresets.findIndex(p => p.name.toLowerCase() === name.toLowerCase());
    const id = idx >= 0 ? d.clonePresets[idx].id
                        : (Date.now().toString(36) + Math.random().toString(36).slice(2, 6));
    const preset = {
      id, name: String(name).trim(), savedAt: Date.now(),
      options, selectedChannels, accounts, targetGuildId
    };
    if (idx >= 0) d.clonePresets[idx] = preset;
    else d.clonePresets.unshift(preset);
    if (d.clonePresets.length > 50) d.clonePresets.length = 50;
    writeData(d);
    ok(res, { id, preset });
  } catch (e) { fail(res, e); }
});

app.delete('/api/clone/presets/:id', (req, res) => {
  const d = readData();
  d.clonePresets = (d.clonePresets || []).filter(x => x.id !== req.params.id);
  writeData(d);
  ok(res);
});

// ── Ban / health alerts log
app.get('/api/ban-alerts', (req, res) => {
  const d = readData();
  ok(res, { alerts: (d.banAlerts || []).slice(0, 100) });
});

app.delete('/api/ban-alerts', (req, res) => {
  const d = readData();
  d.banAlerts = [];
  writeData(d);
  ok(res);
});

// Webhook paste — fast (no token rate-limit, only webhook 5/sec)
async function postWebhook(url, payload, attempts = 4) {
  for (let i = 0; i < attempts; i++) {
    try {
      const r = await axios.post(url, payload, { headers: { 'Content-Type': 'application/json' }, timeout: 15000 });
      return { ok: true, data: r.data };
    } catch (e) {
      const code = e.response?.status;
      if (code === 429) {
        const retry = parseFloat(e.response.headers['retry-after'] || e.response.data?.retry_after || 1);
        await sleep(retry * 1000);
        continue;
      }
      if (code >= 400 && code < 500) return { ok: false, error: e.response?.data?.message || e.message };
      await sleep(500 * (i + 1));
    }
  }
  return { ok: false, error: 'Failed after retries' };
}

app.post('/api/clone/paste/webhook', async (req, res) => {
  try {
    const { webhookUrl, messages = [], includeAuthor = true, gapMs = 250 } = req.body || {};
    if (!webhookUrl || !messages.length) return fail(res, new Error('webhookUrl and messages required'));
    const out = [];
    for (const m of messages) {
      const att = (m.attachments || []).map(a => a.url).join('\n');
      let content = m.content || '';
      if (att) content = (content ? content + '\n' : '') + att;
      if (!content && !(m.embeds || []).length) continue;
      const payload = {
        content: content.slice(0, 1900) || ' ',
        username: includeAuthor ? (m.author?.displayName || m.author?.username || 'Anon') : undefined,
        avatar_url: includeAuthor ? (m.author?.avatar || undefined) : undefined,
        allowed_mentions: { parse: [] }
      };
      const r = await postWebhook(webhookUrl, payload);
      out.push({ id: m.id, ok: r.ok, error: r.error || null });
      await sleep(gapMs);
    }
    recordHistory({
      account: 'webhook', type: 'clone_paste',
      target: { kind: 'webhook' }, messages: messages.length,
      status: out.every(x => x.ok) ? 'success' : (out.some(x => x.ok) ? 'partial' : 'failed'),
      ok: out.filter(x => x.ok).length, fail: out.filter(x => !x.ok).length
    });
    ok(res, { results: out });
  } catch (e) { fail(res, e); }
});

// New comprehensive paste — supports multi-account, selective options, channel-perm overwrites, messages.
app.post('/api/clone/paste/server-build', async (req, res) => {
  try {
    const { accounts: rawAccounts, account, snapshot, targetGuildId, options = {} } = req.body || {};
    if (!snapshot || snapshot.kind !== 'server') return fail(res, new Error('Server snapshot required'));
    if (!targetGuildId) return fail(res, new Error('targetGuildId required'));

    const accountList = Array.isArray(rawAccounts) && rawAccounts.length
      ? rawAccounts
      : [account || activeRef.get()].filter(Boolean);
    if (!accountList.length) return fail(res, new Error('No accounts specified'));

    // The "structure builder" must own (or have admin on) the target server.
    let builderName = null, builder = null, builderGuild = null;
    for (const n of accountList) {
      const cc = getClientByName(n);
      if (!cc?.token) continue;
      const g = cc.guilds.cache.get(targetGuildId);
      if (g && (g.ownerId === cc.user.id || g.members.me?.permissions?.has?.('ADMINISTRATOR'))) {
        builderName = n; builder = cc; builderGuild = g;
        break;
      }
    }
    if (!builder) {
      // Fallback: use first connected account that has the guild visible.
      for (const n of accountList) {
        const cc = getClientByName(n);
        const g = cc?.guilds?.cache?.get?.(targetGuildId);
        if (cc?.token && g) { builderName = n; builder = cc; builderGuild = g; break; }
      }
    }
    if (!builder) return fail(res, new Error('None of the chosen accounts can see the target server'));

    const opts = {
      categories:    !!options.categories,
      textChannels:  !!options.textChannels,
      voiceChannels: !!options.voiceChannels,
      roles:         !!options.roles,
      rolePerms:     !!options.rolePerms,
      roleIcons:     !!options.roleIcons,         // NEW: copy role unicode/icon emoji
      channelPerms:  !!options.channelPerms,
      emojis:        !!options.emojis,
      messages:      !!options.messages,
      messageChannelIds: Array.isArray(options.messageChannelIds) ? options.messageChannelIds : null, // null = all
      // Per-channel cap, configurable. Was hard-coded ~200 elsewhere; we let the
      // user dial it up to 5000 if they really need a deep clone.
      messagesPerChannel: Math.min(Math.max(parseInt(options.messagesPerChannel, 10) || 200, 1), 5000),
      messageGapMs: Math.max(parseInt(options.messageGapMs, 10) || 220, 80),
    };

    const created = {
      categories: 0, textChannels: 0, voiceChannels: 0,
      roles: 0, channelPerms: 0, emojis: 0, messagesPosted: 0, errors: []
    };
    const catMap = new Map();      // snapshot cat id -> new cat id
    const newChMap = new Map();    // snapshot text channel id -> new channel id
    const roleMap = new Map();     // snapshot role id -> new role id
    roleMap.set('@everyone', builderGuild.roles.everyone?.id);

    // ── Roles
    if (opts.roles) {
      // Pre-fetch role icons (PNG bytes -> base64 data URI) when the user opted
      // in. Discord ignores `icon` if the target guild's tier is too low so
      // failures here are non-fatal — we just fall back to a unicode emoji.
      const _roleIconCache = new Map();
      if (opts.roleIcons) {
        for (const r of snapshot.roles || []) {
          if (!r.iconUrl) continue;
          try {
            const ir = await axios.get(r.iconUrl, { responseType: 'arraybuffer', validateStatus: () => true });
            if (ir.status === 200 && ir.data) {
              const b64 = Buffer.from(ir.data).toString('base64');
              _roleIconCache.set(r.id, `data:image/png;base64,${b64}`);
            }
          } catch (_) {}
          await sleep(jitter(120, 220));
        }
      }
      for (const r of (snapshot.roles || []).slice().reverse()) {
        if (r.name === '@everyone') continue;
        try {
          const body = {
            name: r.name, color: r.color, hoist: r.hoist,
            permissions: opts.rolePerms ? r.permissions : '0',
            mentionable: r.mentionable
          };
          if (opts.roleIcons) {
            const ic = _roleIconCache.get(r.id);
            if (ic) body.icon = ic;
            else if (r.unicode_emoji) body.unicode_emoji = r.unicode_emoji;
          }
          const rr = await axios.post(
            `https://discord.com/api/v9/guilds/${targetGuildId}/roles`,
            body,
            { headers: { Authorization: builder.token, 'Content-Type': 'application/json' } }
          );
          roleMap.set(r.id, rr.data.id);
          created.roles++;
          await sleep(jitter(350, 600));
        } catch (e) {
          created.errors.push(`role ${r.name}: ${e.response?.data?.message || e.message}`);
        }
      }
    }

    function buildOverwrites(channelOverwrites) {
      if (!opts.channelPerms || !Array.isArray(channelOverwrites)) return undefined;
      const out = [];
      for (const po of channelOverwrites) {
        // type 0 = role, type 1 = member. Skip member overwrites — those users don't exist on target.
        if (po.type !== 0) continue;
        // For @everyone, the snapshot's @everyone id is the source guild id; map separately.
        const isEveryone = po.id === snapshot.server?.id;
        const newId = isEveryone ? roleMap.get('@everyone') : roleMap.get(po.id);
        if (!newId) continue;
        out.push({ id: newId, type: 0, allow: po.allow, deny: po.deny });
      }
      return out.length ? out : undefined;
    }

    // ── Categories
    if (opts.categories) {
      for (const cat of snapshot.categories || []) {
        try {
          const r = await axios.post(
            `https://discord.com/api/v9/guilds/${targetGuildId}/channels`,
            { name: cat.name, type: 4, permission_overwrites: buildOverwrites(cat.permission_overwrites) },
            { headers: { Authorization: builder.token, 'Content-Type': 'application/json' } }
          );
          catMap.set(cat.id, r.data.id);
          created.categories++;
          if (opts.channelPerms && cat.permission_overwrites?.length) created.channelPerms++;
          await sleep(jitter(250, 500));
        } catch (e) {
          created.errors.push(`category ${cat.name}: ${e.response?.data?.message || e.message}`);
        }
      }
    }

    // ── Text channels
    if (opts.textChannels) {
      for (const ch of snapshot.textChannels || []) {
        try {
          const r = await axios.post(
            `https://discord.com/api/v9/guilds/${targetGuildId}/channels`,
            {
              name: ch.name, type: 0,
              parent_id: catMap.get(ch.parent_id) || null,
              topic: ch.topic, nsfw: ch.nsfw,
              rate_limit_per_user: ch.rate_limit_per_user,
              permission_overwrites: buildOverwrites(ch.permission_overwrites)
            },
            { headers: { Authorization: builder.token, 'Content-Type': 'application/json' } }
          );
          newChMap.set(ch.id, r.data.id);
          created.textChannels++;
          if (opts.channelPerms && ch.permission_overwrites?.length) created.channelPerms++;
          await sleep(jitter(250, 500));
        } catch (e) {
          created.errors.push(`text ${ch.name}: ${e.response?.data?.message || e.message}`);
        }
      }
    }

    // ── Voice channels
    if (opts.voiceChannels) {
      for (const ch of snapshot.voiceChannels || []) {
        try {
          await axios.post(
            `https://discord.com/api/v9/guilds/${targetGuildId}/channels`,
            {
              name: ch.name, type: 2,
              parent_id: catMap.get(ch.parent_id) || null,
              bitrate: ch.bitrate, user_limit: ch.user_limit,
              permission_overwrites: buildOverwrites(ch.permission_overwrites)
            },
            { headers: { Authorization: builder.token, 'Content-Type': 'application/json' } }
          );
          created.voiceChannels++;
          if (opts.channelPerms && ch.permission_overwrites?.length) created.channelPerms++;
          await sleep(jitter(250, 500));
        } catch (e) {
          created.errors.push(`voice ${ch.name}: ${e.response?.data?.message || e.message}`);
        }
      }
    }

    // ── Custom emojis (download + upload)
    if (opts.emojis && Array.isArray(snapshot.emojis)) {
      for (const em of snapshot.emojis) {
        try {
          const img = await axios.get(em.url, { responseType: 'arraybuffer', timeout: 15000 });
          const ct = img.headers['content-type'] || (em.animated ? 'image/gif' : 'image/png');
          const b64 = `data:${ct};base64,${Buffer.from(img.data).toString('base64')}`;
          await axios.post(
            `https://discord.com/api/v9/guilds/${targetGuildId}/emojis`,
            { name: em.name.replace(/[^\w]/g, '').slice(0, 32) || 'emoji', image: b64 },
            { headers: { Authorization: builder.token, 'Content-Type': 'application/json' } }
          );
          created.emojis++;
          await sleep(jitter(450, 800));
        } catch (e) {
          created.errors.push(`emoji ${em.name}: ${e.response?.data?.message || e.message}`);
        }
      }
    }

    // ── Messages: post via webhooks for speed and to preserve author display.
    // Multi-account speedup: round-robin webhook posters across accounts (each gets its own webhook).
    if (opts.messages && snapshot.channelMessages && (opts.textChannels || newChMap.size)) {
      // Pick channels to restore. If textChannels weren't created in this run, we can still
      // post into existing channels with the same name in the target.
      const wantedChannelIds = opts.messageChannelIds || Object.keys(snapshot.channelMessages);

      // Resolve target channel id for each source channel id
      const targetByCh = new Map();
      for (const sourceCh of (snapshot.textChannels || [])) {
        if (!wantedChannelIds.includes(sourceCh.id)) continue;
        let newId = newChMap.get(sourceCh.id);
        if (!newId) {
          const found = builderGuild.channels.cache.find(
            ch => ch.type === 'GUILD_TEXT' && ch.name === sourceCh.name
          );
          if (found) newId = found.id;
        }
        if (newId) targetByCh.set(sourceCh.id, newId);
      }

      // Connected accounts that can hit the target guild — used as webhook posters.
      const posters = accountList
        .map(n => ({ name: n, client: getClientByName(n) }))
        .filter(p => p.client?.token);

      // For each target channel: create one webhook per poster, post messages round-robin, then delete.
      for (const [srcId, tgtId] of targetByCh.entries()) {
        const messages = snapshot.channelMessages[srcId] || [];
        if (!messages.length) continue;

        const channelWebhooks = [];
        for (const p of posters) {
          try {
            const wh = await axios.post(
              `https://discord.com/api/v9/channels/${tgtId}/webhooks`,
              { name: `clone-${p.name}`.slice(0, 80) },
              { headers: { Authorization: p.client.token, 'Content-Type': 'application/json' } }
            );
            channelWebhooks.push({
              poster: p.name,
              url: `https://discord.com/api/webhooks/${wh.data.id}/${wh.data.token}`,
              id: wh.data.id,
              token: p.client.token
            });
          } catch (e) {
            created.errors.push(`webhook ${tgtId} via ${p.name}: ${e.response?.data?.message || e.message}`);
          }
        }
        if (!channelWebhooks.length) continue;

        // Post messages round-robin across webhooks for parallel throughput.
        let idx = 0;
        const concurrency = Math.min(channelWebhooks.length, 3);
        const queue = messages.slice();
        const workers = Array.from({ length: concurrency }, async () => {
          while (queue.length) {
            const m = queue.shift();
            const wh = channelWebhooks[idx++ % channelWebhooks.length];
            const att = (m.attachments || []).map(a => a.url).join('\n');
            let content = m.content || '';
            if (att) content = (content ? content + '\n' : '') + att;
            if (!content) continue;
            const payload = {
              content: content.slice(0, 1900),
              username: (m.author?.displayName || m.author?.username || 'User').slice(0, 80),
              avatar_url: m.author?.avatar || undefined,
              allowed_mentions: { parse: [] }
            };
            const r = await postWebhook(wh.url, payload);
            if (r.ok) created.messagesPosted++;
            else created.errors.push(`msg via ${wh.poster}: ${r.error}`);
            await sleep(opts.messageGapMs);
          }
        });
        await Promise.all(workers);

        // Cleanup webhooks
        for (const wh of channelWebhooks) {
          try {
            await axios.delete(
              `https://discord.com/api/v9/webhooks/${wh.id}`,
              { headers: { Authorization: wh.token } }
            );
          } catch (e) {}
        }
      }
    }

    const status = created.errors.length === 0 ? 'success'
      : (created.categories + created.textChannels + created.voiceChannels + created.roles + created.messagesPosted > 0 ? 'partial' : 'failed');

    recordHistory({
      account: builderName, type: 'clone_build_server',
      target: { id: targetGuildId, accounts: accountList },
      status,
      ok: created.categories + created.textChannels + created.voiceChannels + created.roles + created.emojis + created.channelPerms,
      fail: created.errors.length
    });

    if (created.messagesPosted > 0) {
      recordHistory({
        account: accountList.join('+'),
        type: 'clone_messages',
        target: { id: targetGuildId, channels: Object.keys(snapshot.channelMessages || {}).length },
        status,
        ok: created.messagesPosted,
        fail: created.errors.filter(e => e.startsWith('msg ')).length
      });
    }

    ok(res, { created, builder: builderName, accounts: accountList });
  } catch (e) { fail(res, e); }
});

// ═══════════════════════════════════════════════
//  4. MENTIONS TRACKER
// ═══════════════════════════════════════════════
// Backed by app_data.json so mentions survive restarts (was in-memory only).
const mentionsStore = new Map(); // account -> [{...}]
let _mentionsDirty = false;
function _loadMentionsFromDisk() {
  try {
    const d = readData();
    const m = d.mentions || {};
    for (const [name, list] of Object.entries(m)) {
      if (Array.isArray(list)) mentionsStore.set(name, list);
    }
  } catch (_) {}
}
function _saveMentionsToDisk() {
  try {
    const d = readData();
    const out = {};
    for (const [name, list] of mentionsStore.entries()) out[name] = list.slice(0, 200);
    d.mentions = out;
    writeData(d);
    _mentionsDirty = false;
  } catch (_) {}
}
// Coalesce writes — listeners may fire dozens of times per second
setInterval(() => { if (_mentionsDirty) _saveMentionsToDisk(); }, 4000);
_loadMentionsFromDisk();

function addMention(account, msg) {
  const arr = mentionsStore.get(account) || [];
  const guild = msg.guild;
  arr.unshift({
    id: msg.id,
    account,
    channelId: msg.channel.id,
    channelName: msg.channel.name || (msg.channel.type === 'DM' ? 'DM' : 'channel'),
    channelType: msg.channel.type,
    guildId: guild?.id || null,
    guildName: guild?.name || null,
    guildIcon: guild?.iconURL?.({ size: 32 }) || null,
    content: msg.content || '',
    ts: msg.createdTimestamp,
    deleted: false,
    author: {
      id: msg.author.id, username: msg.author.username,
      displayName: msg.author.globalName || msg.author.username,
      avatar: msg.author.displayAvatarURL?.({ size: 64 }) || defaultAvatarUrl(msg.author.id),
      bot: !!msg.author.bot
    },
    attachments: Array.from(msg.attachments?.values?.() || []).map(a => ({ url: a.url, name: a.name }))
  });
  if (arr.length > 200) arr.length = 200;
  mentionsStore.set(account, arr);
  _mentionsDirty = true;
  sseBroadcast('mention', { account, mention: arr[0] });
}
function markMentionDeleted(account, msgId) {
  const arr = mentionsStore.get(account);
  if (!arr) return;
  const it = arr.find(x => x.id === msgId);
  if (it) { it.deleted = true; _mentionsDirty = true; sseBroadcast('mention_deleted', { account, id: msgId }); }
}

function attachMentionListener(name, client, ownerUid) {
  ownerUid = ownerUid || currentUserId();
  if (client.__mentionListenerBound) return;
  client.__mentionListenerBound = true;
  client.on('messageCreate', (msg) => withUser(ownerUid, () => {
    try {
      if (msg.author?.id === client.user.id) return;
      const mentioned = msg.mentions?.users?.has?.(client.user.id) ||
                        (msg.content || '').includes(`<@${client.user.id}>`) ||
                        (msg.content || '').includes(`<@!${client.user.id}>`);
      if (!mentioned) return;
      addMention(name, msg);
    } catch (e) {}
  }));
  client.on('messageDelete', (msg) => withUser(ownerUid, () => {
    try { markMentionDeleted(name, msg.id); } catch (e) {}
  }));
}
// Listeners are bound during connectOne(); no need to re-iterate here.

app.get('/api/mentions', (req, res) => {
  const account = (req.query.account || activeRef.get() || '').trim();
  const all = req.query.all === '1' || req.query.all === 'true';
  let list = [];
  if (all) {
    for (const [n, arr] of mentionsStore.entries()) list.push(...arr);
    list.sort((a, b) => b.ts - a.ts);
    list = list.slice(0, 200);
  } else {
    list = mentionsStore.get(account) || [];
  }
  ok(res, { mentions: list, accounts: accountAvatarMap() });
});

app.delete('/api/mentions', (req, res) => {
  const { account } = req.body || {};
  if (account) mentionsStore.delete(account);
  else mentionsStore.clear();
  _mentionsDirty = true;
  _saveMentionsToDisk();
  ok(res);
});

// ═══════════════════════════════════════════════
//  5. PIC CAPTURE
// ═══════════════════════════════════════════════
function isImageAttachment(a) {
  if (!a) return false;
  const ct = (a.contentType || a.content_type || '').toLowerCase();
  if (ct.startsWith('image/')) return true;
  return /\.(png|jpe?g|gif|webp|bmp)(\?|$)/i.test(a.url || '');
}
function classifyAttachment(a) {
  const ct = (a?.contentType || a?.content_type || '').toLowerCase();
  const url = a?.url || '';
  if (ct.startsWith('image/') || /\.(png|jpe?g|gif|webp|bmp)(\?|$)/i.test(url)) return 'image';
  if (ct.startsWith('video/') || /\.(mp4|mov|mkv|webm)(\?|$)/i.test(url)) return 'video';
  if (ct.startsWith('audio/') || /\.(mp3|wav|ogg|m4a|flac)(\?|$)/i.test(url)) return 'audio';
  return 'file';
}

async function handlePicMessage(name, msg) {
  try {
    const d = readData();
    const cfg = d.picConfig || {};
    if (!cfg.enabled) return;
    if (cfg.accounts?.length && !cfg.accounts.includes(name)) return;
    const guildId = msg.guild?.id;
    if (cfg.scope === 'servers' && (!guildId || !cfg.servers?.includes(guildId))) return;
    if (cfg.scope === 'all' && !guildId) return; // only servers (per request)

    const media = Array.from(msg.attachments?.values?.() || []).map(a => ({
      url: a.url, name: a.name || a.filename || 'file',
      width: a.width, height: a.height,
      contentType: a.contentType || a.content_type || '',
      size: a.size || 0,
      kind: classifyAttachment(a)
    }));
    if (!media.length) return;

    const meta = {
      id: msg.id,
      account: name,
      ts: msg.createdTimestamp,
      author: {
        id: msg.author.id, username: msg.author.username,
        displayName: msg.author.globalName || msg.author.username,
        avatar: msg.author.displayAvatarURL?.({ size: 64 }) || defaultAvatarUrl(msg.author.id),
        bot: !!msg.author.bot
      },
      guild: msg.guild ? { id: msg.guild.id, name: msg.guild.name, icon: msg.guild.iconURL?.({ size: 32 }) || null } : null,
      channel: { id: msg.channel.id, name: msg.channel.name || 'channel' },
      content: msg.content || '',
      media
    };

    if (cfg.inApp !== false) {
      const buf = d.picBuffer || [];
      // Dedupe: skip if we already saved this message ID (multiple connected
      // accounts can both see the same message → previously double-counted)
      if (buf.some(x => x.id === meta.id)) {
        // already captured by this account — still mirror to webhook below if configured
      } else {
        buf.unshift(meta);
        if (buf.length > 500) buf.length = 500; // raised cap, was 200
        d.picBuffer = buf;
        writeData(d);
        sseBroadcast('pic', { capture: meta });
      }
    }
    if (cfg.webhook) {
      const lines = media.map(i => `${i.kind.toUpperCase()}: ${i.url}`).join('\n');
      const where = msg.guild ? `${msg.guild.name} · #${msg.channel.name}` : `#${msg.channel.name}`;
      const content = `**${meta.author.displayName}** · ${where}\n${meta.content ? meta.content + '\n' : ''}${lines}`;
      await postWebhook(cfg.webhook, {
        content: content.slice(0, 1900),
        username: meta.author.displayName,
        avatar_url: meta.author.avatar,
        allowed_mentions: { parse: [] }
      });
    }
  } catch (e) {}
}

function attachPicListener(name, client, ownerUid) {
  ownerUid = ownerUid || currentUserId();
  if (client.__picListenerBound) return;
  client.__picListenerBound = true;
  client.on('messageCreate', (msg) => withUser(ownerUid, () => handlePicMessage(name, msg)));
}
// Listeners are bound during connectOne(); no need to re-iterate here.

app.get('/api/pic/config', (req, res) => {
  const d = readData();
  ok(res, { config: d.picConfig || {} });
});

app.post('/api/pic/config', (req, res) => {
  try {
    const d = readData();
    const patch = req.body || {};
    if (typeof patch.enabled !== 'undefined' && typeof patch.enabled !== 'boolean') return fail(res, new Error('enabled must be boolean'));
    if (typeof patch.inApp !== 'undefined' && typeof patch.inApp !== 'boolean') return fail(res, new Error('inApp must be boolean'));
    if (typeof patch.scope !== 'undefined' && !['all', 'servers'].includes(patch.scope)) return fail(res, new Error('scope must be all or servers'));
    d.picConfig = { ...(d.picConfig || {}), ...patch };
    d.picConfig.accounts = Array.from(new Set((d.picConfig.accounts || []).map(String))).slice(0, 100);
    d.picConfig.servers = Array.from(new Set((d.picConfig.servers || []).map(String))).slice(0, 500);
    writeData(d);
    ok(res, { config: d.picConfig });
  } catch (e) { fail(res, e); }
});

app.get('/api/pic/buffer', (req, res) => {
  const d = readData();
  ok(res, { buffer: (d.picBuffer || []).slice(0, 100), accounts: accountAvatarMap() });
});

app.delete('/api/pic/buffer', (req, res) => {
  const d = readData(); d.picBuffer = []; writeData(d); ok(res);
});

app.get('/api/pic/media-proxy', async (req, res) => {
  try {
    const rawUrl = String(req.query.u || '');
    const account = String(req.query.account || '');
    if (!rawUrl) return fail(res, new Error('u is required'));
    let parsed;
    try { parsed = new URL(rawUrl); } catch { return fail(res, new Error('Invalid media URL')); }
    if (!/discord(app)?\.com$|discordapp\.net$|discordcdn\.com$|cdn\.discordapp\.com$/i.test(parsed.hostname)) {
      return fail(res, new Error('Only Discord media URLs are allowed'));
    }
    const c = getClientByName(account) || pickClient(req);
    if (!c?.token) return fail(res, new Error('No connected account available for media proxy'));
    const r = await axios.get(rawUrl, {
      responseType: 'stream',
      headers: discordHeaders(c.token),
      timeout: 20000,
      validateStatus: () => true
    });
    if (r.status >= 400) return fail(res, new Error(`Media fetch failed (${r.status})`));
    res.setHeader('Content-Type', r.headers['content-type'] || 'application/octet-stream');
    res.setHeader('Cache-Control', 'private, max-age=60');
    r.data.pipe(res);
  } catch (e) { fail(res, e); }
});

// ═══════════════════════════════════════════════
//  6. ANTI PRUNE
// ═══════════════════════════════════════════════
async function tryDmUser(client, userId, content) {
  try {
    const user = await client.users.fetch(userId);
    const dm = await user.createDM();
    await dm.send({ content, allowed_mentions: { parse: [] } });
    return { ok: true };
  } catch (e) { return { ok: false, error: e.message }; }
}

// Track guilds we've already warned the UI about to avoid spamming SSE
const _antiPruneNoAuditGuilds = new Set();
const _ANTIPRUNE_WARN_MAX = 500;
async function isPrunedRecently(client, guildId) {
  // Check audit log for MEMBER_PRUNE (28) within last 10s
  try {
    const r = await axios.get(`https://discord.com/api/v9/guilds/${guildId}/audit-logs?action_type=28&limit=1`, {
      headers: { Authorization: client.token }
    });
    const entry = r.data.audit_log_entries?.[0];
    if (!entry) return false;
    const t = snowflakeToMs(entry.id);
    return (Date.now() - t) < 12000;
  } catch (e) {
    // 403 = "Missing Permissions" → AntiPrune cannot detect prunes for this
    // server. Surface ONCE to the UI so the user knows why nothing fires.
    const status = e?.response?.status;
    if ((status === 403 || status === 401) && !_antiPruneNoAuditGuilds.has(guildId)) {
      addBounded(_antiPruneNoAuditGuilds, guildId, _ANTIPRUNE_WARN_MAX);
      try {
        const guildName = client.guilds.cache.get(guildId)?.name || guildId;
        sseBroadcast('antiprune_warning', {
          guildId, guildName,
          message: `AntiPrune cannot read audit logs for "${guildName}" — needs the View Audit Log permission. Pruned-member alerts will be skipped for this server.`
        });
        // Persist to the antiPrune log so the user can see it later
        try {
          const d = readData();
          d.antiPruneLog = d.antiPruneLog || [];
          d.antiPruneLog.unshift({
            ts: Date.now(), level: 'warning', guildId, guildName,
            message: 'Missing View Audit Log permission — prune detection disabled for this server.'
          });
          if (d.antiPruneLog.length > 200) d.antiPruneLog.length = 200;
          writeData(d);
        } catch (_) {}
      } catch (_) {}
    }
    return false;
  }
}

async function findInviteFor(client, guildId) {
  try {
    const r = await axios.get(`https://discord.com/api/v9/guilds/${guildId}/invites`, { headers: { Authorization: client.token } });
    if (Array.isArray(r.data) && r.data.length) return `https://discord.gg/${r.data[0].code}`;
  } catch (e) {}
  try {
    const guild = client.guilds.cache.get(guildId);
    const ch = guild?.systemChannel || Array.from(guild.channels.cache.values()).find(c => c.type === 'GUILD_TEXT' || c.type === 0);
    if (ch?.createInvite) {
      const inv = await ch.createInvite({ maxAge: 0, maxUses: 0, unique: false });
      return `https://discord.gg/${inv.code}`;
    }
  } catch (e) {}
  return '';
}

const recentPruneHandled = new Set(); // dedupe per (guild, user)
const antiPruneUserCooldown = new Map(); // userId -> nextAllowedTs
const antiPruneQueues = new Map(); // accountName -> Promise chain
const antiPruneQueueDepth = new Map(); // accountName -> integer
const antiPruneAccountCooldown = new Map(); // accountName -> nextAllowedTs

async function antiPruneEnqueueFor(accountName, task) {
  const prev = antiPruneQueues.get(accountName) || Promise.resolve();
  antiPruneQueueDepth.set(accountName, (antiPruneQueueDepth.get(accountName) || 0) + 1);
  const next = prev.then(task).catch(() => {}).finally(() => {
    antiPruneQueueDepth.set(accountName, Math.max(0, (antiPruneQueueDepth.get(accountName) || 1) - 1));
  });
  antiPruneQueues.set(accountName, next);
  return next;
}

function pickLeastBusyAccount(accountNames = []) {
  if (!accountNames.length) return null;
  return accountNames.slice().sort((a, b) => (antiPruneQueueDepth.get(a) || 0) - (antiPruneQueueDepth.get(b) || 0))[0];
}
function accountCanWorkGuild(accountName, guildId) {
  const e = clients.get(accountName);
  return !!(e?.client?.guilds?.cache?.has(guildId));
}

async function handleAntiPrune(name, member) {
  // Distribute load across allowed accounts by queue depth (fast + safer).
  const d0 = readData();
  const cfg0 = d0.antiPruneConfig || {};
  const guildId = member.guild.id;
  const eligible = Array.from(clients.keys()).filter(n =>
    (!cfg0.accounts?.length || cfg0.accounts.includes(n)) && accountCanWorkGuild(n, guildId)
  );
  const worker = pickLeastBusyAccount(eligible) || name;
  const run = async () => {
  try {
    const d = readData();
    const cfg = d.antiPruneConfig || {};
    if (!cfg.enabled) return;
    if (cfg.accounts?.length && !cfg.accounts.includes(name)) return;
    if (cfg.scope === 'servers' && !cfg.servers?.includes(guildId)) return;

    const dedupeKey = `${guildId}|${member.id}`;
    if (recentPruneHandled.has(dedupeKey)) return;
    const now = Date.now();
    const nextOk = antiPruneUserCooldown.get(member.id) || 0;
    if (now < nextOk) return;

    const client = getClientByName(worker) || getClientByName(name);
    if (!client) return;
    const isPrune = await isPrunedRecently(client, guildId);
    if (!isPrune) return;
    recentPruneHandled.add(dedupeKey);
    setTimeout(() => recentPruneHandled.delete(dedupeKey), 30000);
    antiPruneUserCooldown.set(member.id, Date.now() + 35000); // anti-spam but not too slow at scale

    const invite = await findInviteFor(client, guildId);
    const message = (cfg.message || 'You were removed from {server} by mistake — please rejoin: {invite}')
      .replace('{server}', member.guild.name)
      .replace('{invite}', invite || '(no invite available)')
      .replace('{user}', member.user?.username || '');

    let attempt = null;
    let by = name;
    // Per-account cooldown to avoid DM bursts (also applies in single-account mode).
    const waitMs = Math.max(0, (antiPruneAccountCooldown.get(by) || 0) - Date.now());
    if (waitMs > 0) await sleep(waitMs);
    antiPruneAccountCooldown.set(by, Date.now() + jitter(900, 1500));

    attempt = await tryDmUser(client, member.id, message);
    if (!attempt.ok && cfg.distribute !== false) {
      // Try other connected accounts that share a server with the user
      for (const [otherName, e] of clients.entries()) {
        if (otherName === name) continue;
        if (cfg.accounts?.length && !cfg.accounts.includes(otherName)) continue;
        const shares = Array.from(e.client.guilds.cache.values()).some(g => g.members.cache.has(member.id) || g.id === guildId);
        if (!shares) continue;
        const waitOther = Math.max(0, (antiPruneAccountCooldown.get(otherName) || 0) - Date.now());
        if (waitOther > 0) await sleep(waitOther);
        antiPruneAccountCooldown.set(otherName, Date.now() + jitter(900, 1500));
        const r = await tryDmUser(e.client, member.id, message);
        if (r.ok) { attempt = r; by = otherName; break; }
        await sleep(jitter(350, 850));
      }
    }
    if (!attempt.ok) {
      sseBroadcast('antiprune_warning', {
        guildId,
        guildName: member.guild.name,
        message: `AntiPrune failed to DM ${member.user?.username || member.id}: ${attempt.error || 'unknown error'}`
      });
    }

    const log = d.antiPruneLog || [];
    log.unshift({
      ts: Date.now(),
      guild: { id: guildId, name: member.guild.name },
      user: { id: member.id, username: member.user?.username || 'unknown', avatar: member.user?.displayAvatarURL?.({ size: 32 }) || defaultAvatarUrl(member.id) },
      detectedBy: worker,
      sentBy: attempt.ok ? by : null,
      ok: attempt.ok, error: attempt.error || null,
      invite
    });
    if (log.length > 300) log.length = 300;
    d.antiPruneLog = log;
    writeData(d);
    sseBroadcast('antiprune', { event: log[0] });
  } catch (e) {}
  };
  // Single-account fast path (no extra queue overhead).
  if (eligible.length <= 1) return run();
  return antiPruneEnqueueFor(worker, run);
}

function attachAntiPruneListener(name, client, ownerUid) {
  ownerUid = ownerUid || currentUserId();
  if (client.__antipruneBound) return;
  client.__antipruneBound = true;
  client.on('guildMemberRemove', (member) => withUser(ownerUid, () => handleAntiPrune(name, member)));
}
// Listeners are bound during connectOne(); no need to re-iterate here.

app.get('/api/antiprune/config', (req, res) => {
  const d = readData();
  ok(res, { config: d.antiPruneConfig || {} });
});

app.post('/api/antiprune/config', (req, res) => {
  try {
    const d = readData();
    const patch = req.body || {};
    if (typeof patch.enabled !== 'undefined' && typeof patch.enabled !== 'boolean') return fail(res, new Error('enabled must be boolean'));
    if (typeof patch.scope !== 'undefined' && !['all', 'servers'].includes(patch.scope)) return fail(res, new Error('scope must be all or servers'));
    if (typeof patch.message !== 'undefined' && typeof patch.message !== 'string') return fail(res, new Error('message must be string'));
    if (patch.message && patch.message.length > 500) return fail(res, new Error('message too long (max 500)'));
    if (typeof patch.accounts !== 'undefined' && !Array.isArray(patch.accounts)) return fail(res, new Error('accounts must be array'));
    if (typeof patch.servers !== 'undefined' && !Array.isArray(patch.servers)) return fail(res, new Error('servers must be array'));
    d.antiPruneConfig = { ...(d.antiPruneConfig || {}), ...patch };
    d.antiPruneConfig.accounts = Array.from(new Set((d.antiPruneConfig.accounts || []).map(String))).slice(0, 100);
    d.antiPruneConfig.servers = Array.from(new Set((d.antiPruneConfig.servers || []).map(String))).slice(0, 500);
    writeData(d);
    ok(res, { config: d.antiPruneConfig });
  } catch (e) { fail(res, e); }
});

app.get('/api/antiprune/log', (req, res) => {
  const d = readData();
  ok(res, { log: (d.antiPruneLog || []).slice(0, 200) });
});

app.delete('/api/antiprune/log', (req, res) => {
  const d = readData(); d.antiPruneLog = []; writeData(d); ok(res);
});

app.get('/api/updates', async (req, res) => {
  try {
    const r = await axios.get('https://raw.githubusercontent.com/Bherl1/DiscordAccMgr/refs/heads/main/package.json');
    const latest = r.data.version;
    const current = require('./package.json').version;
    res.json({ hasUpdate: latest > current, version: latest, downloadUrl: `https://github.com/Bherl1/DiscordAccMgr/releases/download/v${latest}/DiscordAccManager-Setup.exe` });
  } catch (e) { res.json({ hasUpdate: false }); }
});

// ═══════════════════════════════════════════════
//  Start server + auto-open browser locally
// ═══════════════════════════════════════════════
// ═══════════════════════════════════════════════
//  6. BACKGROUND TASK SYSTEM
//  Single-task-per-account lock for anti-ban safety.
//  Live progress via SSE on /api/features/stream (type=task).
// ═══════════════════════════════════════════════
const tasks = new Map();
const taskAccountLocks = new Set();
const TASK_RING_MAX = 60;

function newTaskId() { return `t_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`; }

function summarizeTask(t) {
  return {
    id: t.id, type: t.type, label: t.label, account: t.account,
    status: t.status, current: t.current, total: t.total,
    okCount: t.okCount, failCount: t.failCount,
    startedAt: t.startedAt, doneAt: t.doneAt,
    cancelled: t.cancelled, error: t.error || null,
    lastItem: t.items.length ? t.items[t.items.length - 1] : null
  };
}

function createTask({ type, label, total = 0, account = null }) {
  if (account && taskAccountLocks.has(account))
    throw new Error(`Account "${account}" is already running a task. Wait or cancel it first.`);
  const id = newTaskId();
  const t = {
    id, type, label, account,
    status: 'running', current: 0, total,
    okCount: 0, failCount: 0,
    items: [], errors: [],
    startedAt: Date.now(), doneAt: null,
    cancelled: false, error: null
  };
  tasks.set(id, t);
  if (account) taskAccountLocks.add(account);
  // Trim ring buffer of finished tasks
  if (tasks.size > TASK_RING_MAX) {
    const finished = Array.from(tasks.values()).filter(x => x.status !== 'running').sort((a, b) => a.startedAt - b.startedAt);
    while (tasks.size > TASK_RING_MAX && finished.length) {
      const oldest = finished.shift(); tasks.delete(oldest.id);
    }
  }
  sseBroadcast('task', { task: summarizeTask(t) });
  return t;
}
function pushTaskItem(t, item) {
  if (!t || t.status !== 'running') return;
  t.items.push(item); t.current++;
  if (item?.ok) t.okCount++; else t.failCount++;
  if (t.items.length > 200) t.items.splice(0, t.items.length - 200);
  sseBroadcast('task', { task: summarizeTask(t) });
}
function finishTask(t, status = 'done', error = null) {
  if (!t) return;
  t.status = status; t.doneAt = Date.now();
  if (error) t.error = String(error?.message || error);
  if (t.account) taskAccountLocks.delete(t.account);
  sseBroadcast('task', { task: summarizeTask(t) });
}
function isCancelled(t) { return !!t?.cancelled; }

app.get('/api/tasks', (req, res) => {
  const arr = Array.from(tasks.values())
    .sort((a, b) => b.startedAt - a.startedAt)
    .map(summarizeTask);
  ok(res, { tasks: arr });
});
app.get('/api/tasks/:id', (req, res) => {
  const t = tasks.get(req.params.id);
  if (!t) return fail(res, new Error('Task not found'));
  ok(res, { task: summarizeTask(t), items: t.items });
});
app.post('/api/tasks/:id/cancel', (req, res) => {
  const t = tasks.get(req.params.id);
  if (!t) return fail(res, new Error('Task not found'));
  if (t.status !== 'running') return fail(res, new Error('Task already finished'));
  t.cancelled = true;
  sseBroadcast('task', { task: summarizeTask(t) });
  ok(res);
});
app.delete('/api/tasks/:id', (req, res) => {
  const t = tasks.get(req.params.id);
  if (!t) return fail(res, new Error('Task not found'));
  if (t.status === 'running') return fail(res, new Error('Cannot delete a running task; cancel first'));
  tasks.delete(req.params.id); ok(res);
});

// ═══════════════════════════════════════════════
//  7. SEARCH MANAGER
// ═══════════════════════════════════════════════

// GET /users/{id}/profile  — Discord user profile (mutual_guilds, mutual_friends, badges …)
async function fetchUserProfile(token, userId) {
  const url = `https://discord.com/api/v9/users/${userId}/profile?with_mutual_guilds=true&with_mutual_friends_count=true`;
  const r = await axios.get(url, { headers: { Authorization: token } });
  return r.data;
}
async function fetchUserBasic(token, userId) {
  const r = await axios.get(`https://discord.com/api/v9/users/${userId}`, {
    headers: { Authorization: token }
  });
  return r.data;
}

// Look the user up in any connected client's local caches before hitting the
// Discord API. Many "Unauthorized" errors on /users/{id} are recoverable this
// way (e.g. token rate-limited but the user is in our friend list / guild
// member cache / DM recipients). Returns a minimal Discord-style user object
// or null if no cache hit.
function findUserInCaches(userId) {
  for (const [name, entry] of clients.entries()) {
    const c = entry?.client;
    if (!c) continue;
    // 1) global user cache
    try {
      const u = c.users?.cache?.get?.(userId);
      if (u) return { id: u.id, username: u.username, global_name: u.globalName, discriminator: u.discriminator, avatar: u.avatar, bot: u.bot, _cachedFrom: name };
    } catch (e) {}
    // 2) friend / relationship cache
    try {
      for (const rel of c.relationships?.cache?.values?.() || []) {
        const u = rel.user || rel;
        if (u?.id === userId) return { id: u.id, username: u.username, global_name: u.globalName || u.global_name, discriminator: u.discriminator, avatar: u.avatar, bot: !!u.bot, _cachedFrom: name };
      }
    } catch (e) {}
    // 3) guild member caches
    try {
      for (const g of c.guilds?.cache?.values?.() || []) {
        const m = g.members?.cache?.get?.(userId);
        if (m?.user) {
          const u = m.user;
          return { id: u.id, username: u.username, global_name: u.globalName, discriminator: u.discriminator, avatar: u.avatar, bot: !!u.bot, _cachedFrom: name };
        }
      }
    } catch (e) {}
    // 4) DM recipients
    try {
      for (const ch of c.channels?.cache?.values?.() || []) {
        if (ch.type === 'DM' && ch.recipient?.id === userId) {
          const u = ch.recipient;
          return { id: u.id, username: u.username, global_name: u.globalName, discriminator: u.discriminator, avatar: u.avatar, bot: !!u.bot, _cachedFrom: name };
        }
      }
    } catch (e) {}
  }
  return null;
}

function userToView(u) {
  return {
    id: u.id,
    username: u.username,
    globalName: u.global_name || u.globalName || u.username,
    discriminator: u.discriminator || '0',
    bot: !!u.bot,
    avatar: u.avatar
      ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}${u.avatar.startsWith('a_') ? '.gif' : '.png'}?size=256`
      : defaultAvatarUrl(u.id),
    banner: u.banner
      ? `https://cdn.discordapp.com/banners/${u.id}/${u.banner}${u.banner.startsWith('a_') ? '.gif' : '.png'}?size=600`
      : null,
    accentColor: u.accent_color || u.accentColor || null,
    bio: u.bio || '',
    pronouns: u.pronouns || '',
    flags: u.public_flags || u.flags || 0,
    createdAt: (() => { try { return Number((BigInt(u.id) >> 22n) + 1420070400000n); } catch { return null; } })()
  };
}

// Voice state finder — scan every connected client's guild caches
function findVoiceForUser(userId, accountFilter = null) {
  const out = [];
  for (const [name, entry] of clients.entries()) {
    if (accountFilter && name !== accountFilter) continue;
    const c = entry.client;
    if (!c?.guilds) continue;
    for (const g of c.guilds.cache.values()) {
      const vs = g.voiceStates?.cache?.get?.(userId);
      if (!vs || !vs.channelId) continue;
      const ch = g.channels?.cache?.get?.(vs.channelId);
      // Snapshot the entire voice room (everyone in it, with their states)
      const occupants = [];
      if (g.voiceStates?.cache) {
        for (const ovs of g.voiceStates.cache.values()) {
          if (ovs.channelId !== vs.channelId) continue;
          const m = g.members?.cache?.get?.(ovs.id);
          occupants.push({
            id: ovs.id,
            username: m?.user?.username || ovs.id,
            displayName: m?.displayName || m?.user?.globalName || m?.user?.username || ovs.id,
            avatar: m?.user?.displayAvatarURL?.({ size: 64 }) || defaultAvatarUrl(ovs.id),
            self: ovs.id === c.user.id,
            target: ovs.id === userId,
            mute: !!(ovs.mute || ovs.selfMute),
            deaf: !!(ovs.deaf || ovs.selfDeaf),
            video: !!ovs.selfVideo,
            stream: !!ovs.streaming,
            serverMute: !!ovs.serverMute,
            serverDeaf: !!ovs.serverDeaf
          });
        }
      }
      out.push({
        seenBy: name,
        guild: { id: g.id, name: g.name, icon: g.iconURL?.({ size: 64 }) || null },
        channel: { id: ch?.id, name: ch?.name || 'voice', userLimit: ch?.userLimit || 0, type: ch?.type },
        target: {
          mute: !!(vs.mute || vs.selfMute),
          deaf: !!(vs.deaf || vs.selfDeaf),
          video: !!vs.selfVideo,
          stream: !!vs.streaming,
          serverMute: !!vs.serverMute,
          serverDeaf: !!vs.serverDeaf,
          requestToSpeakTimestamp: vs.requestToSpeakTimestamp || null
        },
        occupants
      });
    }
  }
  return out;
}

// Last message search across DMs we share + recent guild caches the user is in
async function findLastMessageForUser(userId, accountFilter = null) {
  const found = [];
  for (const [name, entry] of clients.entries()) {
    if (accountFilter && name !== accountFilter) continue;
    const c = entry.client;
    if (!c?.user) continue;

    // 1) DMs (cheap)
    try {
      for (const ch of c.channels.cache.values()) {
        if (ch.type !== 'DM' || ch.recipient?.id !== userId) continue;
        const last = ch.lastMessage || ch.messages?.cache?.last?.();
        if (last) {
          found.push({
            seenBy: name,
            kind: 'dm',
            channel: { id: ch.id, name: '@' + (ch.recipient?.username || 'dm'), type: 'DM' },
            guild: null,
            message: {
              id: last.id, content: last.content || '',
              ts: last.createdTimestamp || 0,
              attachments: Array.from(last.attachments?.values?.() || []).map(a => ({ url: a.url, name: a.name }))
            }
          });
        }
      }
    } catch (e) {}

    // 2) Guild message search via Discord search API (only guilds where user is a member)
    try {
      for (const g of c.guilds.cache.values()) {
        const member = g.members?.cache?.get?.(userId);
        if (!member) continue;
        try {
          const r = await axios.get(`https://discord.com/api/v9/guilds/${g.id}/messages/search`, {
            headers: { Authorization: c.token },
            params: { author_id: userId, limit: 1 }
          });
          const msg = r.data?.messages?.[0]?.[0];
          if (msg) {
            const ch = g.channels?.cache?.get?.(msg.channel_id);
            found.push({
              seenBy: name, kind: 'guild',
              guild: { id: g.id, name: g.name, icon: g.iconURL?.({ size: 64 }) || null },
              channel: { id: msg.channel_id, name: ch?.name || msg.channel_id, type: ch?.type },
              message: {
                id: msg.id, content: msg.content || '',
                ts: new Date(msg.timestamp).getTime(),
                attachments: (msg.attachments || []).map(a => ({ url: a.url, name: a.filename }))
              }
            });
          }
          await sleep(700 + jitter(0, 400)); // soft anti-rate (raised from 250ms — Discord rate-limits guild search aggressively)
        } catch (e) { /* search not allowed in some guilds */ }
      }
    } catch (e) {}
  }
  return found.sort((a, b) => (b.message?.ts || 0) - (a.message?.ts || 0));
}

// Mutual guilds / friends / DMs across all (or one) account
function gatherMutuals(userId, profileMutualGuilds = [], accountFilter = null) {
  const guildSet = new Map();
  let dms = [];
  for (const [name, entry] of clients.entries()) {
    if (accountFilter && name !== accountFilter) continue;
    const c = entry.client;
    if (!c?.guilds) continue;
    for (const g of c.guilds.cache.values()) {
      if (!g.members?.cache?.has?.(userId)) continue;
      const k = g.id;
      const existing = guildSet.get(k) || { id: g.id, name: g.name, icon: g.iconURL?.({ size: 64 }) || null, sharedBy: [] };
      existing.sharedBy.push(name);
      guildSet.set(k, existing);
    }
    for (const ch of c.channels.cache.values()) {
      if (ch.type === 'DM' && ch.recipient?.id === userId) {
        dms.push({ seenBy: name, channelId: ch.id });
      }
    }
  }
  // Merge with profile-API mutual guilds (covers servers the *target* shares with the requesting account
  // even when we don't have everyone cached)
  for (const mg of profileMutualGuilds || []) {
    if (!guildSet.has(mg.id)) {
      guildSet.set(mg.id, { id: mg.id, name: mg.name || mg.id, icon: mg.icon ? `https://cdn.discordapp.com/icons/${mg.id}/${mg.icon}.png?size=64` : null, sharedBy: ['(via profile API)'] });
    }
  }
  return { mutualGuilds: Array.from(guildSet.values()), mutualDMs: dms };
}

app.get('/api/search/user', async (req, res) => {
  try {
    const id = (req.query.id || '').trim();
    const username = (req.query.username || '').trim().toLowerCase();
    const accountFilter = (req.query.account || '').trim() || null;
    const allAccounts = req.query.all === '1' || req.query.all === 'true';
    if (!id && !username) return fail(res, new Error('Provide id or username'));

    const accountsToUse = (allAccounts || !accountFilter)
      ? Array.from(clients.keys())
      : [accountFilter];
    if (!accountsToUse.length) return fail(res, new Error('No accounts connected'));

    let resolvedId = id;
    let basic = null;
    let resolvedVia = null;

    // 1) ID path: pull authoritative user info
    if (resolvedId) {
      let lastErr = null;
      for (const acct of accountsToUse) {
        const c = clients.get(acct)?.client;
        if (!c?.token) continue;
        try { basic = await fetchUserBasic(c.token, resolvedId); resolvedVia = acct; break; }
        catch (e) { lastErr = e; }
      }
      // Fallback to local caches if every account failed (rate-limit / 401)
      if (!basic) {
        const cached = findUserInCaches(resolvedId);
        if (cached) {
          basic = cached;
          resolvedVia = `cache (${cached._cachedFrom})`;
        } else {
          const reason = lastErr?.response?.status === 401
            ? 'Discord rejected the lookup (token unauthorized for this user). User is not in any of your caches either.'
            : (lastErr?.response?.data?.message || lastErr?.message || 'User not found');
          return fail(res, new Error(reason));
        }
      }
    } else {
      // 2) Username path: fuzzy match against caches (friends/guild members/DMs/recipients)
      const candidates = new Map();
      for (const acct of accountsToUse) {
        const c = clients.get(acct)?.client;
        if (!c) continue;
        // friends via REST
        try {
          const r = await axios.get('https://discord.com/api/v9/users/@me/relationships', { headers: { Authorization: c.token } });
          for (const rel of r.data || []) {
            if (rel.type !== 1) continue;
            const u = rel.user || rel;
            const name = (u.username || '').toLowerCase();
            const gname = (u.global_name || '').toLowerCase();
            if (name === username || gname === username || name.includes(username) || gname.includes(username)) {
              candidates.set(u.id, u);
            }
          }
        } catch (e) {}
        // guild members caches
        for (const g of c.guilds?.cache?.values?.() || []) {
          for (const m of g.members?.cache?.values?.() || []) {
            const u = m.user;
            const name = (u.username || '').toLowerCase();
            const gname = (u.globalName || '').toLowerCase();
            const display = (m.displayName || '').toLowerCase();
            if (name === username || gname === username || display === username ||
                name.includes(username) || gname.includes(username) || display.includes(username)) {
              candidates.set(u.id, { id: u.id, username: u.username, global_name: u.globalName, avatar: u.avatar, bot: u.bot });
            }
          }
        }
        // DM recipients
        for (const ch of c.channels?.cache?.values?.() || []) {
          if (ch.type !== 'DM' || !ch.recipient) continue;
          const u = ch.recipient;
          const name = (u.username || '').toLowerCase();
          const gname = (u.globalName || '').toLowerCase();
          if (name === username || gname === username || name.includes(username) || gname.includes(username)) {
            candidates.set(u.id, { id: u.id, username: u.username, global_name: u.globalName, avatar: u.avatar, bot: u.bot });
          }
        }
      }
      if (!candidates.size) return fail(res, new Error(`No user matches "${username}" in your accessible caches. Try the user's ID.`));
      // If multiple, return list for disambiguation
      if (candidates.size > 1) {
        const arr = Array.from(candidates.values()).map(userToView).slice(0, 20);
        return ok(res, { multiple: true, candidates: arr });
      }
      basic = Array.from(candidates.values())[0];
      resolvedId = basic.id;
      // Re-fetch authoritative info to enrich
      for (const acct of accountsToUse) {
        const c = clients.get(acct)?.client;
        if (!c?.token) continue;
        try { basic = await fetchUserBasic(c.token, resolvedId); resolvedVia = acct; break; } catch (e) {}
      }
    }

    const view = userToView(basic);

    // Profile (mutuals) — best with any single account
    let profileMutualGuilds = [];
    let mutualFriendsCount = 0;
    let badges = [];
    for (const acct of accountsToUse) {
      const c = clients.get(acct)?.client;
      if (!c?.token) continue;
      try {
        const p = await fetchUserProfile(c.token, resolvedId);
        profileMutualGuilds = p.mutual_guilds || [];
        mutualFriendsCount = p.mutual_friends_count || 0;
        badges = p.badges || p.user?.public_flags ? (p.badges || []) : [];
        break;
      } catch (e) {}
    }

    const mutuals = gatherMutuals(resolvedId, profileMutualGuilds, accountFilter);
    const voice = findVoiceForUser(resolvedId, accountFilter);
    let lastMessage = null;
    try {
      const msgs = await findLastMessageForUser(resolvedId, accountFilter);
      if (msgs.length) lastMessage = msgs[0];
    } catch (e) {}

    ok(res, {
      user: view,
      resolvedVia,
      mutualGuilds: mutuals.mutualGuilds,
      mutualDMs: mutuals.mutualDMs,
      mutualFriendsCount,
      badges,
      voice,            // array — if non-empty, user is currently in a voice channel we can see
      lastMessage,      // single most-recent across our visible channels (DMs + guild search)
      accountsScanned: accountsToUse
    });
  } catch (e) { fail(res, e); }
});

// Quick endpoint: poll voice state only (used by SearchManager auto-refresh)
app.get('/api/search/voice/:userId', (req, res) => {
  const accountFilter = (req.query.account || '').trim() || null;
  ok(res, { voice: findVoiceForUser(req.params.userId, accountFilter) });
});

// Quick endpoint: refresh just last message
app.get('/api/search/last-message/:userId', async (req, res) => {
  try {
    const accountFilter = (req.query.account || '').trim() || null;
    const list = await findLastMessageForUser(req.params.userId, accountFilter);
    ok(res, { messages: list.slice(0, 5) });
  } catch (e) { fail(res, e); }
});

// Fast user suggest from local cache — zero Discord API calls, <10ms response
app.get('/api/search/suggest', (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  if (!q || q.length < 1) return ok(res, { suggestions: [] });
  const accountFilter = (req.query.account || '').trim() || null;
  const accountsToUse = accountFilter ? [accountFilter] : Array.from(clients.keys());
  const seen = new Map();
  const tryAdd = (u, displayName) => {
    if (seen.size >= 25 || !u?.id) return;
    const uname  = (u.username   || '').toLowerCase();
    const gname  = (u.globalName || u.global_name || '').toLowerCase();
    const dname  = (displayName  || gname || uname).toLowerCase();
    if (!uname.includes(q) && !gname.includes(q) && !dname.includes(q)) return;
    if (!seen.has(u.id)) {
      seen.set(u.id, {
        id: u.id,
        username:   u.username || '',
        globalName: u.globalName || u.global_name || u.username || '',
        avatar: u.avatar
          ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png?size=64`
          : defaultAvatarUrl(u.id)
      });
    }
  };
  for (const acct of accountsToUse) {
    const c = clients.get(acct)?.client;
    if (!c) continue;
    for (const ch of c.channels?.cache?.values?.() || []) {
      if (ch.type !== 'DM' || !ch.recipient) continue;
      tryAdd(ch.recipient, null);
    }
    for (const g of c.guilds?.cache?.values?.() || []) {
      for (const m of g.members?.cache?.values?.() || []) {
        if (seen.size >= 25) break;
        tryAdd(m.user, m.displayName);
      }
      if (seen.size >= 25) break;
    }
  }
  ok(res, { suggestions: Array.from(seen.values()).slice(0, 10) });
});

// ═══════════════════════════════════════════════
//  8. MASS FRIEND OPERATIONS
//  All bulk ops run through the task system.
//  Conservative throttling: default 1 req / 6-10s, capped at 30/hr/account.
// ═══════════════════════════════════════════════
async function relationshipPut(token, userId) {
  // Adds friend by ID
  await axios.put(`https://discord.com/api/v9/users/@me/relationships/${userId}`,
    {}, { headers: { Authorization: token, 'Content-Type': 'application/json' } });
}
async function relationshipDelete(token, userId) {
  await axios.delete(`https://discord.com/api/v9/users/@me/relationships/${userId}`,
    { headers: { Authorization: token } });
}
async function fetchGuildMembers(client, guildId, max = 1000) {
  const guild = client.guilds.cache.get(guildId);
  if (!guild) throw new Error('Guild not found');
  try { await guild.members.fetch({ time: 30000 }); } catch (e) {}
  return Array.from(guild.members.cache.values()).slice(0, max);
}

function applyMemberFilter(members, f = {}) {
  return members.filter(m => {
    const u = m.user;
    if (!u) return false;
    if (f.excludeBots && u.bot) return false;
    if (f.botsOnly && !u.bot) return false;
    if (f.excludeIds?.length && f.excludeIds.includes(u.id)) return false;
    if (f.includeIds?.length && !f.includeIds.includes(u.id)) return false;
    if (f.usernameContains) {
      const q = f.usernameContains.toLowerCase();
      if (!(u.username || '').toLowerCase().includes(q) &&
          !(u.globalName || '').toLowerCase().includes(q) &&
          !(m.displayName || '').toLowerCase().includes(q)) return false;
    }
    return true;
  });
}

// POST /api/friends/bulk-add
//   body: { account, ids?:[], serverId?, filter?:{}, throttleMs?: 7000, max?: 50 }
//   Returns: { taskId }
// Per-account rolling 1-hour quota of friend-adds. Discord bans accounts
// that send too many invites — we cap at 30/h regardless of UI input.
const MASS_FRIEND_HOURLY_CAP = 30;
const _friendAddHistory = new Map(); // account -> [timestamps]
function _recordFriendAdd(account) {
  const arr = _friendAddHistory.get(account) || [];
  arr.push(Date.now());
  _friendAddHistory.set(account, arr);
}
function _friendAddsInLastHour(account) {
  const cutoff = Date.now() - 3600 * 1000;
  const arr = (_friendAddHistory.get(account) || []).filter(t => t >= cutoff);
  _friendAddHistory.set(account, arr);
  return arr.length;
}

app.post('/api/friends/bulk-add', async (req, res) => {
  try {
    const { account, ids = [], serverId, filter = {}, throttleMs = 7000, max = 50 } = req.body || {};
    if (!account) return fail(res, new Error('account is required'));
    const c = clients.get(account)?.client;
    if (!c?.token) return fail(res, new Error('Account not connected'));

    let targetUsers = [];
    if (Array.isArray(ids) && ids.length) {
      targetUsers = ids.map(id => ({ id, username: id }));
    } else if (serverId) {
      const members = await fetchGuildMembers(c, serverId, 2000);
      // Auto-exclude bots in addition to user filter — adding bots as friends
      // is impossible and just wastes quota
      const filtered = applyMemberFilter(members, { excludeBots: true, ...filter, excludeIds: [c.user.id, ...(filter.excludeIds || [])] });
      targetUsers = filtered.map(m => ({ id: m.user.id, username: m.user.username, globalName: m.user.globalName, avatar: m.user.displayAvatarURL?.({ size: 64 }) || defaultAvatarUrl(m.user.id) }));
    } else {
      return fail(res, new Error('Provide ids[] or serverId'));
    }
    if (!targetUsers.length) return fail(res, new Error('No users matched'));
    targetUsers = targetUsers.slice(0, Math.max(1, Math.min(500, max)));

    // Enforce hourly cap up-front: trim the queue to whatever we can still send
    const usedThisHour = _friendAddsInLastHour(account);
    const remaining = Math.max(0, MASS_FRIEND_HOURLY_CAP - usedThisHour);
    if (remaining === 0) {
      return fail(res, new Error(`Hourly safety cap reached for "${account}" (${MASS_FRIEND_HOURLY_CAP}/hr). Try again later.`));
    }
    if (targetUsers.length > remaining) targetUsers = targetUsers.slice(0, remaining);

    const t = createTask({
      type: 'friend_add', account,
      label: serverId ? `Add ${targetUsers.length} from server ${serverId}` : `Add ${targetUsers.length} by IDs`,
      total: targetUsers.length
    });

    (async () => {
      // Floor delay raised to 5s — sub-3s adds are a major ban signal
      const delay = Math.max(5000, throttleMs);
      let consecutiveFails = 0;
      for (const u of targetUsers) {
        if (isCancelled(t)) break;
        // Re-check hourly cap inside the loop in case other tasks ran in parallel
        if (_friendAddsInLastHour(account) >= MASS_FRIEND_HOURLY_CAP) {
          t.error = `Hourly safety cap reached (${MASS_FRIEND_HOURLY_CAP}/hr) — stopping early.`;
          break;
        }
        try {
          await relationshipPut(c.token, u.id);
          _recordFriendAdd(account);
          pushTaskItem(t, { ok: true, id: u.id, username: u.username, ts: Date.now() });
          consecutiveFails = 0;
        } catch (e) {
          const msg = e?.response?.data?.message || e?.message || 'failed';
          const code = e?.response?.status;
          pushTaskItem(t, { ok: false, id: u.id, username: u.username, error: msg, code, ts: Date.now() });
          if (code === 429) {
            const retry = Number(e.response?.data?.retry_after || 5);
            await sleep((retry + 1) * 1000);
          } else if (code === 401 || code === 403) {
            // Account-wide block — stop NOW, don't drain the rest
            t.error = `Discord blocked friend requests on this account (${code}). Stopping to avoid escalation.`;
            break;
          } else {
            consecutiveFails++;
            if (consecutiveFails >= 5) {
              t.error = 'Too many consecutive failures — stopping to protect the account from a ban.';
              break;
            }
          }
        }
        await sleep(delay + jitter(0, 1500));
      }
      finishTask(t, isCancelled(t) ? 'cancelled' : 'done');
    })().catch(e => finishTask(t, 'failed', e));

    ok(res, { taskId: t.id, hourlyCap: MASS_FRIEND_HOURLY_CAP, remainingThisHour: Math.max(0, MASS_FRIEND_HOURLY_CAP - _friendAddsInLastHour(account)) });
  } catch (e) { fail(res, e); }
});

// POST /api/friends/bulk-remove
//   body: { account, mode: 'all' | 'server' | 'ids', serverId?, ids?, filter?, throttleMs? }
app.post('/api/friends/bulk-remove', async (req, res) => {
  try {
    const { account, mode, serverId, ids = [], filter = {}, throttleMs = 4000 } = req.body || {};
    if (!account) return fail(res, new Error('account is required'));
    const c = clients.get(account)?.client;
    if (!c?.token) return fail(res, new Error('Account not connected'));

    // Pull current friends list
    const r = await axios.get('https://discord.com/api/v9/users/@me/relationships', { headers: { Authorization: c.token } });
    const friends = (r.data || []).filter(x => x.type === 1).map(x => x.user);
    let targets = [];

    if (mode === 'all') {
      targets = friends;
    } else if (mode === 'ids') {
      const set = new Set(ids);
      targets = friends.filter(u => set.has(u.id));
    } else if (mode === 'server') {
      if (!serverId) return fail(res, new Error('serverId required'));
      const members = await fetchGuildMembers(c, serverId, 2000);
      const memberIds = new Set(members.map(m => m.user.id));
      targets = friends.filter(u => memberIds.has(u.id));
    } else {
      return fail(res, new Error('mode must be all|server|ids'));
    }
    if (filter && Object.keys(filter).length) {
      targets = targets.filter(u => {
        if (filter.excludeBots && u.bot) return false;
        if (filter.usernameContains) {
          const q = filter.usernameContains.toLowerCase();
          if (!(u.username || '').toLowerCase().includes(q) &&
              !(u.global_name || '').toLowerCase().includes(q)) return false;
        }
        return true;
      });
    }
    if (!targets.length) return fail(res, new Error('No friends matched the criteria'));

    const t = createTask({
      type: 'friend_remove', account,
      label: `Remove ${targets.length} friend(s) (${mode})`,
      total: targets.length
    });

    (async () => {
      const delay = Math.max(2000, throttleMs);
      for (const u of targets) {
        if (isCancelled(t)) break;
        try {
          await relationshipDelete(c.token, u.id);
          pushTaskItem(t, { ok: true, id: u.id, username: u.username, ts: Date.now() });
        } catch (e) {
          const msg = e?.response?.data?.message || e?.message || 'failed';
          const code = e?.response?.status;
          pushTaskItem(t, { ok: false, id: u.id, username: u.username, error: msg, code, ts: Date.now() });
          if (code === 429) {
            const retry = Number(e.response?.data?.retry_after || 5);
            await sleep((retry + 1) * 1000);
          }
        }
        await sleep(delay + jitter(0, 1000));
      }
      finishTask(t, isCancelled(t) ? 'cancelled' : 'done');
    })().catch(e => finishTask(t, 'failed', e));

    ok(res, { taskId: t.id });
  } catch (e) { fail(res, e); }
});

// Lightweight server-members lookup for the UI to preview before kicking off a task
app.get('/api/discord/servers/:serverId/members', async (req, res) => {
  try {
    const c = pickClient(req);
    if (!c?.user) return fail(res, new Error('Not connected'));
    const guild = c.guilds.cache.get(req.params.serverId);
    if (!guild) return fail(res, new Error('Server not found'));
    try { await guild.members.fetch({ time: 20000 }); } catch (e) {}
    const arr = Array.from(guild.members.cache.values()).slice(0, 1500).map(m => ({
      id: m.user.id,
      username: m.user.username,
      displayName: m.displayName || m.user.globalName || m.user.username,
      avatar: m.user.displayAvatarURL?.({ size: 64 }) || defaultAvatarUrl(m.user.id),
      bot: !!m.user.bot
    }));
    ok(res, { members: arr, total: guild.memberCount || arr.length });
  } catch (e) { fail(res, e); }
});

// ═══════════════════════════════════════════════
//  9. PRIVATE MESSAGE DELETE TRACKING (real-time)
// ═══════════════════════════════════════════════
function attachDMDeleteListener(name, client, ownerUid) {
  ownerUid = ownerUid || currentUserId();
  if (client.__dmDeleteListenerBound) return;
  client.__dmDeleteListenerBound = true;
  client.on('messageDelete', (msg) => withUser(ownerUid, () => {
    try {
      if (!msg.channel || msg.channel.type !== 'DM') return;
      const payload = JSON.stringify({
        type: 'dm_delete',
        account: name,
        channelId: msg.channel.id,
        messageId: msg.id,
        ts: Date.now()
      });
      for (const sc of sseClients) {
        if (!sc.account || sc.account === name) {
          try { sc.res.write(`data: ${payload}\n\n`); } catch (e) {}
        }
      }
    } catch (e) {}
  }));
}
// Listeners are bound during connectOne(); no need to re-iterate here.

// ═══════════════════════════════════════════════
//  10. VOICE MANAGER
// ═══════════════════════════════════════════════

// In-memory state
const voiceSessions   = new Map(); // "<name>_<guildId>" -> { name, guildId, channelId, selfMute, selfDeaf, selfVideo, selfStream }
const voiceRotations  = new Map(); // rotationId -> { id, name, guildId, channels, intervalMs, randomOrder, timer, currentIdx, nextAt }
const voiceStateCycles= new Map(); // cycleId    -> { id, accounts, states, intervalMs, timer, currentIdx, nextAt }

// ── Voice Persistence (auto-rejoin on restart) ──────────────────────────────
// Per-user voice persistence — voice sessions auto-rejoin on restart.
const voicePersistStore = scopedStore('voice-persist.json', []);

function persistVoice() {
  try {
    voicePersistStore.write(Array.from(voiceSessions.values()));
  } catch (e) { /* non-fatal */ }
}

function loadVoicePersist() {
  try {
    const v = voicePersistStore.read();
    return Array.isArray(v) ? v : [];
  } catch (e) { return []; }
}

// Wrappers that persist on every mutation
function vsSet(key, val) { voiceSessions.set(key, val); persistVoice(); }
function vsDel(key)      { voiceSessions.delete(key);   persistVoice(); }

function sendVoiceOp(client, guildId, channelId, selfMute = false, selfDeaf = false, selfVideo = false, selfStream = false) {
  try {
    const shard = client.ws?.shards?.first?.() || client.ws?.shards?.get?.(0);
    if (!shard) return { ok: false, error: 'No active gateway shard' };
    // discord.js Status.READY === 0 ; if not ready, send is queued and may not deliver.
    const status = shard.status;
    if (status !== 0 && status !== undefined) return { ok: false, error: `Gateway not ready (status=${status})` };
    shard.send({
      op: 4,
      d: { guild_id: guildId, channel_id: channelId, self_mute: !!selfMute, self_deaf: !!selfDeaf, self_video: !!selfVideo, self_stream: !!selfStream }
    });
    return { ok: true };
  } catch (e) { return { ok: false, error: e?.message || 'send failed' }; }
}

// Send op 4 and wait briefly for the gateway to echo a VOICE_STATE_UPDATE confirming
// the join (or leave). Returns { ok, error }. This converts UI "simulation" into a
// real verified action — if Discord ignores the op (perms, shadowban, missing intents,
// etc.), we surface a real error instead of pretending the join succeeded.
function sendVoiceOpConfirmed(client, guildId, channelId, opts = {}, timeoutMs = 4500) {
  return new Promise((resolve) => {
    const myId = client?.user?.id;
    if (!myId) return resolve({ ok: false, error: 'Client not ready (no user id)' });

    let settled = false;
    const cleanup = () => {
      try { client.ws?.off?.('VOICE_STATE_UPDATE', onWsState); } catch (e) {}
      try { client.off?.('voiceStateUpdate', onJsState); } catch (e) {}
      clearTimeout(timer);
    };
    const finish = (r) => { if (settled) return; settled = true; cleanup(); resolve(r); };

    const matches = (gId, cId) => String(gId) === String(guildId) && (channelId == null ? cId == null : String(cId) === String(channelId));

    const onWsState = (data) => {
      if (!data || String(data.user_id) !== String(myId)) return;
      if (matches(data.guild_id, data.channel_id)) finish({ ok: true });
    };
    const onJsState = (oldS, newS) => {
      const target = newS?.member?.id || newS?.id || newS?.userId;
      if (String(target) !== String(myId)) return;
      const gId = newS?.guild?.id || newS?.guildId;
      const cId = newS?.channelId ?? newS?.channel_id;
      if (matches(gId, cId)) finish({ ok: true });
    };

    try { client.ws?.on?.('VOICE_STATE_UPDATE', onWsState); } catch (e) {}
    try { client.on?.('voiceStateUpdate', onJsState); } catch (e) {}

    const sendRes = sendVoiceOp(client, guildId, channelId, opts.selfMute, opts.selfDeaf, opts.selfVideo, opts.selfStream);
    if (!sendRes.ok) return finish({ ok: false, error: sendRes.error });

    const timer = setTimeout(() => finish({ ok: false, error: 'Discord did not confirm voice state (gateway timeout)' }), timeoutMs);
  });
}

function getVoiceClient(name) {
  const entry = clients.get(name);
  if (!entry?.client?.ws) return null;
  return entry.client;
}

function voiceSessionKey(name, guildId) { return `${name}__${guildId}`; }
function normalizeVoiceTargets(accounts) {
  const arr = Array.isArray(accounts) ? accounts : [accounts].filter(Boolean);
  return Array.from(new Set(arr.map(String).filter(Boolean)));
}
function resultSummary(results = []) {
  const okCount = results.filter(r => r.ok).length;
  return { total: results.length, ok: okCount, failed: results.length - okCount };
}

function isVoiceType(channel) {
  const t = channel?.type;
  return t === 'GUILD_VOICE' || t === 2 || t === 'GUILD_STAGE_VOICE' || t === 13;
}

function getSelfMember(guild, client) {
  return guild?.members?.me || guild?.members?.cache?.get?.(client?.user?.id) || null;
}

function canJoinVoiceChannel(channel, memberOrId) {
  const perms = channel?.permissionsFor?.(memberOrId);
  const canView = perms?.has?.('VIEW_CHANNEL') ?? true;
  const canConnect = perms?.has?.('CONNECT') ?? true;
  return !!(canView && canConnect);
}

function validateVoiceTarget(client, guildId, channelId) {
  const guild = client?.guilds?.cache?.get?.(guildId);
  if (!guild) return { ok: false, error: 'Guild not found in this account' };
  const channel = guild.channels?.cache?.get?.(channelId);
  if (!channel) return { ok: false, error: 'Channel not found in this guild' };
  if (!isVoiceType(channel)) return { ok: false, error: 'Target channel is not voice/stage' };

  const me = getSelfMember(guild, client) || client?.user?.id;
  if (!canJoinVoiceChannel(channel, me)) return { ok: false, error: 'Missing voice permissions' };

  const userLimit = Number(channel.userLimit) || 0;
  const currentIn = channel.members?.size || 0;
  const alreadyIn = guild.voiceStates?.cache?.get?.(client?.user?.id)?.channelId === channelId;
  if (!alreadyIn && userLimit > 0 && currentIn >= userLimit) return { ok: false, error: 'Voice channel is full' };

  return { ok: true, guild, channel };
}

// GET /api/voice/guilds — list all guilds with their voice channels for an account
app.get('/api/voice/guilds', (req, res) => {
  const { account } = req.query;
  const targets = account ? [[account, clients.get(account)]] : Array.from(clients.entries());
  const results = [];
  for (const [name, entry] of targets) {
    if (!entry?.client?.guilds) continue;
    for (const [, guild] of entry.client.guilds.cache) {
      const me = getSelfMember(guild, entry.client);
      const voiceChannels = guild.channels.cache
        .filter(c => isVoiceType(c))
        .filter((c) => {
          if (!canJoinVoiceChannel(c, me || entry.client.user?.id)) return false;
          const userLimit = Number(c.userLimit) || 0;
          if (userLimit <= 0) return true;
          const membersCount = c.members?.size || 0;
          return membersCount < userLimit;
        })
        .map(c => ({
          id: c.id,
          name: c.name,
          userLimit: c.userLimit || 0,
          members: c.members?.size || 0,
          bitrate: Math.round((c.bitrate || 64000) / 1000)
        }))
        .sort((a, b) => a.name.localeCompare(b.name));
      if (voiceChannels.length > 0) {
        results.push({ account: name, guildId: guild.id, guildName: guild.name, guildIcon: guild.iconURL?.({ size: 64 }) || null, voiceChannels });
      }
    }
  }
  ok(res, { guilds: results });
});

// GET /api/voice/sessions — list all active voice sessions
app.get('/api/voice/sessions', (req, res) => {
  ok(res, { sessions: Array.from(voiceSessions.values()) });
});

// GET /api/voice/rotations — list channel rotations
app.get('/api/voice/rotations', (req, res) => {
  const list = Array.from(voiceRotations.values()).map(r => ({
    id: r.id, name: r.name, guildId: r.guildId, guildName: r.guildName,
    channels: r.channels, intervalMs: r.intervalMs, randomOrder: r.randomOrder,
    currentIdx: r.currentIdx, nextAt: r.nextAt, accounts: r.accounts
  }));
  ok(res, { rotations: list });
});

// GET /api/voice/state-cycles — list state cycles
app.get('/api/voice/state-cycles', (req, res) => {
  const list = Array.from(voiceStateCycles.values()).map(c => ({
    id: c.id, accounts: c.accounts, states: c.states,
    intervalMs: c.intervalMs, currentIdx: c.currentIdx, nextAt: c.nextAt
  }));
  ok(res, { cycles: list });
});

// POST /api/voice/join — join a voice channel (REAL, with gateway confirmation)
app.post('/api/voice/join', async (req, res) => {
  const { accounts, guildId, channelId, selfMute = false, selfDeaf = false } = req.body;
  const targets = normalizeVoiceTargets(accounts);
  if (!targets.length) return fail(res, new Error('No accounts specified'));
  if (!guildId || !channelId) return fail(res, new Error('guildId and channelId required'));
  if (typeof selfMute !== 'boolean' || typeof selfDeaf !== 'boolean') return fail(res, new Error('selfMute/selfDeaf must be boolean'));
  const results = await Promise.all(targets.map(async (name) => {
    const client = getVoiceClient(name);
    if (!client) return { name, ok: false, error: 'Not connected' };
    const target = validateVoiceTarget(client, guildId, channelId);
    if (!target.ok) return { name, ok: false, error: target.error };
    const r = await sendVoiceOpConfirmed(client, guildId, channelId, { selfMute, selfDeaf });
    if (r.ok) {
      vsSet(voiceSessionKey(name, guildId), { name, guildId, channelId, selfMute, selfDeaf, selfVideo: false, selfStream: false, joinedAt: Date.now() });
    }
    return { name, ok: r.ok, error: r.ok ? null : r.error };
  }));
  ok(res, { results, summary: resultSummary(results) });
});

// POST /api/voice/leave — leave voice channel (with gateway confirmation)
app.post('/api/voice/leave', async (req, res) => {
  const { accounts, guildId } = req.body;
  const targets = normalizeVoiceTargets(accounts);
  if (!targets.length || !guildId) return fail(res, new Error('accounts and guildId required'));
  const results = await Promise.all(targets.map(async (name) => {
    const client = getVoiceClient(name);
    if (!client) return { name, ok: false, error: 'Not connected' };
    const r = await sendVoiceOpConfirmed(client, guildId, null);
    vsDel(voiceSessionKey(name, guildId));
    return { name, ok: r.ok, error: r.ok ? null : r.error };
  }));
  ok(res, { results, summary: resultSummary(results) });
});

// POST /api/voice/state — update voice state (mute/deaf/video/stream)
app.post('/api/voice/state', async (req, res) => {
  const { accounts, guildId, selfMute, selfDeaf, selfVideo, selfStream } = req.body;
  const targets = normalizeVoiceTargets(accounts);
  if (!targets.length || !guildId) return fail(res, new Error('accounts and guildId required'));
  for (const v of [selfMute, selfDeaf, selfVideo, selfStream]) {
    if (v !== undefined && typeof v !== 'boolean') return fail(res, new Error('voice state fields must be boolean'));
  }
  if (selfDeaf === true && (selfVideo === true || selfStream === true)) {
    return fail(res, new Error('Cannot enable video/stream while self-deaf is true'));
  }
  const results = await Promise.all(targets.map(async (name) => {
    const client = getVoiceClient(name);
    if (!client) return { name, ok: false, error: 'Not connected' };
    const key = voiceSessionKey(name, guildId);
    const sess = voiceSessions.get(key);
    if (!sess?.channelId) return { name, ok: false, error: 'Not connected to voice in this guild' };
    const chId = sess.channelId;
    const sm = selfMute  !== undefined ? selfMute  : (sess.selfMute  || false);
    const sd = selfDeaf  !== undefined ? selfDeaf  : (sess.selfDeaf  || false);
    const sv = selfVideo !== undefined ? selfVideo : (sess.selfVideo || false);
    const ss = selfStream!== undefined ? selfStream: (sess.selfStream|| false);
    // For state-only changes the gateway typically echoes within ~2s; reduce wait.
    const r = await sendVoiceOpConfirmed(client, guildId, chId, { selfMute: sm, selfDeaf: sd, selfVideo: sv, selfStream: ss }, 2500);
    if (r.ok) { Object.assign(sess, { selfMute: sm, selfDeaf: sd, selfVideo: sv, selfStream: ss }); persistVoice(); }
    return { name, ok: r.ok, error: r.ok ? null : r.error };
  }));
  ok(res, { results, summary: resultSummary(results) });
});

// POST /api/voice/join-all — join all connected accounts to one channel
app.post('/api/voice/join-all', async (req, res) => {
  const { guildId, channelId, selfMute = false, selfDeaf = false } = req.body;
  if (!guildId || !channelId) return fail(res, new Error('guildId and channelId required'));
  const entries = Array.from(clients.entries()).filter(([, e]) => e?.client?.ws);
  const results = await Promise.all(entries.map(async ([name, entry]) => {
    const target = validateVoiceTarget(entry.client, guildId, channelId);
    if (!target.ok) return { name, ok: false, error: target.error };
    const r = await sendVoiceOpConfirmed(entry.client, guildId, channelId, { selfMute, selfDeaf });
    if (r.ok) vsSet(voiceSessionKey(name, guildId), { name, guildId, channelId, selfMute, selfDeaf, selfVideo: false, selfStream: false, joinedAt: Date.now() });
    return { name, ok: r.ok, error: r.ok ? null : r.error };
  }));
  ok(res, { results, summary: resultSummary(results) });
});

// POST /api/voice/distribute-random — randomly distribute accounts across voice channels
app.post('/api/voice/distribute-random', async (req, res) => {
  const { accounts, guildId, channelIds } = req.body;
  if (!Array.isArray(channelIds) || !channelIds.length) return fail(res, new Error('channelIds required'));
  const targets = normalizeVoiceTargets(accounts).length ? normalizeVoiceTargets(accounts) : Array.from(clients.keys());
  const shuffled = [...channelIds].sort(() => Math.random() - 0.5);
  const results = await Promise.all(targets.map(async (name, i) => {
    const client = getVoiceClient(name);
    if (!client) return { name, ok: false, channelId: null, error: 'Not connected' };
    const channelId = shuffled[i % shuffled.length];
    const target = validateVoiceTarget(client, guildId, channelId);
    if (!target.ok) return { name, ok: false, channelId, error: target.error };
    const r = await sendVoiceOpConfirmed(client, guildId, channelId);
    if (r.ok) vsSet(voiceSessionKey(name, guildId), { name, guildId, channelId, selfMute: false, selfDeaf: false, selfVideo: false, selfStream: false, joinedAt: Date.now() });
    return { name, ok: r.ok, channelId, error: r.ok ? null : r.error };
  }));
  ok(res, { results, summary: resultSummary(results) });
});

// POST /api/voice/rotation/start — rotate between voice channels on a timer
app.post('/api/voice/rotation/start', (req, res) => {
  const { accounts, guildId, guildName, channelIds, intervalMs = 3600000, randomOrder = false } = req.body;
  if (!Array.isArray(channelIds) || channelIds.length < 2) return fail(res, new Error('At least 2 channelIds required'));
  const targets = normalizeVoiceTargets(accounts).length ? normalizeVoiceTargets(accounts) : Array.from(clients.keys());
  if (!targets.length || !guildId) return fail(res, new Error('accounts and guildId required'));
  const safeInterval = Math.max(15000, parseInt(intervalMs || 3600000) || 3600000);
  if (voiceRotations.size >= 100) return fail(res, new Error('Too many active rotations'));
  const id = `vr_${Date.now()}`;
  const rotation = {
    id, accounts: targets, guildId, guildName: guildName || guildId,
    channels: Array.from(new Set(channelIds)), intervalMs: safeInterval, randomOrder: !!randomOrder, currentIdx: 0,
    nextAt: Date.now() + safeInterval
  };

  function doRotate() {
    const chList = rotation.channels;
    let idx;
    if (rotation.randomOrder) idx = Math.floor(Math.random() * chList.length);
    else { rotation.currentIdx = (rotation.currentIdx + 1) % chList.length; idx = rotation.currentIdx; }
    const channelId = chList[idx];
    rotation.nextAt = Date.now() + safeInterval;
    for (const name of targets) {
      const client = getVoiceClient(name);
      if (!client) continue;
      const target = validateVoiceTarget(client, guildId, channelId);
      if (!target.ok) continue;
      sendVoiceOp(client, guildId, channelId, false, false, false, false);
      const key = voiceSessionKey(name, guildId);
      const sess = voiceSessions.get(key);
      if (sess) sess.channelId = channelId;
      else vsSet(key, { name, guildId, channelId, selfMute: false, selfDeaf: false, selfVideo: false, selfStream: false, joinedAt: Date.now() });
    }
  }

  // Join initial channel
  const firstChannel = rotation.channels[0];
  for (const name of targets) {
    const client = getVoiceClient(name);
    if (!client) continue;
    const target = validateVoiceTarget(client, guildId, firstChannel);
    if (!target.ok) continue;
    sendVoiceOp(client, guildId, firstChannel, false, false, false, false);
    vsSet(voiceSessionKey(name, guildId), { name, guildId, channelId: firstChannel, selfMute: false, selfDeaf: false, selfVideo: false, selfStream: false, joinedAt: Date.now() });
  }

  rotation.timer = setInterval(doRotate, safeInterval);
  voiceRotations.set(id, rotation);
  ok(res, { id, message: 'Rotation started', intervalMs: safeInterval, channels: rotation.channels.length, accounts: targets.length });
});

// POST /api/voice/rotation/stop
app.post('/api/voice/rotation/stop', (req, res) => {
  const { id } = req.body;
  const rot = voiceRotations.get(id);
  if (!rot) return fail(res, new Error('Rotation not found'));
  clearInterval(rot.timer);
  voiceRotations.delete(id);
  ok(res, { ok: true });
});

// POST /api/voice/state-cycle/start — cycle voice states on a timer
app.post('/api/voice/state-cycle/start', (req, res) => {
  const { accounts, guildId, states, intervalMs = 3600000 } = req.body;
  // states: array of objects { selfMute, selfDeaf, selfVideo, selfStream }
  if (!Array.isArray(states) || states.length < 2) return fail(res, new Error('At least 2 states required'));
  const targets = normalizeVoiceTargets(accounts).length ? normalizeVoiceTargets(accounts) : Array.from(clients.keys());
  if (!targets.length || !guildId) return fail(res, new Error('accounts and guildId required'));
  const safeStates = states.map(s => ({
    selfMute: !!s?.selfMute, selfDeaf: !!s?.selfDeaf, selfVideo: !!s?.selfVideo, selfStream: !!s?.selfStream
  }));
  const safeInterval = Math.max(15000, parseInt(intervalMs || 3600000) || 3600000);
  if (voiceStateCycles.size >= 100) return fail(res, new Error('Too many active cycles'));
  const id = `vsc_${Date.now()}`;
  const cycle = { id, accounts: targets, guildId, states: safeStates, intervalMs: safeInterval, currentIdx: 0, nextAt: Date.now() + safeInterval };

  function applyState() {
    cycle.currentIdx = (cycle.currentIdx + 1) % safeStates.length;
    const s = safeStates[cycle.currentIdx];
    cycle.nextAt = Date.now() + safeInterval;
    for (const name of targets) {
      const client = getVoiceClient(name);
      if (!client) continue;
      const key = voiceSessionKey(name, guildId);
      const sess = voiceSessions.get(key);
      const chId = sess?.channelId || null;
      if (!chId) continue;
      sendVoiceOp(client, guildId, chId, !!s.selfMute, !!s.selfDeaf, !!s.selfVideo, !!s.selfStream);
      if (sess) Object.assign(sess, { selfMute: !!s.selfMute, selfDeaf: !!s.selfDeaf, selfVideo: !!s.selfVideo, selfStream: !!s.selfStream });
    }
  }

  // Apply first state immediately
  const s0 = safeStates[0];
  for (const name of targets) {
    const client = getVoiceClient(name);
    if (!client) continue;
    const key = voiceSessionKey(name, guildId);
    const sess = voiceSessions.get(key);
    const chId = sess?.channelId || null;
    if (!chId) continue;
    sendVoiceOp(client, guildId, chId, !!s0.selfMute, !!s0.selfDeaf, !!s0.selfVideo, !!s0.selfStream);
    if (sess) Object.assign(sess, { selfMute: !!s0.selfMute, selfDeaf: !!s0.selfDeaf, selfVideo: !!s0.selfVideo, selfStream: !!s0.selfStream });
  }

  cycle.timer = setInterval(applyState, safeInterval);
  voiceStateCycles.set(id, cycle);
  ok(res, { id, message: 'State cycle started', intervalMs: safeInterval, states: safeStates.length, accounts: targets.length });
});

// POST /api/voice/state-cycle/stop
app.post('/api/voice/state-cycle/stop', (req, res) => {
  const { id } = req.body;
  const cycle = voiceStateCycles.get(id);
  if (!cycle) return fail(res, new Error('Cycle not found'));
  clearInterval(cycle.timer);
  voiceStateCycles.delete(id);
  ok(res, { ok: true });
});

app.listen(PORT, '0.0.0.0', async () => {
  const banner = `
╔══════════════════════════════════════════════════╗
║  Discord Account Manager — by Ahmed (@4_3a)      ║
║  Local URL : http://localhost:${PORT}                ║
╚══════════════════════════════════════════════════╝
`;
  console.log(banner);

  // Auto-connect saved tokens (non-blocking)
  autoConnectSaved();

  // Open browser only when running locally (not on Replit)
  const isReplit = !!(process.env.REPL_ID || process.env.REPLIT_DEV_DOMAIN || process.env.REPL_SLUG);
  if (!isReplit && !process.env.NO_OPEN) {
    const url = `http://localhost:${PORT}`;
    const cmd = process.platform === 'win32' ? `start "" "${url}"`
      : process.platform === 'darwin' ? `open "${url}"`
      : `xdg-open "${url}"`;
    exec(cmd, () => {});
  }
});
