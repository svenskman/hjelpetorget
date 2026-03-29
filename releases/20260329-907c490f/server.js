// VERSION: 0.2.0
'use strict';

const express   = require('express');
const session   = require('express-session');
const path      = require('path');
const fs        = require('fs');
const crypto    = require('crypto');
const zlib      = require('zlib');
const rateLimit = require('express-rate-limit');
const multer    = require('multer');

const GITHUB_REPO  = process.env.GITHUB_REPO  || 'svenskman/hjelpetorget';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const MAX_RELEASES = 5;

// Auto-generate version from content hash of all source files
function computeVersion() {
  const FILES = ['server.js','db.js','utils.js','session-store.js','content-filter.js',
    'routes/auth.js','routes/posts.js','routes/profile.js','routes/messages.js','public/index.html'];
  const hash = crypto.createHash('sha256');
  for (const f of FILES) {
    try { hash.update(fs.readFileSync(path.join(__dirname, f))); } catch {}
  }
  const short = hash.digest('hex').slice(0, 8);
  const date  = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  return date + '-' + short;
}

const APP_VERSION = computeVersion();


const IS_LAB              = process.env.IS_LAB === 'true' || process.env.IS_LAB === '1';
const PORTAINER_URL       = process.env.PORTAINER_URL || '';
const PORTAINER_TOKEN     = process.env.PORTAINER_TOKEN || '';
const PORTAINER_ENV_ID    = parseInt(process.env.PORTAINER_ENV_ID || '1');
const PORTAINER_CONTAINER = process.env.PORTAINER_CONTAINER || 'hjelpetorget';
const PORTAINER_LAB_CONTAINER = process.env.PORTAINER_LAB_CONTAINER || 'hjelpetorget-lab';

// ── Portainer helpers ─────────────────────────────────────────────────────────
async function portainerGetContainer(name) {
  if (!PORTAINER_URL || !PORTAINER_TOKEN) throw new Error('Portainer ikke konfigurert');
  const r = await fetch(PORTAINER_URL + '/api/endpoints/' + PORTAINER_ENV_ID + '/docker/containers/json?all=true',
    { headers: { 'X-API-Key': PORTAINER_TOKEN } });
  if (!r.ok) throw new Error('Portainer feil: ' + r.status);
  const containers = await r.json();
  const c = containers.find(x => (x.Names || []).some(n => n.replace(/^\//, '') === name));
  if (!c) throw new Error('Container "' + name + '" ikke funnet');
  return c;
}

async function portainerAction(containerName, action) {
  const c = await portainerGetContainer(containerName);
  const r = await fetch(PORTAINER_URL + '/api/endpoints/' + PORTAINER_ENV_ID + '/docker/containers/' + c.Id + '/' + action,
    { method: 'POST', headers: { 'X-API-Key': PORTAINER_TOKEN } });
  if (!r.ok) throw new Error('Portainer ' + action + ' feilet: ' + r.status);
  return { ok: true, containerId: c.Id, state: c.State };
}

async function portainerInspect(containerName) {
  const c = await portainerGetContainer(containerName);
  return {
    name:    containerName,
    state:   c.State,
    status:  c.Status,
    image:   c.Image,
    created: c.Created,
    id:      c.Id.slice(0, 12),
  };
}
const DATA_DIR            = process.env.DATA_DIR || './data';
const PORT                = parseInt(process.env.PORT || '3000');
const BASE                = process.env.BASE_DOMAIN || 'hjelpetorget.no';

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

require('./db');
const { UPLOADS_DIR, AVATARS_DIR, requireAuth, requireAdmin, notify } = require('./utils');
const db = require('./db');

const app = express();
const labMulter = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

const SqliteStore = require('./session-store');
app.use(session({
  store: new SqliteStore(),
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false, saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'lax', maxAge: 30 * 24 * 3600 * 1000 },
}));

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300, standardHeaders: true }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true }));

app.use('/uploads', express.static(UPLOADS_DIR, { maxAge: '7d' }));
app.use('/avatars', express.static(AVATARS_DIR, { maxAge: '7d' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/auth',    require('./routes/auth'));
app.use('/api/posts',   require('./routes/posts'));
app.use('/api/profile', require('./routes/profile'));
app.use('/api/messages',require('./routes/messages'));

// ── Admin API ─────────────────────────────────────────────────────────────────
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  res.json({
    users:    db.prepare('SELECT COUNT(*) as n FROM users').get().n,
    posts:    db.prepare("SELECT COUNT(*) as n FROM posts WHERE status='open'").get().n,
    messages: db.prepare('SELECT COUNT(*) as n FROM messages').get().n,
    reviews:  db.prepare('SELECT COUNT(*) as n FROM reviews').get().n,
    flagged:  db.prepare('SELECT COUNT(*) as n FROM posts WHERE flagged=1 AND flag_reviewed=0').get().n,
  });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT id,email,name,verified,role,created_at FROM users ORDER BY created_at DESC').all());
});

app.put('/api/admin/users/:id/role', requireAdmin, (req, res) => {
  const { role } = req.body;
  if (!['user','admin'].includes(role)) return res.status(400).json({ error: 'Ugyldig rolle' });
  db.prepare('UPDATE users SET role=? WHERE id=?').run(role, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/posts/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM posts WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/categories', requireAdmin, (req, res) => {
  const cats = db.prepare('SELECT * FROM categories ORDER BY id').all();
  for (const c of cats) c.count = db.prepare("SELECT COUNT(*) as n FROM posts WHERE category_id=?").get(c.id).n;
  res.json(cats);
});

app.post('/api/admin/categories', requireAdmin, (req, res) => {
  const { name, slug, icon, color } = req.body;
  if (!name || !slug || !icon) return res.status(400).json({ error: 'Navn, slug og ikon er påkrevd' });
  try {
    db.prepare('INSERT INTO categories (slug,name,icon,color) VALUES (?,?,?,?)').run(slug, name, icon, color || '#AAAAAA');
    res.json({ ok: true });
  } catch { res.status(409).json({ error: 'Slug er allerede i bruk' }); }
});

app.put('/api/admin/categories/:id', requireAdmin, (req, res) => {
  const { name, icon, color } = req.body;
  db.prepare('UPDATE categories SET name=?,icon=?,color=? WHERE id=?').run(name, icon, color || '#AAAAAA', req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/categories/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM categories WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/flagged', requireAdmin, (req, res) => {
  const posts = db.prepare('SELECT p.*,u.name as author_name,u.email as author_email FROM posts p JOIN users u ON p.user_id=u.id WHERE p.flagged=1 AND p.flag_reviewed=0 ORDER BY p.created_at DESC').all();
  res.json(posts.map(p => ({ ...p, flag_reasons: JSON.parse(p.flag_reasons || '[]') })));
});

app.post('/api/admin/flagged/:id/approve', requireAdmin, (req, res) => {
  db.prepare('UPDATE posts SET flag_reviewed=1, flagged=0 WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.post('/api/admin/flagged/:id/remove', requireAdmin, (req, res) => {
  const post = db.prepare('SELECT user_id FROM posts WHERE id=?').get(req.params.id);
  if (post) notify(post.user_id, 'post_removed', { post_id: req.params.id });
  db.prepare('DELETE FROM posts WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ── Admin audit log helper ────────────────────────────────────────────────────
function adminLog(userId, userName, action, target, detail) {
  const { v4: uuidv4 } = require('uuid');
  try {
    db.prepare('INSERT INTO admin_log (id,user_id,user_name,action,target,detail) VALUES (?,?,?,?,?,?)')
      .run(uuidv4(), userId, userName, action, target || null, detail || null);
  } catch (e) { console.error('[adminlog]', e.message); }
}

// Wrap requireAdmin to also log
function requireAdminLogged(action) {
  return (req, res, next) => {
    if (!req.session || req.session.role !== 'admin') return res.status(403).json({ error: 'Ikke tilgang' });
    req._adminAction = action;
    next();
  };
}

const ADMIN_HOURS = 4;

// Auto-expire session admin access
app.use((req, res, next) => {
  if (req.session && req.session.adminUntil && Date.now() > req.session.adminUntil) {
    req.session.role = 'user';
    req.session.adminUntil = null;
  }
  next();
});

// Auto-expire approved requests
setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  const expired = db.prepare("SELECT * FROM admin_requests WHERE status='approved' AND expires_at <= ?").all(now);
  for (const r of expired) {
    db.prepare("UPDATE admin_requests SET status='expired' WHERE id=?").run(r.id);
    const u = db.prepare('SELECT name FROM users WHERE id=?').get(r.user_id);
    if (u) adminLog(r.user_id, u.name, 'ADMIN_EXPIRED', null, ADMIN_HOURS + 't utløpt');
  }
}, 60000);

// Request admin access
app.post('/api/admin-request', requireAuth, (req, res) => {
  const { reason } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Kun admin-brukere kan be om tilgang' });
  const existing = db.prepare("SELECT id FROM admin_requests WHERE user_id=? AND status='pending'").get(req.session.userId);
  if (existing) return res.status(409).json({ error: 'Du har allerede en ventende forespørsel' });
  const { v4: uuidv4 } = require('uuid');
  const id = uuidv4();
  db.prepare('INSERT INTO admin_requests (id,user_id,reason) VALUES (?,?,?)').run(id, req.session.userId, reason || '');
  const admins = db.prepare("SELECT id,email,name FROM users WHERE role='admin' AND id!=?").all(req.session.userId);
  const { sendMail, notify } = require('./utils');
  for (const a of admins) {
    notify(a.id, 'admin_request', { request_id: id, requester: user.name, reason: reason || '' });
    sendMail({ to: a.email, subject: '🔐 Admin-tilgang forespurt av ' + user.name,
      html: '<p><strong>' + user.name + '</strong> ber om midlertidig admin-tilgang i ' + ADMIN_HOURS + ' timer.</p>' +
            (reason ? '<p>Begrunnelse: ' + reason + '</p>' : '') +
            '<p>Logg inn og gå til Admin → Tilgangsforespørsler for å godkjenne.</p>'
    }).catch(e => console.warn('[req-mail]', e.message));
  }
  res.json({ ok: true, message: 'Forespørsel sendt!' });
});

// Get pending requests
app.get('/api/admin-request/pending', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT r.*,u.name as requester_name,u.email as requester_email,u.avatar as requester_avatar FROM admin_requests r JOIN users u ON r.user_id=u.id WHERE r.status=? ORDER BY r.created_at DESC').all('pending');
  res.json(rows);
});

// Approve request
app.post('/api/admin-request/:id/approve', requireAdmin, (req, res) => {
  const r = db.prepare("SELECT * FROM admin_requests WHERE id=? AND status='pending'").get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Ikke funnet eller allerede behandlet' });
  if (r.user_id === req.session.userId) return res.status(400).json({ error: 'Kan ikke godkjenne egen forespørsel' });
  const expiresAt = Math.floor(Date.now() / 1000) + ADMIN_HOURS * 3600;
  db.prepare("UPDATE admin_requests SET status='approved',approved_by=?,approved_at=unixepoch(),expires_at=? WHERE id=?").run(req.session.userId, expiresAt, req.params.id);
  const approver = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  const requester = db.prepare('SELECT name FROM users WHERE id=?').get(r.user_id);
  adminLog(req.session.userId, approver.name, 'ADMIN_APPROVED', r.user_id, requester.name);
  const { notify } = require('./utils');
  notify(r.user_id, 'admin_approved', { approved_by: approver.name, expires_hours: ADMIN_HOURS, expires_at: expiresAt });
  res.json({ ok: true, message: requester.name + ' kan nå aktivere admin-tilgang i ' + ADMIN_HOURS + ' timer.' });
});

// Deny request
app.post('/api/admin-request/:id/deny', requireAdmin, (req, res) => {
  const r = db.prepare("SELECT * FROM admin_requests WHERE id=? AND status='pending'").get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Ikke funnet' });
  db.prepare("UPDATE admin_requests SET status='denied',approved_by=?,approved_at=unixepoch() WHERE id=?").run(req.session.userId, req.params.id);
  const denier = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  const requester = db.prepare('SELECT name FROM users WHERE id=?').get(r.user_id);
  adminLog(req.session.userId, denier.name, 'ADMIN_DENIED', r.user_id, requester.name);
  const { notify } = require('./utils');
  notify(r.user_id, 'admin_denied', { denied_by: denier.name });
  res.json({ ok: true });
});

// Activate approved access in session
app.post('/api/admin-request/:id/activate', requireAuth, (req, res) => {
  const r = db.prepare("SELECT * FROM admin_requests WHERE id=? AND user_id=? AND status='approved'").get(req.params.id, req.session.userId);
  if (!r) return res.status(404).json({ error: 'Ingen godkjent forespørsel' });
  if (r.expires_at < Math.floor(Date.now() / 1000)) {
    db.prepare("UPDATE admin_requests SET status='expired' WHERE id=?").run(req.params.id);
    return res.status(410).json({ error: 'Tilgangen er utløpt' });
  }
  req.session.role = 'admin';
  req.session.adminUntil = r.expires_at * 1000;
  const user = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  adminLog(req.session.userId, user.name, 'ADMIN_ACTIVATED', null, 'Utløper ' + new Date(r.expires_at * 1000).toLocaleString('no'));
  res.json({ ok: true, adminUntil: r.expires_at, message: 'Admin-tilgang aktivert i ' + ADMIN_HOURS + ' timer!' });
});

// Get admin log
app.get('/api/admin-request/log', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM admin_log ORDER BY created_at DESC LIMIT 200').all());
});

// ── Lab control (from prod) ───────────────────────────────────────────────────

// Get lab container status via Portainer
app.get('/api/lab-control/status', requireAdmin, async (req, res) => {
  if (IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig fra prod' });
  try {
    const info = await portainerInspect(PORTAINER_LAB_CONTAINER);
    // Also check GitHub manifest for version history
    const manifest = await getManifest().catch(() => null);
    res.json({ ok: true, container: info, manifest });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Restart lab container via Portainer
app.post('/api/lab-control/restart', requireAdmin, async (req, res) => {
  if (IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig fra prod' });
  const user = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  try {
    await portainerAction(PORTAINER_LAB_CONTAINER, 'restart');
    adminLog(req.session.userId, user.name, 'LAB_RESTART', PORTAINER_LAB_CONTAINER, 'Restartet via prod-admin');
    res.json({ ok: true, message: 'Lab-container restartet.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Deploy specific version to lab: writes files from GitHub release to lab app dir
// then restarts lab via Portainer
app.post('/api/lab-control/deploy', requireAdmin, async (req, res) => {
  if (IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig fra prod' });
  if (!GITHUB_TOKEN) return res.status(400).json({ error: 'GITHUB_TOKEN ikke konfigurert' });

  const { version } = req.body;
  if (!version) return res.status(400).json({ error: 'Versjon er påkrevd' });

  const user = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  const manifest = await getManifest().catch(() => null);
  if (!manifest) return res.status(404).json({ error: 'Ingen manifest på GitHub' });

  const releaseExists = (manifest.releases || []).some(r => r.version === version);
  if (!releaseExists) return res.status(404).json({ error: 'Versjon ikke funnet: ' + version });

  const FILES = ['server.js','db.js','utils.js','session-store.js','content-filter.js','package.json',
    'routes/auth.js','routes/posts.js','routes/profile.js','routes/messages.js','public/index.html'];
  const releaseDir = 'releases/' + version;
  const steps = [];

  // Determine lab app dir from Portainer volume info
  // Convention: lab runs at same base as prod but in hjelpetorget-lab subfolder
  const prodDir = process.cwd(); // e.g. /app
  // Lab dir is sibling on host: derive from DATA_DIR pattern
  // We write to a staging file that lab reads on restart
  // Simpler: use GitHub → lab fetches on its own restart via /api/update/apply

  // Write a "pending deploy" record to GitHub so lab picks it up
  try {
    const pendingPath = 'pending-deploy.json';
    const existing = await ghGet(pendingPath);
    await ghPut(pendingPath,
      JSON.stringify({ version, requested_by: user.name, requested_at: new Date().toISOString() }, null, 2),
      'Pending deploy: ' + version + ' (requested by ' + user.name + ')',
      existing && existing.sha
    );
    steps.push('✅ Pending deploy skrevet til GitHub');

    // Restart lab via Portainer so it picks up the pending deploy
    await portainerAction(PORTAINER_LAB_CONTAINER, 'restart');
    steps.push('✅ Lab-container restartet via Portainer');

    adminLog(req.session.userId, user.name, 'LAB_DEPLOY', version, 'Gjenoppretter lab til versjon ' + version);
    res.json({ ok: true, version, steps, message: 'Lab gjenopprettes til v' + version + '. Ferdig om ca. 30 sek.' });
  } catch (e) { res.status(500).json({ error: e.message, steps }); }
});

// ── Breakglass ────────────────────────────────────────────────────────────────
// ── Lab control (from prod) ───────────────────────────────────────────────────

// Get lab container status via Portainer
app.get('/api/lab-control/status', requireAdmin, async (req, res) => {
  if (IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig fra prod' });
  try {
    const info = await portainerInspect(PORTAINER_LAB_CONTAINER);
    // Also check GitHub manifest for version history
    const manifest = await getManifest().catch(() => null);
    res.json({ ok: true, container: info, manifest });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Restart lab container via Portainer
app.post('/api/lab-control/restart', requireAdmin, async (req, res) => {
  if (IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig fra prod' });
  const user = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  try {
    await portainerAction(PORTAINER_LAB_CONTAINER, 'restart');
    adminLog(req.session.userId, user.name, 'LAB_RESTART', PORTAINER_LAB_CONTAINER, 'Restartet via prod-admin');
    res.json({ ok: true, message: 'Lab-container restartet.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Deploy specific version to lab: writes files from GitHub release to lab app dir
// then restarts lab via Portainer
app.post('/api/lab-control/deploy', requireAdmin, async (req, res) => {
  if (IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig fra prod' });
  if (!GITHUB_TOKEN) return res.status(400).json({ error: 'GITHUB_TOKEN ikke konfigurert' });

  const { version } = req.body;
  if (!version) return res.status(400).json({ error: 'Versjon er påkrevd' });

  const user = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  const manifest = await getManifest().catch(() => null);
  if (!manifest) return res.status(404).json({ error: 'Ingen manifest på GitHub' });

  const releaseExists = (manifest.releases || []).some(r => r.version === version);
  if (!releaseExists) return res.status(404).json({ error: 'Versjon ikke funnet: ' + version });

  const FILES = ['server.js','db.js','utils.js','session-store.js','content-filter.js','package.json',
    'routes/auth.js','routes/posts.js','routes/profile.js','routes/messages.js','public/index.html'];
  const releaseDir = 'releases/' + version;
  const steps = [];

  // Determine lab app dir from Portainer volume info
  // Convention: lab runs at same base as prod but in hjelpetorget-lab subfolder
  const prodDir = process.cwd(); // e.g. /app
  // Lab dir is sibling on host: derive from DATA_DIR pattern
  // We write to a staging file that lab reads on restart
  // Simpler: use GitHub → lab fetches on its own restart via /api/update/apply

  // Write a "pending deploy" record to GitHub so lab picks it up
  try {
    const pendingPath = 'pending-deploy.json';
    const existing = await ghGet(pendingPath);
    await ghPut(pendingPath,
      JSON.stringify({ version, requested_by: user.name, requested_at: new Date().toISOString() }, null, 2),
      'Pending deploy: ' + version + ' (requested by ' + user.name + ')',
      existing && existing.sha
    );
    steps.push('✅ Pending deploy skrevet til GitHub');

    // Restart lab via Portainer so it picks up the pending deploy
    await portainerAction(PORTAINER_LAB_CONTAINER, 'restart');
    steps.push('✅ Lab-container restartet via Portainer');

    adminLog(req.session.userId, user.name, 'LAB_DEPLOY', version, 'Gjenoppretter lab til versjon ' + version);
    res.json({ ok: true, version, steps, message: 'Lab gjenopprettes til v' + version + '. Ferdig om ca. 30 sek.' });
  } catch (e) { res.status(500).json({ error: e.message, steps }); }
});

// ── Breakglass ────────────────────────────────────────────────────────────────
app.post('/api/breakglass', (req, res) => {
  const { token } = req.body;
  const valid = [process.env.BREAKGLASS_1, process.env.BREAKGLASS_2, process.env.BREAKGLASS_3].filter(Boolean);
  if (!token || !valid.includes(token)) return res.status(403).json({ error: 'Ugyldig token' });
  req.session.userId = 'breakglass';
  req.session.role   = 'admin';
  res.json({ ok: true });
});

// ── Lab: status ───────────────────────────────────────────────────────────────
app.get('/api/lab/status', requireAdmin, (req, res) => {
  const FILES = ['server.js','db.js','utils.js','session-store.js','content-filter.js','package.json',
    'routes/auth.js','routes/posts.js','routes/profile.js','routes/messages.js','public/index.html'];

  function extractVersion(buf, name) {
    const text = buf.slice(0, 300).toString('utf8');
    if (name === 'package.json') {
      try { return JSON.parse(buf.toString('utf8')).version || null; } catch { return null; }
    }
    const m = name.endsWith('.html') ? text.match(/<!-- VERSION: ([\d.]+) -->/) : text.match(/\/\/ VERSION: ([\d.]+)/);
    return m ? m[1] : null;
  }

  const files = FILES.map(f => {
    try {
      const fp  = path.join(process.cwd(), f);
      const buf = fs.readFileSync(fp);
      const st  = fs.statSync(fp);
      const ver = extractVersion(buf, f);
      return { name: f, size: buf.length, modified: Math.floor(st.mtimeMs / 1000),
               sha256: crypto.createHash('sha256').update(buf).digest('hex').slice(0, 12),
               version: ver };
    } catch { return { name: f, size: 0, modified: 0, sha256: null, version: null }; }
  });

  // Files are in sync if they all share the same version tag
  const versions = files.filter(f => f.sha256 && f.version).map(f => f.version);
  const syncVer  = versions.length > 0 && versions.every(v => v === versions[0]) ? versions[0] : null;
  for (const f of files) { f.ok = !!(f.sha256 && f.version && syncVer && f.version === syncVer); }

  res.json({
    isLab: IS_LAB, version: APP_VERSION, syncVersion: syncVer,
    uptime: Math.floor(process.uptime()),
    node: process.version, portainerConfigured: !!(PORTAINER_URL && PORTAINER_TOKEN),
    githubConfigured: !!GITHUB_TOKEN, container: PORTAINER_CONTAINER, files,
  });
});

// ── Lab: upload ───────────────────────────────────────────────────────────────
app.post('/api/lab/upload', requireAdmin, labMulter.any(), (req, res) => {
  if (!IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig på lab-instansen' });
  const ALLOWED = ['server.js','db.js','utils.js','session-store.js','content-filter.js','package.json',
    'routes/auth.js','routes/posts.js','routes/profile.js','routes/messages.js','public/index.html'];
  const files = req.files || [];
  if (!files.length) return res.status(400).json({ error: 'Ingen filer mottatt' });
  const uploaded = [], errors = [];
  const backupDir = path.join(DATA_DIR, '_backup');
  fs.mkdirSync(backupDir, { recursive: true });

  function saveFile(rel, buf) {
    if (!ALLOWED.includes(rel)) { errors.push('Ikke tillatt: ' + rel); return; }
    const dest = path.resolve(process.cwd(), rel);
    try {
      if (fs.existsSync(dest)) fs.copyFileSync(dest, path.join(backupDir, rel.replace(/\//g, '_')));
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, buf);
      uploaded.push({ name: rel, size: buf.length, sha256: crypto.createHash('sha256').update(buf).digest('hex') });
    } catch (e) { errors.push('Feil ved ' + rel + ': ' + e.message); }
  }

  for (const f of files) {
    if (f.originalname.toLowerCase().endsWith('.zip')) {
      try { for (const [n, b] of Object.entries(extractZip(f.buffer))) saveFile(n, b); }
      catch (e) { errors.push('ZIP: ' + e.message); }
    } else {
      const rel = f.fieldname && f.fieldname.includes('/') ? f.fieldname : f.originalname;
      saveFile(rel, f.buffer);
    }
  }
  if (!uploaded.length && errors.length) return res.status(400).json({ error: errors.join(' | ') });
  res.json({ ok: true, uploaded, errors, message: uploaded.length + ' fil(er) lastet opp. Restart for å aktivere.' });
});

// ── Lab: restart ──────────────────────────────────────────────────────────────
app.post('/api/lab/restart', requireAdmin, async (req, res) => {
  if (!IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig på lab-instansen' });
  if (PORTAINER_URL && PORTAINER_TOKEN) {
    try {
      const listRes = await fetch(PORTAINER_URL + '/api/endpoints/' + PORTAINER_ENV_ID + '/docker/containers/json?all=true', { headers: { 'X-API-Key': PORTAINER_TOKEN } });
      const containers = await listRes.json();
      const c = containers.find(x => (x.Names||[]).some(n => n.replace(/^\//, '') === PORTAINER_CONTAINER));
      if (!c) throw new Error('Container ikke funnet');
      await fetch(PORTAINER_URL + '/api/endpoints/' + PORTAINER_ENV_ID + '/docker/containers/' + c.Id + '/restart', { method: 'POST', headers: { 'X-API-Key': PORTAINER_TOKEN } });
      return res.json({ ok: true, method: 'portainer', message: 'Restartes via Portainer. Laster om om 8 sek.' });
    } catch (e) { console.warn('[lab] Portainer feilet:', e.message); }
  }
  res.json({ ok: true, method: 'exit', message: 'Restarter om 2 sek…' });
  setTimeout(() => process.exit(0), 2000);
});

// ── GitHub helper ─────────────────────────────────────────────────────────────
async function ghGet(path_) {
  const r = await fetch('https://api.github.com/repos/' + GITHUB_REPO + '/contents/' + path_,
    { headers: { 'Authorization': 'token ' + GITHUB_TOKEN, 'User-Agent': 'Hjelpetorget', 'Accept': 'application/vnd.github.v3+json' } });
  return r.ok ? r.json() : null;
}

async function ghPut(path_, content, message, sha) {
  const body = { message, content: Buffer.isBuffer(content) ? content.toString('base64') : Buffer.from(content).toString('base64') };
  if (sha) body.sha = sha;
  const r = await fetch('https://api.github.com/repos/' + GITHUB_REPO + '/contents/' + path_, {
    method: 'PUT',
    headers: { 'Authorization': 'token ' + GITHUB_TOKEN, 'User-Agent': 'Hjelpetorget',
                'Accept': 'application/vnd.github.v3+json', 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) { const e = await r.json(); throw new Error(e.message || r.status); }
  return r.json();
}

async function ghDelete(path_, message, sha) {
  const r = await fetch('https://api.github.com/repos/' + GITHUB_REPO + '/contents/' + path_, {
    method: 'DELETE',
    headers: { 'Authorization': 'token ' + GITHUB_TOKEN, 'User-Agent': 'Hjelpetorget',
                'Accept': 'application/vnd.github.v3+json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, sha }),
  });
  return r.ok;
}

async function ghListDir(dir) {
  const r = await fetch('https://api.github.com/repos/' + GITHUB_REPO + '/contents/' + dir,
    { headers: { 'Authorization': 'token ' + GITHUB_TOKEN, 'User-Agent': 'Hjelpetorget', 'Accept': 'application/vnd.github.v3+json' } });
  if (!r.ok) return [];
  const d = await r.json();
  return Array.isArray(d) ? d : [];
}

// ── Lab: publish to GitHub (versioned releases) ───────────────────────────────
app.post('/api/lab/publish', requireAdmin, async (req, res) => {
  if (!IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig på lab-instansen' });
  if (!GITHUB_TOKEN) return res.status(400).json({ error: 'GITHUB_TOKEN ikke konfigurert i Portainer' });

  const { changelog } = req.body;
  const version = APP_VERSION;
  const FILES = ['server.js','db.js','utils.js','session-store.js','content-filter.js','package.json',
    'routes/auth.js','routes/posts.js','routes/profile.js','routes/messages.js','public/index.html'];
  const steps = [];

  try {
    // 1. Upload files to releases/{version}/
    const releaseDir = 'releases/' + version;
    for (const file of FILES) {
      const fp = path.join(process.cwd(), file);
      if (!fs.existsSync(fp)) { steps.push('⚠️ Mangler: ' + file); continue; }
      const buf = fs.readFileSync(fp);
      const ghPath = releaseDir + '/' + file;
      const existing = await ghGet(ghPath);
      await ghPut(ghPath, buf, 'Release ' + version + ': ' + file, existing && existing.sha);
      steps.push('✅ ' + file);
    }

    // 2. Update manifest.json with new version + history
    const manifestPath = 'manifest.json';
    const existingManifest = await ghGet(manifestPath);
    let manifest = { current: version, releases: [] };
    if (existingManifest) {
      try { manifest = JSON.parse(Buffer.from(existingManifest.content.replace(/\n/g,''), 'base64').toString()); } catch {}
    }

    // Add new release to history, keep MAX_RELEASES
    manifest.releases = manifest.releases || [];
    manifest.releases = manifest.releases.filter(function(r) { return r.version !== version; });
    manifest.releases.unshift({ version, published_at: new Date().toISOString(), changelog: changelog || '' });

    // Prune old releases from GitHub if > MAX_RELEASES
    const toDelete = manifest.releases.slice(MAX_RELEASES);
    manifest.releases = manifest.releases.slice(0, MAX_RELEASES);
    manifest.current = version;

    await ghPut(manifestPath, JSON.stringify(manifest, null, 2), 'Manifest: release ' + version, existingManifest && existingManifest.sha);
    steps.push('✅ manifest.json oppdatert');

    // Delete old release dirs from GitHub
    for (const old of toDelete) {
      const oldDir = 'releases/' + old.version;
      const oldFiles = await ghListDir(oldDir);
      for (const f of oldFiles) await ghDelete(f.path, 'Cleanup old release ' + old.version, f.sha);
      // Also delete subdirs
      for (const subdir of ['routes', 'public']) {
        const subFiles = await ghListDir(oldDir + '/' + subdir);
        for (const f of subFiles) await ghDelete(f.path, 'Cleanup ' + old.version, f.sha);
      }
      steps.push('🗑️ Slettet gammel release: ' + old.version);
    }

    res.json({ ok: true, version, steps, message: 'v' + version + ' publisert til GitHub! (' + manifest.releases.length + '/' + MAX_RELEASES + ' releases lagret)' });
  } catch (e) { res.status(500).json({ error: e.message, steps }); }
});

// ── Prod: check for updates ──────────────────────────────────────────────────
async function getManifest() {
  const f = await ghGet('manifest.json');
  if (!f) return null;
  try { return JSON.parse(Buffer.from(f.content.replace(/\n/g, ''), 'base64').toString()); } catch { return null; }
}

app.get('/api/update/check', requireAdmin, async (req, res) => {
  if (!GITHUB_TOKEN) return res.json({ available: false, reason: 'GITHUB_TOKEN ikke konfigurert' });
  try {
    const manifest = await getManifest();
    if (!manifest) return res.json({ available: false, reason: 'Ingen manifest på GitHub' });
    const available = manifest.current !== APP_VERSION;
    res.json({ available, current: APP_VERSION, latest: manifest.current, releases: manifest.releases || [] });
  } catch (e) { res.json({ available: false, reason: e.message }); }
});

// ── Prod: apply specific version from GitHub ──────────────────────────────────
app.post('/api/update/apply', requireAdmin, async (req, res) => {
  if (!GITHUB_TOKEN) return res.status(400).json({ error: 'GITHUB_TOKEN ikke konfigurert' });
  const { version } = req.body;
  const manifest = await getManifest();
  if (!manifest) return res.status(404).json({ error: 'Ingen manifest funnet på GitHub' });

  const targetVersion = version || manifest.current;
  const releaseDir    = 'releases/' + targetVersion;
  const backupDir     = path.join(DATA_DIR, '_backup_' + APP_VERSION);
  fs.mkdirSync(backupDir, { recursive: true });

  const FILES = ['server.js','db.js','utils.js','session-store.js','content-filter.js','package.json',
    'routes/auth.js','routes/posts.js','routes/profile.js','routes/messages.js','public/index.html'];
  const steps = [];

  try {
    for (const file of FILES) {
      const ghFile = await ghGet(releaseDir + '/' + file);
      if (!ghFile) { steps.push('⚠️ Mangler: ' + file); continue; }
      const buf  = Buffer.from(ghFile.content.replace(/\n/g, ''), 'base64');
      const dest = path.join(process.cwd(), file);
      if (fs.existsSync(dest)) fs.copyFileSync(dest, path.join(backupDir, file.replace(/\//g, '_')));
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, buf);
      steps.push('✅ ' + file);
    }
    res.json({ ok: true, version: targetVersion, steps, message: 'Versjon ' + targetVersion + ' installert! Restarter om 3 sek…' });
    setTimeout(() => process.exit(0), 3000);
  } catch (e) { res.status(500).json({ error: e.message, steps }); }
});

// ── ZIP extractor ─────────────────────────────────────────────────────────────
function extractZip(buf) {
  const ALLOWED = ['server.js','db.js','utils.js','session-store.js','content-filter.js','package.json',
    'routes/auth.js','routes/posts.js','routes/profile.js','routes/messages.js','public/index.html'];
  const result = {};
  let i = 0;
  while (i < buf.length - 4) {
    if (buf.readUInt32LE(i) !== 0x04034b50) { i++; continue; }
    const comp    = buf.readUInt16LE(i + 8);
    const compSz  = buf.readUInt32LE(i + 18);
    const uncompSz= buf.readUInt32LE(i + 22);
    const fnLen   = buf.readUInt16LE(i + 26);
    const exLen   = buf.readUInt16LE(i + 28);
    const raw     = buf.slice(i + 30, i + 30 + fnLen).toString('utf8');
    const dataStart = i + 30 + fnLen + exLen;
    const data    = buf.slice(dataStart, dataStart + compSz);
    i = dataStart + compSz;
    if (raw.endsWith('/') || raw.toLowerCase().endsWith('.zip')) continue;
    const parts = raw.split('/');
    const name  = ALLOWED.includes(parts.slice(1).join('/')) ? parts.slice(1).join('/')
                : ALLOWED.includes(raw) ? raw : null;
    if (!name) continue;
    result[name] = comp === 8 ? zlib.inflateRawSync(data) : data;
  }
  if (!Object.keys(result).length) throw new Error('ZIP inneholder ingen kjente filer');
  return result;
}

// ── SPA ───────────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'For stor fil (maks 10MB)' });
  console.error(err);
  res.status(500).json({ error: 'Intern serverfeil' });
});

app.listen(PORT, async () => {
  console.log('✅ Hjelpetorget v' + APP_VERSION + ' kjører på port ' + PORT + (IS_LAB ? ' [🧪 LAB]' : ''));
  console.log('   Data: ' + DATA_DIR + ' | Node: ' + process.version);

  // Lab: check for pending deploy from prod
  if (IS_LAB && GITHUB_TOKEN) {
    try {
      const pendingFile = await ghGet('pending-deploy.json');
      if (pendingFile) {
        const pending = JSON.parse(Buffer.from(pendingFile.content.replace(/\n/g, ''), 'base64').toString());

        if (pending.version && pending.version !== APP_VERSION) {
          console.log('[lab] Pending deploy funnet: ' + pending.version + ' (forespurt av ' + pending.requested_by + ')');
          // Apply the version
          const FILES = ['server.js','db.js','utils.js','session-store.js','content-filter.js','package.json',
            'routes/auth.js','routes/posts.js','routes/profile.js','routes/messages.js','public/index.html'];
          const releaseDir = 'releases/' + pending.version;
          let applied = 0;
          for (const file of FILES) {
            try {
              const ghFile = await ghGet(releaseDir + '/' + file);
              if (!ghFile) continue;
              const buf  = Buffer.from(ghFile.content.replace(/\n/g, ''), 'base64');

              const dest = path.join(process.cwd(), file);
              const bkDir = path.join(DATA_DIR, '_backup_pending');
              require('fs').mkdirSync(bkDir, { recursive: true });
              if (require('fs').existsSync(dest)) require('fs').copyFileSync(dest, path.join(bkDir, file.replace(/\//g, '_')));
              require('fs').mkdirSync(path.dirname(dest), { recursive: true });
              require('fs').writeFileSync(dest, buf);
              applied++;
            } catch (e) { console.warn('[lab] Feil ved ' + file + ':', e.message); }
          }
          if (applied > 0) {
            // Delete pending deploy marker
            try {
              await ghDelete('pending-deploy.json', 'Clear pending deploy after applying ' + pending.version, pendingFile.sha);
            } catch {}
            console.log('[lab] Pending deploy fullført (' + applied + ' filer). Restarter om 2 sek…');
            setTimeout(() => process.exit(0), 2000);
          }
        } else if (pending.version === APP_VERSION) {
          // Already on correct version, clear pending
          await ghDelete('pending-deploy.json', 'Clear pending - already on ' + pending.version, pendingFile.sha).catch(() => {});
          console.log('[lab] Allerede på korrekt versjon ' + pending.version + ', sletter pending.');
        }
      }
    } catch (e) { console.warn('[lab] Pending deploy sjekk feilet:', e.message); }
  }
});
