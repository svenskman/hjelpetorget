// VERSION: 0.2.0
'use strict';

const express   = require('express');
const session   = require('express-session');
const path      = require('path');
const fs        = require('fs');
const crypto    = require('crypto');
const zlib      = require('zlib');
const https     = require('https');
const rateLimit = require('express-rate-limit');
const multer    = require('multer');

// ── Config ────────────────────────────────────────────────────────────────────
const GITHUB_REPO         = process.env.GITHUB_REPO         || 'svenskman/hjelpetorget';
const GITHUB_TOKEN        = process.env.GITHUB_TOKEN        || '';
const MAX_RELEASES        = 5;
const IS_LAB              = process.env.IS_LAB === 'true'   || process.env.IS_LAB === '1';
const PORTAINER_URL       = process.env.PORTAINER_URL       || '';
const PORTAINER_TOKEN     = process.env.PORTAINER_TOKEN     || '';
const PORTAINER_ENV_ID    = parseInt(process.env.PORTAINER_ENV_ID || '1');
const PORTAINER_CONTAINER = process.env.PORTAINER_CONTAINER || 'hjelpetorget';
const PORTAINER_LAB_CONTAINER = process.env.PORTAINER_LAB_CONTAINER || 'hjelpetorget-lab';
const DATA_DIR            = process.env.DATA_DIR            || './data';
const PORT                = parseInt(process.env.PORT       || '3000');
const BASE                = process.env.BASE_DOMAIN         || 'hjelpetorget.no';
const ADMIN_HOURS         = 4;

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Auto-version ──────────────────────────────────────────────────────────────
function computeVersion() {
  const FILES = ['server.js','db.js','utils.js','session-store.js','content-filter.js',
    'routes/auth.js','routes/posts.js','routes/profile.js','routes/messages.js','public/index.html'];
  const hash = crypto.createHash('sha256');
  for (const f of FILES) {
    try { hash.update(fs.readFileSync(path.join(__dirname, f))); } catch {}
  }
  return new Date().toISOString().slice(0,10).replace(/-/g,'') + '-' + hash.digest('hex').slice(0,8);
}
const APP_VERSION = computeVersion();

// ── DB & utils ────────────────────────────────────────────────────────────────
require('./db');
const db = require('./db');
const { UPLOADS_DIR, AVATARS_DIR, requireAuth, requireAdmin, notify } = require('./utils');

// ── Express setup ─────────────────────────────────────────────────────────────
const app       = express();
const labMulter = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300, standardHeaders: true }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true }));

const SqliteStore = require('./session-store');
app.use(session({
  store: new SqliteStore(),
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false, saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'lax', maxAge: 30 * 24 * 3600 * 1000 },
}));

// Block suspended/banned users
app.use('/api', (req, res, next) => {
  if (!req.session || !req.session.userId) return next();
  const user = db.prepare('SELECT trust_status FROM users WHERE id=?').get(req.session.userId);
  if (!user) return next();
  if (user.trust_status === 'banned') {
    req.session.destroy(() => {});
    return res.status(403).json({ error: 'Kontoen din er permanent deaktivert. Kontakt support.' });
  }
  if (user.trust_status === 'suspended') {
    const u = db.prepare('SELECT suspend_reason, suspended_at FROM users WHERE id=?').get(req.session.userId);
    return res.status(403).json({ error: 'Kontoen din er midlertidig suspendert.', reason: u.suspend_reason, suspended_at: u.suspended_at });
  }
  next();
});

// Expire temp admin sessions (prod only)
app.use((req, res, next) => {
  if (!IS_LAB && req.session && req.session.adminUntil && Date.now() > req.session.adminUntil) {
    req.session.role = 'admin'; // keep DB role, just clear timer
    req.session.adminUntil = null;
  }
  next();
});

app.use('/uploads', express.static(UPLOADS_DIR, { maxAge: '7d' }));
app.use('/avatars', express.static(AVATARS_DIR, { maxAge: '7d' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/api/auth',     require('./routes/auth'));
app.use('/api/posts',    require('./routes/posts'));
app.use('/api/profile',  require('./routes/profile'));
app.use('/api/messages', require('./routes/messages'));

// ── Admin helpers ─────────────────────────────────────────────────────────────
function adminLog(userId, userName, action, target, detail) {
  const { v4: uuidv4 } = require('uuid');
  try {
    db.prepare('INSERT INTO admin_log (id,user_id,user_name,action,target,detail) VALUES (?,?,?,?,?,?)')
      .run(uuidv4(), userId, userName, action, target || null, detail || null);
  } catch {}
}

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

// ── Admin-on-demand (prod only) ───────────────────────────────────────────────
setInterval(() => {
  if (IS_LAB) return;
  const now = Math.floor(Date.now() / 1000);
  const expired = db.prepare("SELECT * FROM admin_requests WHERE status='approved' AND expires_at <= ?").all(now);
  for (const r of expired) {
    db.prepare("UPDATE admin_requests SET status='expired' WHERE id=?").run(r.id);
    const u = db.prepare('SELECT name FROM users WHERE id=?').get(r.user_id);
    if (u) adminLog(r.user_id, u.name, 'ADMIN_EXPIRED', null, ADMIN_HOURS + 't utløpt');
  }
}, 60000);

app.post('/api/admin-request', requireAuth, (req, res) => {
  if (IS_LAB) return res.status(400).json({ error: 'Ikke tilgjengelig i lab' });
  const { reason } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Kun admin-brukere kan be om tilgang' });
  const existing = db.prepare("SELECT id FROM admin_requests WHERE user_id=? AND status='pending'").get(req.session.userId);
  if (existing) return res.status(409).json({ error: 'Du har allerede en ventende forespørsel' });
  const { v4: uuidv4 } = require('uuid');
  const id = uuidv4();
  db.prepare('INSERT INTO admin_requests (id,user_id,reason) VALUES (?,?,?)').run(id, req.session.userId, reason || '');
  const admins = db.prepare("SELECT id,email,name FROM users WHERE role='admin' AND id!=?").all(req.session.userId);
  const { sendMail } = require('./utils');
  for (const a of admins) {
    notify(a.id, 'admin_request', { request_id: id, requester: user.name, reason: reason || '' });
    sendMail({ to: a.email, subject: '🔐 Admin-tilgang forespurt av ' + user.name,
      html: '<p><strong>' + user.name + '</strong> ber om midlertidig admin-tilgang i ' + ADMIN_HOURS + ' timer.</p>' +
            (reason ? '<p>Begrunnelse: ' + reason + '</p>' : '') }).catch(() => {});
  }
  res.json({ ok: true, message: 'Forespørsel sendt!' });
});

app.get('/api/admin-request/pending', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT r.*,u.name as requester_name,u.email as requester_email,u.avatar as requester_avatar FROM admin_requests r JOIN users u ON r.user_id=u.id WHERE r.status=? ORDER BY r.created_at DESC').all('pending'));
});

app.post('/api/admin-request/:id/approve', requireAdmin, (req, res) => {
  const r = db.prepare("SELECT * FROM admin_requests WHERE id=? AND status='pending'").get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Ikke funnet' });
  if (r.user_id === req.session.userId) return res.status(400).json({ error: 'Kan ikke godkjenne egen forespørsel' });
  const expiresAt = Math.floor(Date.now() / 1000) + ADMIN_HOURS * 3600;
  db.prepare("UPDATE admin_requests SET status='approved',approved_by=?,approved_at=unixepoch(),expires_at=? WHERE id=?").run(req.session.userId, expiresAt, req.params.id);
  const approver  = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  const requester = db.prepare('SELECT name FROM users WHERE id=?').get(r.user_id);
  adminLog(req.session.userId, approver.name, 'ADMIN_APPROVED', r.user_id, requester.name);
  notify(r.user_id, 'admin_approved', { approved_by: approver.name, expires_hours: ADMIN_HOURS, expires_at: expiresAt });
  res.json({ ok: true, message: requester.name + ' kan nå aktivere admin-tilgang i ' + ADMIN_HOURS + ' timer.' });
});

app.post('/api/admin-request/:id/deny', requireAdmin, (req, res) => {
  const r = db.prepare("SELECT * FROM admin_requests WHERE id=? AND status='pending'").get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Ikke funnet' });
  db.prepare("UPDATE admin_requests SET status='denied',approved_by=?,approved_at=unixepoch() WHERE id=?").run(req.session.userId, req.params.id);
  const denier    = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  const requester = db.prepare('SELECT name FROM users WHERE id=?').get(r.user_id);
  adminLog(req.session.userId, denier.name, 'ADMIN_DENIED', r.user_id, requester.name);
  notify(r.user_id, 'admin_denied', { denied_by: denier.name });
  res.json({ ok: true });
});

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

app.get('/api/admin-request/log', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM admin_log ORDER BY created_at DESC LIMIT 200').all());
});

// ── Skill levels ─────────────────────────────────────────────────────────────

// Level thresholds
const LEVEL_THRESHOLDS = {
  experienced:   { completed: 2, avgRating: 4.0 },
  professional:  { completed: 10, avgRating: 4.5, mustBeHighLevel: true },
};

const LEVEL_LABELS = {
  beginner:     { label: 'Nybegynner', icon: '🌱', color: '#6AAF7C' },
  experienced:  { label: 'Erfaren',    icon: '⭐', color: '#E8C06A' },
  professional: { label: 'Profesjonell', icon: '🏆', color: '#C4613B' },
};

function getUserSkill(userId) {
  const row = db.prepare('SELECT * FROM skill_levels WHERE user_id=?').get(userId);
  if (!row) return { user_id: userId, level: 'beginner', completed: 0, avg_rating: 0 };
  return row;
}

function checkSkillPromotion(userId) {
  const skill   = getUserSkill(userId);
  const reviews = db.prepare('SELECT AVG(rating) as avg, COUNT(*) as count FROM reviews WHERE reviewee_id=?').get(userId);
  const avgRating = parseFloat((reviews.avg || 0).toFixed(2));

  // Count completed posts where user was assignee
  const completed = db.prepare("SELECT COUNT(*) as n FROM posts p JOIN post_assignments pa ON p.id=pa.post_id WHERE pa.user_id=? AND p.status='done'").get(userId).n;

  // Update stats
  db.prepare('INSERT INTO skill_levels (user_id,level,completed,avg_rating) VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET completed=?,avg_rating=?')
    .run(userId, skill.level, completed, avgRating, completed, avgRating);

  let newLevel = skill.level;

  if (skill.level === 'beginner' && completed >= LEVEL_THRESHOLDS.experienced.completed && avgRating >= LEVEL_THRESHOLDS.experienced.avgRating) {
    newLevel = 'experienced';
  }

  if (skill.level === 'experienced' && completed >= LEVEL_THRESHOLDS.professional.completed && avgRating >= LEVEL_THRESHOLDS.professional.avgRating) {
    // Check if enough high-level completions
    const highLevel = db.prepare("SELECT COUNT(*) as n FROM posts p JOIN post_assignments pa ON p.id=pa.post_id WHERE pa.user_id=? AND p.status='done' AND p.skill_level='experienced'").get(userId).n;
    if (highLevel >= 5) newLevel = 'professional';
  }

  if (newLevel !== skill.level) {
    db.prepare('UPDATE skill_levels SET level=?, promoted_at=unixepoch() WHERE user_id=?').run(newLevel, userId);
    notify(userId, 'skill_promoted', { level: newLevel, label: LEVEL_LABELS[newLevel].label, icon: LEVEL_LABELS[newLevel].icon });
    console.log('[skill] ' + userId + ' promoted to ' + newLevel);
  }

  return getUserSkill(userId);
}

// Get user skill level
app.get('/api/skill/:userId', (req, res) => {
  const skill = getUserSkill(req.params.userId);
  res.json({ ...skill, ...LEVEL_LABELS[skill.level] });
});

// Get all levels info
app.get('/api/skill/levels/info', (req, res) => {
  res.json({ levels: LEVEL_LABELS, thresholds: LEVEL_THRESHOLDS });
});

// Admin: manually set skill level
app.put('/api/skill/:userId/level', requireAdmin, (req, res) => {
  const { level } = req.body;
  if (!['beginner','experienced','professional'].includes(level)) return res.status(400).json({ error: 'Ugyldig nivå' });
  db.prepare('INSERT INTO skill_levels (user_id,level) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET level=?, promoted_at=unixepoch(), promoted_by=?')
    .run(req.params.userId, level, level, req.session.userId);
  const user = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  adminLog(req.session.userId, user.name, 'SKILL_OVERRIDE', req.params.userId, 'Satt til ' + level);
  notify(req.params.userId, 'skill_promoted', { level, label: LEVEL_LABELS[level].label, icon: LEVEL_LABELS[level].icon });
  res.json({ ok: true });
});

// Check promotion after review
app.post('/api/skill/:userId/check', requireAuth, (req, res) => {
  const skill = checkSkillPromotion(req.params.userId);
  res.json({ ...skill, ...LEVEL_LABELS[skill.level] });
});

// ── Mentor system ────────────────────────────────────────────────────────────

// Invite an apprentice to join a post (mentor must be professional)
app.post('/api/mentor/invite', requireAuth, (req, res) => {
  const { apprentice_id, post_id } = req.body;
  if (!apprentice_id || !post_id) return res.status(400).json({ error: 'Mangler lærling eller oppdrag' });

  // Check mentor is professional
  const mentorSkill = db.prepare('SELECT level FROM skill_levels WHERE user_id=?').get(req.session.userId);
  if (!mentorSkill || mentorSkill.level !== 'professional') {
    return res.status(403).json({ error: 'Kun Profesjonelle (🏆) kan ta med seg en lærling på oppdrag. Jobb deg opp til Profesjonell-nivå først!' });
  }

  // Check post exists and mentor is assigned to it
  const post = db.prepare('SELECT * FROM posts WHERE id=?').get(post_id);
  if (!post) return res.status(404).json({ error: 'Oppdrag ikke funnet' });

  const isAssigned = db.prepare('SELECT id FROM post_assignments WHERE post_id=? AND user_id=?').get(post_id, req.session.userId);
  if (!isAssigned) return res.status(403).json({ error: 'Du må være tildelt oppdraget for å ta med en lærling' });

  // Check apprentice is not already on this post
  const alreadyOn = db.prepare('SELECT id FROM mentorships WHERE post_id=? AND apprentice_id=? AND status=?').get(post_id, apprentice_id, 'active');
  if (alreadyOn) return res.status(409).json({ error: 'Denne lærlingen er allerede med på oppdraget' });

  // Check apprentice skill - warn if not beginner/experienced (anyone can be apprentice)
  const apprentice = db.prepare('SELECT id, name FROM users WHERE id=?').get(apprentice_id);
  if (!apprentice) return res.status(404).json({ error: 'Lærling ikke funnet' });

  const { v4: uuidv4 } = require('uuid');
  db.prepare('INSERT INTO mentorships (id,mentor_id,apprentice_id,post_id,status) VALUES (?,?,?,?,?)').run(uuidv4(), req.session.userId, apprentice_id, post_id, 'active');

  const mentor = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  notify(apprentice_id, 'mentorship_invite', {
    mentor_name: mentor.name,
    post_id,
    post_title: post.title,
    message: mentor.name + ' inviterer deg med som lærling på oppdraget "' + post.title + '"',
  });

  res.json({ ok: true, message: apprentice.name + ' er nå med som lærling på oppdraget!' });
});

// Get mentorships for a post
app.get('/api/mentor/post/:postId', requireAuth, (req, res) => {
  const mentorships = db.prepare('SELECT m.*, u.name as apprentice_name, u.avatar as apprentice_avatar, m2.name as mentor_name FROM mentorships m JOIN users u ON m.apprentice_id=u.id JOIN users m2 ON m.mentor_id=m2.id WHERE m.post_id=? AND m.status=?').all(req.params.postId, 'active');
  res.json(mentorships);
});

// Get my mentorships (as mentor or apprentice)
app.get('/api/mentor/my', requireAuth, (req, res) => {
  const asMentor     = db.prepare('SELECT m.*,u.name as other_name,u.avatar as other_avatar,p.title as post_title FROM mentorships m JOIN users u ON m.apprentice_id=u.id JOIN posts p ON m.post_id=p.id WHERE m.mentor_id=? AND m.status=?').all(req.session.userId, 'active');
  const asApprentice = db.prepare('SELECT m.*,u.name as other_name,u.avatar as other_avatar,p.title as post_title FROM mentorships m JOIN users u ON m.mentor_id=u.id JOIN posts p ON m.post_id=p.id WHERE m.apprentice_id=? AND m.status=?').all(req.session.userId, 'active');
  res.json({ asMentor, asApprentice });
});

// End a mentorship
app.post('/api/mentor/:id/end', requireAuth, (req, res) => {
  const m = db.prepare('SELECT * FROM mentorships WHERE id=?').get(req.params.id);
  if (!m) return res.status(404).json({ error: 'Mentorskap ikke funnet' });
  if (m.mentor_id !== req.session.userId && m.apprentice_id !== req.session.userId) return res.status(403).json({ error: 'Ikke tilgang' });
  db.prepare('UPDATE mentorships SET status=?,ended_at=unixepoch() WHERE id=?').run('ended', req.params.id);
  res.json({ ok: true });
});

// ── Trust & safety system ────────────────────────────────────────────────────
const REPORT_AUTO_SUSPEND = 3; // auto-suspend after X reports

// Report a user
app.post('/api/report/user/:id', requireAuth, (req, res) => {
  const { reason, detail } = req.body;
  if (!reason) return res.status(400).json({ error: 'Begrunnelse er påkrevd' });
  if (req.params.id === req.session.userId) return res.status(400).json({ error: 'Kan ikke rapportere deg selv' });

  const reported = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!reported) return res.status(404).json({ error: 'Bruker ikke funnet' });

  const { v4: uuidv4 } = require('uuid');
  try {
    db.prepare('INSERT INTO user_reports (id,reporter_id,reported_id,reason,detail) VALUES (?,?,?,?,?)')
      .run(uuidv4(), req.session.userId, req.params.id, reason, detail || '');
  } catch {
    return res.status(409).json({ error: 'Du har allerede rapportert denne brukeren' });
  }

  // Increment report count
  const newCount = (reported.report_count || 0) + 1;
  db.prepare('UPDATE users SET report_count=? WHERE id=?').run(newCount, req.params.id);

  // Auto-suspend if threshold reached
  if (newCount >= REPORT_AUTO_SUSPEND && reported.trust_status === 'active') {
    db.prepare("UPDATE users SET trust_status='suspended', suspended_at=unixepoch(), suspend_reason=? WHERE id=?")
      .run('Automatisk suspendert etter ' + newCount + ' rapporter', req.params.id);
    // Notify admins
    const admins = db.prepare("SELECT id FROM users WHERE role='admin'").all();
    const reporter = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
    for (const a of admins) {
      notify(a.id, 'user_auto_suspended', {
        reported_name: reported.name, reported_id: req.params.id,
        report_count: newCount, latest_reason: reason,
      });
    }
  }

  // Always notify admins of reports
  const admins = db.prepare("SELECT id FROM users WHERE role='admin'").all();
  for (const a of admins) {
    notify(a.id, 'user_reported', {
      reported_id: req.params.id, reported_name: reported.name,
      reason, report_count: newCount,
    });
  }

  res.json({ ok: true, message: 'Rapport sendt til admin. Takk for at du hjelper oss å holde tjenesten trygg.' });
});

// Get reports for admin - includes full network context
app.get('/api/admin/reports', requireAdmin, (req, res) => {
  const reports = db.prepare(`
    SELECT r.*, u1.name as reporter_name, u2.name as reported_name,
      u2.trust_status, u2.report_count, u2.email as reported_email,
      u2.vouched_by, u2.approved_by
    FROM user_reports r
    JOIN users u1 ON r.reporter_id = u1.id
    JOIN users u2 ON r.reported_id = u2.id
    WHERE r.status = 'pending'
    ORDER BY r.created_at DESC
  `).all();

  // Enrich each report with network info
  const enriched = reports.map(r => {
    // Who vouched for the reported user (their inviter)
    const vouchedByUser = r.vouched_by
      ? db.prepare('SELECT id, name, email, trust_status FROM users WHERE id=?').get(r.vouched_by)
      : null;

    // Who has the inviter also vouched for (siblings in network)
    const inviterNetwork = vouchedByUser
      ? db.prepare(`SELECT u.id, u.name, u.email, u.trust_status, u.report_count
          FROM vouches v JOIN users u ON v.vouchee_id = u.id
          WHERE v.voucher_id = ? AND v.vouchee_id != ?`).all(r.vouched_by, r.reported_id)
      : [];

    // Who has the reported user vouched for (their invitees)
    const invitedByReported = db.prepare(`
      SELECT u.id, u.name, u.email, u.trust_status, u.report_count
      FROM vouches v JOIN users u ON v.vouchee_id = u.id
      WHERE v.voucher_id = ?`).all(r.reported_id);

    return { ...r, vouchedByUser, inviterNetwork, invitedByReported };
  });

  res.json(enriched);
});

// Admin: approve/suspend/ban/restore user
app.post('/api/admin/users/:id/trust', requireAdmin, (req, res) => {
  const { action, reason } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Bruker ikke funnet' });
  const admin = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);

  const actions = {
    approve:  () => { db.prepare("UPDATE users SET trust_status='active', approved_by=? WHERE id=?").run(req.session.userId, req.params.id); notify(req.params.id, 'account_approved', { approved_by: admin.name }); },
    suspend:  () => { db.prepare("UPDATE users SET trust_status='suspended', suspended_at=unixepoch(), suspend_reason=? WHERE id=?").run(reason || 'Suspendert av admin', req.params.id); notify(req.params.id, 'account_suspended', { reason: reason || '' }); },
    ban:      () => { db.prepare("UPDATE users SET trust_status='banned' WHERE id=?").run(req.params.id); notify(req.params.id, 'account_banned', {}); },
    restore:  () => { db.prepare("UPDATE users SET trust_status='active', suspended_at=NULL, suspend_reason=NULL, report_count=0 WHERE id=?").run(req.params.id); notify(req.params.id, 'account_restored', { by: admin.name }); },
    verify:   () => { db.prepare("UPDATE users SET trust_status='verified', bankid_verified=1 WHERE id=?").run(req.params.id); notify(req.params.id, 'account_verified', {}); },
  };

  if (!actions[action]) return res.status(400).json({ error: 'Ugyldig handling' });
  actions[action]();
  adminLog(req.session.userId, admin.name, 'USER_' + action.toUpperCase(), req.params.id, reason || user.name);
  res.json({ ok: true });
});

// Admin: dismiss report
app.post('/api/admin/reports/:id/dismiss', requireAdmin, (req, res) => {
  db.prepare("UPDATE user_reports SET status='dismissed' WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

// Admin: pending users (trust_status = pending/vouched)
app.get('/api/admin/pending-users', requireAdmin, (req, res) => {
  const users = db.prepare("SELECT u.*, v.voucher_id, u2.name as voucher_name FROM users u LEFT JOIN vouches v ON v.vouchee_id=u.id LEFT JOIN users u2 ON v.voucher_id=u2.id WHERE u.trust_status IN ('pending','vouched') ORDER BY u.created_at DESC").all();
  res.json(users);
});

// Vouch for a user
app.post('/api/vouch/:id', requireAuth, (req, res) => {
  const voucher = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);
  if (!voucher || !['active','verified'].includes(voucher.trust_status))
    return res.status(403).json({ error: 'Du må selv være aktiv og verifisert for å gå god for andre' });

  const vouchee = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!vouchee) return res.status(404).json({ error: 'Bruker ikke funnet' });
  if (vouchee.trust_status !== 'pending') return res.status(400).json({ error: 'Denne brukeren trenger ikke vouch' });

  const { v4: uuidv4 } = require('uuid');
  try {
    db.prepare('INSERT INTO vouches (id,voucher_id,vouchee_id,note) VALUES (?,?,?,?)').run(uuidv4(), req.session.userId, req.params.id, req.body.note || '');
  } catch { return res.status(409).json({ error: 'Du har allerede gått god for denne brukeren' }); }

  db.prepare("UPDATE users SET trust_status='vouched', vouched_by=? WHERE id=?").run(req.session.userId, req.params.id);

  // Notify admins
  const admins = db.prepare("SELECT id FROM users WHERE role='admin'").all();
  for (const a of admins) notify(a.id, 'user_vouched', { voucher_name: voucher.name, vouchee_name: vouchee.name, vouchee_id: vouchee.id });

  notify(req.params.id, 'you_were_vouched', { voucher_name: voucher.name });
  res.json({ ok: true, message: 'Du har gått god for ' + vouchee.name + '. Admin vil nå vurdere å aktivere kontoen.' });
});

// Get vouch status for current user
app.get('/api/vouch/status', requireAuth, (req, res) => {
  const user = db.prepare('SELECT trust_status, vouched_by, approved_by, bankid_verified, report_count, suspended_at, suspend_reason FROM users WHERE id=?').get(req.session.userId);
  res.json(user);
});

// ── Changelog (admin only) ───────────────────────────────────────────────────
app.get('/api/admin/changelog', requireAdmin, (req, res) => {
  try {
    const cl = require('fs').readFileSync(require('path').join(__dirname, 'CHANGELOG.md'), 'utf8');
    res.json({ content: cl });
  } catch { res.status(404).json({ error: 'Changelog ikke funnet' }); }
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

// ── GitHub helpers ────────────────────────────────────────────────────────────
const _ghHeaders = () => ({
  'Authorization': 'token ' + GITHUB_TOKEN,
  'Accept': 'application/vnd.github.v3+json',
  'User-Agent': 'Hjelpetorget',
  'Content-Type': 'application/json',
});

async function ghGet(p) {
  const r = await fetch('https://api.github.com/repos/' + GITHUB_REPO + '/contents/' + p, { headers: _ghHeaders() });
  return r.ok ? r.json() : null;
}

async function ghPut(p, content, message, sha) {
  const body = { message, content: Buffer.isBuffer(content) ? content.toString('base64') : Buffer.from(content).toString('base64') };
  if (sha) body.sha = sha;
  const r = await fetch('https://api.github.com/repos/' + GITHUB_REPO + '/contents/' + p, { method: 'PUT', headers: _ghHeaders(), body: JSON.stringify(body) });
  if (!r.ok) { const e = await r.json(); throw new Error(e.message || r.status); }
  return r.json();
}

async function ghDelete(p, message, sha) {
  const r = await fetch('https://api.github.com/repos/' + GITHUB_REPO + '/contents/' + p, { method: 'DELETE', headers: _ghHeaders(), body: JSON.stringify({ message, sha }) });
  return r.ok;
}

async function ghListDir(dir) {
  const r = await fetch('https://api.github.com/repos/' + GITHUB_REPO + '/contents/' + dir, { headers: _ghHeaders() });
  if (!r.ok) return [];
  const d = await r.json();
  return Array.isArray(d) ? d : [];
}

async function getManifest() {
  const f = await ghGet('manifest.json');
  if (!f) return null;
  try { return JSON.parse(Buffer.from(f.content.replace(/\n/g, ''), 'base64').toString()); } catch { return null; }
}

// ── Lab status ────────────────────────────────────────────────────────────────
app.get('/api/lab/status', requireAdmin, (req, res) => {
  const FILES = ['server.js','db.js','utils.js','session-store.js','content-filter.js','package.json',
    'routes/auth.js','routes/posts.js','routes/profile.js','routes/messages.js','public/index.html'];

  function extractVersion(buf, name) {
    const text = buf.slice(0, 300).toString('utf8');
    if (name === 'package.json') { try { return JSON.parse(buf.toString('utf8')).version || null; } catch { return null; } }
    const m = name.endsWith('.html') ? text.match(/<!-- VERSION: ([\d.]+) -->/) : text.match(/\/\/ VERSION: ([\d.]+)/);
    return m ? m[1] : null;
  }

  const files = FILES.map(f => {
    try {
      const fp  = path.join(process.cwd(), f);
      const buf = fs.readFileSync(fp);
      const st  = fs.statSync(fp);
      return { name: f, size: buf.length, modified: Math.floor(st.mtimeMs / 1000),
               sha256: crypto.createHash('sha256').update(buf).digest('hex').slice(0, 12),
               version: extractVersion(buf, f) };
    } catch { return { name: f, size: 0, modified: 0, sha256: null, version: null }; }
  });

  const versions = files.filter(f => f.sha256 && f.version).map(f => f.version);
  const syncVer  = versions.length > 0 && versions.every(v => v === versions[0]) ? versions[0] : null;
  for (const f of files) f.ok = !!(f.sha256 && f.version && syncVer && f.version === syncVer);

  res.json({ isLab: IS_LAB, version: APP_VERSION, syncVersion: syncVer,
    uptime: Math.floor(process.uptime()), node: process.version,
    portainerConfigured: !!(PORTAINER_URL && PORTAINER_TOKEN),
    githubConfigured: !!GITHUB_TOKEN, container: PORTAINER_CONTAINER, files });
});

// ── Lab upload ────────────────────────────────────────────────────────────────
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
      saveFile(f.fieldname && f.fieldname.includes('/') ? f.fieldname : f.originalname, f.buffer);
    }
  }
  if (!uploaded.length && errors.length) return res.status(400).json({ error: errors.join(' | ') });
  res.json({ ok: true, uploaded, errors, message: uploaded.length + ' fil(er) lastet opp. Restart for å aktivere.' });
});

// ── Lab restart ───────────────────────────────────────────────────────────────
app.post('/api/lab/restart', requireAdmin, async (req, res) => {
  if (!IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig på lab-instansen' });
  if (PORTAINER_URL && PORTAINER_TOKEN) {
    try {
      await portainerAction(PORTAINER_CONTAINER, 'restart');
      return res.json({ ok: true, method: 'portainer', message: 'Restartes via Portainer. Laster om om 8 sek.' });
    } catch (e) { console.warn('[lab] Portainer feilet:', e.message); }
  }
  res.json({ ok: true, method: 'exit', message: 'Restarter om 2 sek…' });
  setTimeout(() => process.exit(0), 2000);
});

// ── Lab publish to GitHub ─────────────────────────────────────────────────────
app.post('/api/lab/publish', requireAdmin, async (req, res) => {
  if (!IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig på lab-instansen' });
  if (!GITHUB_TOKEN) return res.status(400).json({ error: 'GITHUB_TOKEN ikke konfigurert' });
  const { changelog } = req.body;
  const version = APP_VERSION;
  const FILES = ['server.js','db.js','utils.js','session-store.js','content-filter.js','package.json',
    'routes/auth.js','routes/posts.js','routes/profile.js','routes/messages.js','public/index.html'];
  const steps = [];
  try {
    const releaseDir = 'releases/' + version;
    for (const file of FILES) {
      const fp = path.join(process.cwd(), file);
      if (!fs.existsSync(fp)) { steps.push('⚠️ Mangler: ' + file); continue; }
      const buf = fs.readFileSync(fp);
      const existing = await ghGet(releaseDir + '/' + file);
      await ghPut(releaseDir + '/' + file, buf, 'Release ' + version + ': ' + file, existing && existing.sha);
      steps.push('✅ ' + file);
    }
    const existingManifest = await ghGet('manifest.json');
    let manifest = { current: version, releases: [] };
    if (existingManifest) {
      try { manifest = JSON.parse(Buffer.from(existingManifest.content.replace(/\n/g, ''), 'base64').toString()); } catch {}
    }
    manifest.releases = (manifest.releases || []).filter(r => r.version !== version);
    manifest.releases.unshift({ version, published_at: new Date().toISOString(), changelog: changelog || '' });
    const toDelete = manifest.releases.slice(MAX_RELEASES);
    manifest.releases = manifest.releases.slice(0, MAX_RELEASES);
    manifest.current = version;
    await ghPut('manifest.json', JSON.stringify(manifest, null, 2), 'Manifest: ' + version, existingManifest && existingManifest.sha);
    steps.push('✅ manifest.json');
    for (const old of toDelete) {
      for (const subdir of ['', 'routes', 'public']) {
        const dir = 'releases/' + old.version + (subdir ? '/' + subdir : '');
        const oldFiles = await ghListDir(dir);
        for (const f of oldFiles) if (f.type === 'file') await ghDelete(f.path, 'Cleanup ' + old.version, f.sha).catch(() => {});
      }
      steps.push('🗑️ Slettet: ' + old.version);
    }
    res.json({ ok: true, version, steps, message: 'v' + version + ' publisert til GitHub!' });
  } catch (e) { res.status(500).json({ error: e.message, steps }); }
});

// ── Update check & apply (prod) ───────────────────────────────────────────────
app.get('/api/update/check', requireAdmin, async (req, res) => {
  if (!GITHUB_TOKEN) return res.json({ available: false, reason: 'GITHUB_TOKEN ikke konfigurert' });
  try {
    const manifest = await getManifest();
    if (!manifest) return res.json({ available: false, reason: 'Ingen manifest på GitHub' });
    res.json({ available: manifest.current !== APP_VERSION, current: APP_VERSION, latest: manifest.current, releases: manifest.releases || [] });
  } catch (e) { res.json({ available: false, reason: e.message }); }
});

app.post('/api/update/apply', requireAdmin, async (req, res) => {
  if (!GITHUB_TOKEN) return res.status(400).json({ error: 'GITHUB_TOKEN ikke konfigurert' });
  const { version } = req.body;
  const manifest = await getManifest();
  if (!manifest) return res.status(404).json({ error: 'Ingen manifest funnet' });
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

// ── Lab control (from prod) ───────────────────────────────────────────────────
const _portainerAgent = new https.Agent({ rejectUnauthorized: false });
function portainerFetch(url, opts) {
  const options = opts || {};
  if (url.startsWith('https://')) options.agent = _portainerAgent;
  return fetch(url, options);
}
async function portainerGetContainer(name) {
  if (!PORTAINER_URL || !PORTAINER_TOKEN) throw new Error('Portainer ikke konfigurert (sett PORTAINER_URL og PORTAINER_TOKEN i prod-stacken)');
  const r = await portainerFetch(PORTAINER_URL + '/api/endpoints/' + PORTAINER_ENV_ID + '/docker/containers/json?all=true', { headers: { 'X-API-Key': PORTAINER_TOKEN } });
  if (!r.ok) throw new Error('Portainer API feil: ' + r.status);
  const containers = await r.json();
  const c = containers.find(x => (x.Names || []).some(n => n.replace(/^\//, '') === name));
  if (!c) throw new Error('Container "' + name + '" ikke funnet');
  return c;
}
async function portainerAction(containerName, action) {
  const c = await portainerGetContainer(containerName);
  const r = await portainerFetch(PORTAINER_URL + '/api/endpoints/' + PORTAINER_ENV_ID + '/docker/containers/' + c.Id + '/' + action, { method: 'POST', headers: { 'X-API-Key': PORTAINER_TOKEN } });
  if (!r.ok) throw new Error('Portainer ' + action + ' feilet: ' + r.status);
  return { ok: true };
}

app.get('/api/lab-control/status', requireAdmin, async (req, res) => {
  if (IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig fra prod' });
  try {
    const c = await portainerGetContainer(PORTAINER_LAB_CONTAINER);
    const manifest = await getManifest().catch(() => null);
    res.json({ ok: true, container: { name: PORTAINER_LAB_CONTAINER, state: c.State, status: c.Status, image: c.Image, id: c.Id.slice(0,12) }, manifest });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/lab-control/restart', requireAdmin, async (req, res) => {
  if (IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig fra prod' });
  const user = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  try {
    await portainerAction(PORTAINER_LAB_CONTAINER, 'restart');
    adminLog(req.session.userId, user.name, 'LAB_RESTART', PORTAINER_LAB_CONTAINER, 'Via prod-admin');
    res.json({ ok: true, message: 'Lab restartet.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/lab-control/deploy', requireAdmin, async (req, res) => {
  if (IS_LAB) return res.status(400).json({ error: 'Kun tilgjengelig fra prod' });
  if (!GITHUB_TOKEN) return res.status(400).json({ error: 'GITHUB_TOKEN ikke konfigurert' });
  const { version } = req.body;
  if (!version) return res.status(400).json({ error: 'Versjon er påkrevd' });
  const user = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  const manifest = await getManifest().catch(() => null);
  if (!manifest) return res.status(404).json({ error: 'Ingen manifest på GitHub' });
  const exists = (manifest.releases || []).some(r => r.version === version);
  if (!exists) return res.status(404).json({ error: 'Versjon ikke funnet: ' + version });
  const steps = [];
  try {
    const pendingPath = 'pending-deploy.json';
    const existing = await ghGet(pendingPath);
    await ghPut(pendingPath, JSON.stringify({ version, requested_by: user.name, requested_at: new Date().toISOString() }, null, 2), 'Pending deploy: ' + version, existing && existing.sha);
    steps.push('✅ pending-deploy.json skrevet til GitHub');
    await portainerAction(PORTAINER_LAB_CONTAINER, 'restart');
    steps.push('✅ Lab restartet via Portainer');
    adminLog(req.session.userId, user.name, 'LAB_DEPLOY', version, 'Gjenoppretter lab');
    res.json({ ok: true, version, steps, message: 'Lab gjenopprettes til v' + version + '. Ferdig om ca. 30 sek.' });
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
    const fnLen   = buf.readUInt16LE(i + 26);
    const exLen   = buf.readUInt16LE(i + 28);
    const raw     = buf.slice(i + 30, i + 30 + fnLen).toString('utf8');
    const dataStart = i + 30 + fnLen + exLen;
    const data    = buf.slice(dataStart, dataStart + compSz);
    i = dataStart + compSz;
    if (raw.endsWith('/')) continue;
    const parts = raw.split('/');
    const name  = ALLOWED.includes(parts.slice(1).join('/')) ? parts.slice(1).join('/') : ALLOWED.includes(raw) ? raw : null;
    if (!name) continue;
    result[name] = comp === 8 ? zlib.inflateRawSync(data) : data;
  }
  if (!Object.keys(result).length) throw new Error('ZIP inneholder ingen kjente filer');
  return result;
}

// ── SPA fallback ──────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'For stor fil (maks 10MB)' });
  console.error(err);
  res.status(500).json({ error: 'Intern serverfeil' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('✅ Hjelpetorget v' + APP_VERSION + ' kjører på port ' + PORT + (IS_LAB ? ' [🧪 LAB]' : ''));
  console.log('   Data: ' + DATA_DIR + ' | Node: ' + process.version);

  // Lab: check for pending deploy
  if (IS_LAB && GITHUB_TOKEN) {
    setTimeout(async () => {
      try {
        const pendingFile = await ghGet('pending-deploy.json');
        if (!pendingFile) return;
        const pending = JSON.parse(Buffer.from(pendingFile.content.replace(/\n/g, ''), 'base64').toString());
        if (!pending.version) return;

        // Check local marker to avoid re-apply loop
        const markerPath = path.join(DATA_DIR, '_last_deployed');
        let lastDeployed = '';
        try { lastDeployed = fs.readFileSync(markerPath, 'utf8').trim(); } catch {}
        if (lastDeployed === pending.version) {
          await ghDelete('pending-deploy.json', 'Clear already-deployed pending', pendingFile.sha).catch(() => {});
          console.log('[lab] Versjon ' + pending.version + ' allerede installert, sletter pending.');
          return;
        }

        console.log('[lab] Pending deploy: ' + pending.version);
        const FILES = ['server.js','db.js','utils.js','session-store.js','content-filter.js','package.json',
          'routes/auth.js','routes/posts.js','routes/profile.js','routes/messages.js','public/index.html'];
        let applied = 0;
        for (const file of FILES) {
          try {
            const ghFile = await ghGet('releases/' + pending.version + '/' + file);
            if (!ghFile) continue;
            const buf  = Buffer.from(ghFile.content.replace(/\n/g, ''), 'base64');
            const dest = path.join(process.cwd(), file);
            const bkDir = path.join(DATA_DIR, '_backup_pending');
            fs.mkdirSync(bkDir, { recursive: true });
            if (fs.existsSync(dest)) fs.copyFileSync(dest, path.join(bkDir, file.replace(/\//g, '_')));
            fs.mkdirSync(path.dirname(dest), { recursive: true });
            fs.writeFileSync(dest, buf);
            applied++;
          } catch (e) { console.warn('[lab] Feil ved ' + file + ':', e.message); }
        }
        if (applied > 0) {
          fs.writeFileSync(markerPath, pending.version, 'utf8');
          await ghDelete('pending-deploy.json', 'Clear pending after deploy ' + pending.version, pendingFile.sha).catch(() => {});
          console.log('[lab] Deploy fullført (' + applied + ' filer). Restarter om 3 sek…');
          setTimeout(() => process.exit(0), 3000);
        } else {
          await ghDelete('pending-deploy.json', 'Clear failed pending', pendingFile.sha).catch(() => {});
          console.warn('[lab] Ingen filer installert, sletter pending.');
        }
      } catch (e) { console.warn('[lab] Pending deploy feilet:', e.message); }
    }, 5000); // Wait 5 sec after startup before checking
  }
});
