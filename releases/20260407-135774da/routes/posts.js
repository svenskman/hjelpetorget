// VERSION: 0.2.0
'use strict';
const express = require('express');
const path    = require('path');
const fs      = require('fs');
const { v4: uuidv4 } = require('uuid');
const db      = require('../db');
const { requireAuth, upload, resizePostImage, notify, sendMail, UPLOADS_DIR } = require('../utils');
const { analyzeContent } = require('../content-filter');
const router  = express.Router();

const POST_SQL = `
  SELECT p.*, u.name as author_name, u.avatar as author_avatar,
    c.name as category_name, c.icon as category_icon, c.color as category_color,
    c.parent_id as category_parent_id,
    pc.name as parent_category_name, pc.icon as parent_category_icon,
    (SELECT COUNT(*) FROM messages m JOIN conversations cv ON m.conversation_id=cv.id WHERE cv.post_id=p.id) as reply_count
  FROM posts p JOIN users u ON p.user_id=u.id
  LEFT JOIN categories c ON p.category_id=c.id
  LEFT JOIN categories pc ON c.parent_id=pc.id
`;

function withImages(posts) {
  const arr = Array.isArray(posts) ? posts : [posts];
  for (const p of arr) p.images = db.prepare('SELECT filename FROM post_images WHERE post_id=? ORDER BY ord').all(p.id).map(r => r.filename);
  return posts;
}

router.get('/meta/locations', (req, res) => {
  const rows = db.prepare("SELECT fylke, kommune, COUNT(*) as count FROM posts WHERE status='open' AND fylke IS NOT NULL GROUP BY fylke, kommune ORDER BY fylke, kommune").all();
  const tree = {};
  for (const r of rows) {
    if (!tree[r.fylke]) tree[r.fylke] = { count: 0, kommuner: {} };
    tree[r.fylke].count += r.count;
    if (r.kommune) tree[r.fylke].kommuner[r.kommune] = (tree[r.fylke].kommuner[r.kommune] || 0) + r.count;
  }
  res.json(tree);
});

router.get('/meta/categories', (req, res) => {
  const cats = db.prepare('SELECT * FROM categories ORDER BY id').all();
  for (const c of cats) c.count = db.prepare("SELECT COUNT(*) as n FROM posts WHERE category_id=? AND status='open'").get(c.id).n;
  res.json(cats);
});

router.get('/', (req, res) => {
  const { type, category, q, page = 1, limit = 20 } = req.query;
  const where = ["p.status='open'", 'p.flagged=0'];
  const params = [];
  if (type && ['offer','request'].includes(type)) { where.push('p.type=?'); params.push(type); }
  if (category) { where.push('c.slug=?'); params.push(category); }
  if (q && q.trim()) { where.push('(p.title LIKE ? OR p.body LIKE ?)'); params.push('%'+q+'%','%'+q+'%'); }
  if (req.query.fylke === 'digital') { where.push("p.fylke='digital'"); }
  else if (req.query.fylke) { where.push('p.fylke=?'); params.push(req.query.fylke);
    if (req.query.kommune) { where.push('p.kommune=?'); params.push(req.query.kommune); } }
  const offset = (Math.max(1, parseInt(page)) - 1) * parseInt(limit);
  const w = 'WHERE ' + where.join(' AND ');
  const posts = db.prepare(POST_SQL + w + ' ORDER BY p.created_at DESC LIMIT ? OFFSET ?').all(...params, parseInt(limit), offset);
  const total = db.prepare('SELECT COUNT(*) as n FROM posts p LEFT JOIN categories c ON p.category_id=c.id ' + w).get(...params);
  withImages(posts);
  res.json({ posts, total: total.n, page: parseInt(page), pages: Math.ceil(total.n / limit) });
});

router.get('/:id', (req, res) => {
  const post = db.prepare(POST_SQL + 'WHERE p.id=?').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Ikke funnet' });
  withImages(post);
  res.json(post);
});

router.post('/', requireAuth, upload.array('images', 4), async (req, res) => {
  const { type, title, body, category_id, location } = req.body;
  if (!type || !title || !body) return res.status(400).json({ error: 'Type, tittel og beskrivelse er påkrevd' });
  if (!['offer','request'].includes(type)) return res.status(400).json({ error: 'Ugyldig type' });
  if (title.trim().length > 120) return res.status(400).json({ error: 'Tittel kan ikke være lengre enn 120 tegn' });
  if (body.trim().length > 2000) return res.status(400).json({ error: 'Beskrivelse kan ikke være lengre enn 2000 tegn' });

  const id = uuidv4();
  const emailToken = require('crypto').randomBytes(16).toString('hex');
  const { fylke, kommune, skill_level } = req.body;
  const postSkillLevel = ['any','experienced','professional'].includes(skill_level) ? skill_level : 'any';
  // Sanitize fylke/kommune - only allow alphanumeric, spaces, Norwegian chars, hyphens
  const SAFE_RE = /^[a-zA-Z0-9æøåÆØÅ\s\-\.]+$/;
  const safeFylke  = fylke && SAFE_RE.test(fylke)   ? fylke.slice(0, 50)   : null;
  const safeKommune = kommune && SAFE_RE.test(kommune) ? kommune.slice(0, 60) : null;
  db.prepare('INSERT INTO posts (id,user_id,category_id,type,title,body,location,email_token,fylke,kommune,skill_level) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    .run(id, req.session.userId, category_id || null, type, title.trim().slice(0,120), body.trim().slice(0,2000), (location||'').slice(0,100), emailToken, safeFylke, safeKommune, postSkillLevel);

  if (req.files && req.files.length) {
    for (let i = 0; i < req.files.length; i++) {
      const filename = 'post_' + id + '_' + i + '.webp';
      await resizePostImage(req.files[i].path, filename);
      fs.unlinkSync(req.files[i].path);
      db.prepare('INSERT INTO post_images (post_id,filename,ord) VALUES (?,?,?)').run(id, filename, i);
    }
  }

  const filter = analyzeContent(title.trim(), body.trim());
  if (filter.flagged) {
    db.prepare('UPDATE posts SET flagged=1, flag_reasons=? WHERE id=?').run(JSON.stringify(filter.reasons), id);
    const admins = db.prepare("SELECT id,email FROM users WHERE role='admin'").all();
    for (const a of admins) {
      notify(a.id, 'post_flagged', { post_id: id, post_title: title.trim(), severity: filter.severity });
    }
  }

  res.status(201).json({ ok: true, id });
});

router.patch('/:id', requireAuth, upload.array('images', 4), async (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id=?').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Ikke funnet' });
  if (post.user_id !== req.session.userId && req.session.role !== 'admin') return res.status(403).json({ error: 'Ikke tilgang' });
  if (post.status === 'done') return res.status(400).json({ error: 'Kan ikke redigere fullført annonse' });

  db.prepare('UPDATE posts SET title=?,body=?,location=?,category_id=?,status=?,updated_at=unixepoch() WHERE id=?').run(
    req.body.title || post.title,
    req.body.body  || post.body,
    req.body.location !== undefined ? req.body.location : post.location,
    req.body.category_id !== undefined ? req.body.category_id : post.category_id,
    req.body.status && ['open','closed','done'].includes(req.body.status) ? req.body.status : post.status,
    req.params.id
  );

  if (req.body.remove_images) {
    const toRemove = Array.isArray(req.body.remove_images) ? req.body.remove_images : [req.body.remove_images];
    for (const f of toRemove) {
      db.prepare('DELETE FROM post_images WHERE post_id=? AND filename=?').run(req.params.id, f);
      try { fs.unlinkSync(path.join(UPLOADS_DIR, f)); } catch {}
    }
  }
  if (req.files && req.files.length) {
    const existing = db.prepare('SELECT COUNT(*) as n FROM post_images WHERE post_id=?').get(req.params.id).n;
    for (let i = 0; i < req.files.length && existing + i < 8; i++) {
      const filename = 'post_' + req.params.id + '_' + Date.now() + '_' + i + '.webp';
      await resizePostImage(req.files[i].path, filename);
      fs.unlinkSync(req.files[i].path);
      db.prepare('INSERT INTO post_images (post_id,filename,ord) VALUES (?,?,?)').run(req.params.id, filename, existing + i);
    }
  }
  res.json({ ok: true });
});

router.delete('/:id', requireAuth, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id=?').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Ikke funnet' });
  if (post.user_id !== req.session.userId && req.session.role !== 'admin') return res.status(403).json({ error: 'Ikke tilgang' });
  db.prepare('DELETE FROM posts WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

module.exports = router;
