// VERSION: 0.1.0
'use strict';
const express = require('express');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const { requireAuth, upload, resizeAvatar, notify, AVATARS_DIR } = require('../utils');
const router = express.Router();

router.get('/:id', (req, res) => {
  const user = db.prepare('SELECT id,name,bio,avatar,location,verified,created_at FROM users WHERE id=?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Bruker ikke funnet' });
  const posts   = db.prepare("SELECT p.*,c.name as category_name,c.icon as category_icon FROM posts p LEFT JOIN categories c ON p.category_id=c.id WHERE p.user_id=? AND p.status='open' ORDER BY p.created_at DESC LIMIT 10").all(req.params.id);
  const reviews = db.prepare('SELECT r.*,u.name as reviewer_name,u.avatar as reviewer_avatar FROM reviews r JOIN users u ON r.reviewer_id=u.id WHERE r.reviewee_id=? ORDER BY r.created_at DESC LIMIT 20').all(req.params.id);
  const avg     = db.prepare('SELECT AVG(rating) as avg, COUNT(*) as count FROM reviews WHERE reviewee_id=?').get(req.params.id);
  res.json({ ...user, posts, reviews, avgRating: avg.avg, reviewCount: avg.count });
});

router.put('/me', requireAuth, (req, res) => {
  const { name, bio, location, phone } = req.body;
  if (!name || name.trim().length < 2) return res.status(400).json({ error: 'Navn må være minst 2 tegn' });
  db.prepare('UPDATE users SET name=?,bio=?,location=?,phone=? WHERE id=?').run(name.trim(), bio||'', location||'', phone||'', req.session.userId);
  res.json({ ok: true });
});

router.post('/me/avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Ingen fil lastet opp' });
  try {
    const filename = 'avatar_' + req.session.userId + '.webp';
    await resizeAvatar(req.file.path, filename);
    fs.unlinkSync(req.file.path);
    db.prepare('UPDATE users SET avatar=? WHERE id=?').run(filename, req.session.userId);
    res.json({ ok: true, avatar: filename });
  } catch (e) { res.status(500).json({ error: 'Kunne ikke laste opp bilde' }); }
});

router.post('/:id/review', requireAuth, (req, res) => {
  const { rating, comment, post_id } = req.body;
  if (req.params.id === req.session.userId) return res.status(400).json({ error: 'Kan ikke anmelde deg selv' });
  if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Ugyldig vurdering' });
  try {
    db.prepare('INSERT INTO reviews (id,reviewer_id,reviewee_id,post_id,rating,comment) VALUES (?,?,?,?,?,?)')
      .run(uuidv4(), req.session.userId, req.params.id, post_id||null, rating, comment||'');
    notify(req.params.id, 'new_review', { rating, post_id });
    res.json({ ok: true });
  } catch { res.status(409).json({ error: 'Du har allerede anmeldt denne brukeren for dette oppdraget' }); }
});

router.get('/me/notifications', requireAuth, (req, res) => {
  const notifs = db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50').all(req.session.userId);
  res.json(notifs.map(n => ({ ...n, payload: JSON.parse(n.payload) })));
});

router.post('/me/notifications/read', requireAuth, (req, res) => {
  db.prepare('UPDATE notifications SET read=1 WHERE user_id=?').run(req.session.userId);
  res.json({ ok: true });
});

module.exports = router;
