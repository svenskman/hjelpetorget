// VERSION: 0.2.0
'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const { requireAuth, notify } = require('../utils');
const router = express.Router();

router.post('/start', requireAuth, (req, res) => {
  const { post_id, recipient_id } = req.body;
  if (!recipient_id) return res.status(400).json({ error: 'Mangler mottaker' });
  if (recipient_id === req.session.userId) return res.status(400).json({ error: 'Kan ikke sende melding til deg selv' });

  let conv = post_id
    ? db.prepare('SELECT c.id FROM conversations c JOIN conversation_members m1 ON c.id=m1.conversation_id AND m1.user_id=? JOIN conversation_members m2 ON c.id=m2.conversation_id AND m2.user_id=? WHERE c.post_id=?').get(req.session.userId, recipient_id, post_id)
    : db.prepare('SELECT c.id FROM conversations c JOIN conversation_members m1 ON c.id=m1.conversation_id AND m1.user_id=? JOIN conversation_members m2 ON c.id=m2.conversation_id AND m2.user_id=? WHERE c.post_id IS NULL').get(req.session.userId, recipient_id);

  if (conv) return res.json({ id: conv.id, existing: true });
  const id = uuidv4();
  db.prepare('INSERT INTO conversations (id,post_id) VALUES (?,?)').run(id, post_id||null);
  db.prepare('INSERT INTO conversation_members (conversation_id,user_id) VALUES (?,?)').run(id, req.session.userId);
  db.prepare('INSERT INTO conversation_members (conversation_id,user_id) VALUES (?,?)').run(id, recipient_id);
  res.status(201).json({ id, existing: false });
});

router.get('/', requireAuth, (req, res) => {
  const convs = db.prepare(`SELECT c.id,c.post_id,c.created_at,p.title as post_title,m.last_read_at,
    (SELECT body FROM messages WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1) as last_message,
    (SELECT created_at FROM messages WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1) as last_message_at,
    (SELECT COUNT(*) FROM messages WHERE conversation_id=c.id AND created_at>m.last_read_at) as unread_count
    FROM conversations c JOIN conversation_members m ON c.id=m.conversation_id AND m.user_id=?
    LEFT JOIN posts p ON c.post_id=p.id ORDER BY last_message_at DESC NULLS LAST`).all(req.session.userId);
  for (const c of convs) {
    c.participants = db.prepare('SELECT u.id,u.name,u.avatar FROM users u JOIN conversation_members cm ON u.id=cm.user_id WHERE cm.conversation_id=? AND u.id!=?').all(c.id, req.session.userId);
  }
  res.json(convs);
});

router.get('/:id', requireAuth, (req, res) => {
  const member = db.prepare('SELECT * FROM conversation_members WHERE conversation_id=? AND user_id=?').get(req.params.id, req.session.userId);
  if (!member) return res.status(403).json({ error: 'Ikke tilgang' });
  const messages = db.prepare('SELECT m.*,u.name as sender_name,u.avatar as sender_avatar FROM messages m JOIN users u ON m.sender_id=u.id WHERE m.conversation_id=? ORDER BY m.created_at ASC').all(req.params.id);
  db.prepare('UPDATE conversation_members SET last_read_at=unixepoch() WHERE conversation_id=? AND user_id=?').run(req.params.id, req.session.userId);
  const conv = db.prepare('SELECT * FROM conversations WHERE id=?').get(req.params.id);
  const participants = db.prepare('SELECT u.id,u.name,u.avatar FROM users u JOIN conversation_members cm ON u.id=cm.user_id WHERE cm.conversation_id=?').all(req.params.id);
  res.json({ conversation: { ...conv, participants }, messages });
});

router.post('/:id/messages', requireAuth, (req, res) => {
  const { body } = req.body;
  if (!body || !body.trim()) return res.status(400).json({ error: 'Tom melding' });
  if (!db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?').get(req.params.id, req.session.userId))
    return res.status(403).json({ error: 'Ikke tilgang' });
  const id = uuidv4();
  db.prepare('INSERT INTO messages (id,conversation_id,sender_id,body) VALUES (?,?,?,?)').run(id, req.params.id, req.session.userId, body.trim());
  const others = db.prepare('SELECT user_id FROM conversation_members WHERE conversation_id=? AND user_id!=?').all(req.params.id, req.session.userId);
  const sender = db.prepare('SELECT name FROM users WHERE id=?').get(req.session.userId);
  for (const o of others) notify(o.user_id, 'new_message', { conversation_id: req.params.id, sender_name: sender.name, preview: body.trim().slice(0, 80) });
  res.status(201).json({ ok: true, id });
});

module.exports = router;
