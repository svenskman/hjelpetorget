// VERSION: 0.2.0
'use strict';
const express = require('express');
const bcrypt  = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const db      = require('../db');
const { sendMail, requireAuth } = require('../utils');
const router  = express.Router();

router.post('/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) return res.status(400).json({ error: 'Alle felt er påkrevd' });
  if (password.length < 8) return res.status(400).json({ error: 'Passord må være minst 8 tegn' });
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase()))
    return res.status(409).json({ error: 'E-postadressen er allerede registrert' });

  const id = uuidv4(), hash = await bcrypt.hash(password, 12), token = uuidv4();
  db.prepare('INSERT INTO users (id,email,password,name,verify_token,trust_status) VALUES (?,?,?,?,?,?)').run(id, email.toLowerCase(), hash, name, token, 'pending');

  const smtpOk = !!(process.env.SMTP_HOST && process.env.SMTP_USER);
  if (smtpOk) {
    await sendMail({ to: email, subject: 'Velkommen til Hjelpetorget', html: '<p>Hei ' + name + '! <a href="https://' + (process.env.BASE_DOMAIN||'hjelpetorget.no') + '/api/auth/verify/' + token + '">Bekreft e-post</a></p>' });
  } else {
    db.prepare('UPDATE users SET verified=1, verify_token=NULL WHERE id=?').run(id);
  }
  res.json({ ok: true, message: smtpOk ? 'Sjekk e-posten din.' : 'Registrert! Du kan nå logge inn.' });
});

router.get('/verify/:token', (req, res) => {
  const user = db.prepare('SELECT id FROM users WHERE verify_token=?').get(req.params.token);
  if (!user) return res.redirect('/?error=invalid_token');
  db.prepare('UPDATE users SET verified=1, verify_token=NULL WHERE id=?').run(user.id);
  res.redirect('/?verified=1');
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Mangler e-post eller passord' });
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email.toLowerCase());
  if (!user || !await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Feil e-post eller passord' });
  if (user.trust_status === 'banned') return res.status(403).json({ error: 'Denne kontoen er permanent deaktivert. Kontakt support.' });
  if (user.trust_status === 'suspended') return res.status(403).json({ error: 'Denne kontoen er midlertidig suspendert: ' + (user.suspend_reason || '') });

  req.session.userId = user.id;
  req.session.role   = user.role;
  res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email, avatar: user.avatar, role: user.role, trust_status: user.trust_status, bankid_verified: user.bankid_verified } });
});

router.post('/logout', (req, res) => { req.session.destroy(() => res.json({ ok: true })); });

router.get('/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id,email,name,bio,avatar,location,phone,verified,role,trust_status,bankid_verified,report_count,created_at FROM users WHERE id=?').get(req.session.userId);
  if (!user) return res.status(404).json({ error: 'Bruker ikke funnet' });
  const unread = db.prepare('SELECT COUNT(*) as n FROM notifications WHERE user_id=? AND read=0').get(user.id);
  res.json({ ...user, unreadNotifications: unread.n });
});

router.post('/forgot', async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE email=?').get((req.body.email||'').toLowerCase());
  if (!user) return res.json({ ok: true });
  const token = uuidv4();
  db.prepare('UPDATE users SET reset_token=?, reset_expiry=? WHERE id=?').run(token, Date.now() + 3600000, user.id);
  await sendMail({ to: user.email, subject: 'Tilbakestill passord', html: '<a href="https://' + (process.env.BASE_DOMAIN||'hjelpetorget.no') + '/?reset=' + token + '">Tilbakestill passord</a>' });
  res.json({ ok: true });
});

router.post('/reset', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password || password.length < 8) return res.status(400).json({ error: 'Ugyldig forespørsel' });
  const user = db.prepare('SELECT * FROM users WHERE reset_token=? AND reset_expiry>?').get(token, Date.now());
  if (!user) return res.status(400).json({ error: 'Token utløpt' });
  db.prepare('UPDATE users SET password=?, reset_token=NULL, reset_expiry=NULL WHERE id=?').run(await bcrypt.hash(password, 12), user.id);
  res.json({ ok: true });
});

module.exports = router;
