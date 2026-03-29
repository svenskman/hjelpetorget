// VERSION: 0.1.0
'use strict';
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');

const DATA_DIR    = process.env.DATA_DIR || './data';
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const AVATARS_DIR = path.join(DATA_DIR, 'avatars');
for (const d of [UPLOADS_DIR, AVATARS_DIR]) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => cb(null, 'tmp_' + uuidv4() + path.extname(file.originalname)),
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Kun bilder er tillatt'));
    cb(null, true);
  },
});

async function resizeAvatar(tmpPath, filename) {
  const sharp = require('sharp');
  await sharp(tmpPath).resize(256, 256, { fit: 'cover' }).webp({ quality: 85 }).toFile(path.join(AVATARS_DIR, filename));
}

async function resizePostImage(tmpPath, filename) {
  const sharp = require('sharp');
  await sharp(tmpPath).resize(1024, 1024, { fit: 'inside', withoutEnlargement: true }).webp({ quality: 82 }).toFile(path.join(UPLOADS_DIR, filename));
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Ikke innlogget' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || req.session.role !== 'admin') return res.status(403).json({ error: 'Ikke tilgang' });
  next();
}

let _transporter = null;
async function sendMail({ to, subject, html }) {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER) return;
  if (!_transporter) {
    _transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_PORT === '465',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
  }
  try {
    await _transporter.sendMail({ from: process.env.SMTP_FROM || 'noreply@hjelpetorget.no', to, subject, html });
  } catch (e) { console.error('[mail]', e.message); }
}

function notify(userId, type, payload = {}) {
  try {
    db.prepare('INSERT INTO notifications (id,user_id,type,payload) VALUES (?,?,?,?)')
      .run(uuidv4(), userId, type, JSON.stringify(payload));
  } catch (e) { console.error('[notify]', e.message); }
}

module.exports = { upload, resizeAvatar, resizePostImage, requireAuth, requireAdmin, sendMail, notify, UPLOADS_DIR, AVATARS_DIR };
