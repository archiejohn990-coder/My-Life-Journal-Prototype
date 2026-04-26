
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const Database = require('better-sqlite3');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'db', 'journal.sqlite');
const schema = fs.readFileSync(path.join(__dirname, 'db', 'schema.sql'), 'utf8');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(schema);

app.use(cors());
app.use(express.json({ limit: '8mb' }));
app.use('/', express.static(path.join(__dirname, '..', 'public')));

const sessions = new Map();
const pending2FA = new Map();

function hashValue(value, salt){ return crypto.pbkdf2Sync(value, salt, 120000, 32, 'sha256').toString('hex'); }
function createDemoCode(){ return String(Math.floor(100000 + Math.random() * 900000)); }
function sanitizeUser(row){ return { id: row.id, name: row.name, email: row.email, photo: row.photo || null, created_at: row.created_at }; }
function auth(req, res, next){
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const session = token ? sessions.get(token) : null;
  if(!session) return res.status(401).json({ error: 'Unauthorized' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.userId);
  if(!user) return res.status(401).json({ error: 'Session user not found' });
  req.user = user;
  req.token = token;
  next();
}

app.post('/api/auth/signup', (req, res) => {
  const { name, email, password, pin } = req.body || {};
  if(!name || !email || !password || !pin) return res.status(400).json({ error: 'Missing signup fields' });
  if(password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if(!/^\d{6}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 6 digits' });
  const normEmail = String(email).trim().toLowerCase();
  if(db.prepare('SELECT id FROM users WHERE email = ?').get(normEmail)) return res.status(409).json({ error: 'Email already exists' });
  const passwordSalt = crypto.randomBytes(16).toString('hex');
  const pinSalt = crypto.randomBytes(16).toString('hex');
  const twoFactorSecret = crypto.randomBytes(10).toString('hex');
  const info = db.prepare(`INSERT INTO users (name,email,password_hash,password_salt,pin_hash,pin_salt,two_factor_secret,photo)
    VALUES (?,?,?,?,?,?,?,NULL)`).run(name.trim(), normEmail, hashValue(password, passwordSalt), passwordSalt, hashValue(pin, pinSalt), pinSalt, twoFactorSecret);
  const code = createDemoCode();
  pending2FA.set(normEmail, { mode: 'signup', code, password, pin, userId: info.lastInsertRowid, expires: Date.now()+5*60*1000 });
  res.json({ ok: true, message: 'Account created. Verify 2FA to continue.', demoCode: code });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password, pin } = req.body || {};
  const normEmail = String(email || '').trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normEmail);
  if(!user) return res.status(401).json({ error: 'Invalid credentials' });
  if(hashValue(password, user.password_salt) !== user.password_hash) return res.status(401).json({ error: 'Invalid credentials' });
  if(hashValue(pin, user.pin_salt) !== user.pin_hash) return res.status(401).json({ error: 'Invalid credentials' });
  const code = createDemoCode();
  pending2FA.set(normEmail, { mode: 'login', code, userId: user.id, expires: Date.now()+5*60*1000 });
  res.json({ ok: true, message: '2FA code generated', demoCode: code });
});

app.post('/api/auth/verify-2fa', (req, res) => {
  const { email, code } = req.body || {};
  const normEmail = String(email || '').trim().toLowerCase();
  const pending = pending2FA.get(normEmail);
  if(!pending || pending.expires < Date.now()) return res.status(400).json({ error: '2FA code expired. Start again.' });
  if(String(code) !== String(pending.code)) return res.status(400).json({ error: 'Invalid 2FA code' });
  pending2FA.delete(normEmail);
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { userId: pending.userId, createdAt: Date.now() });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(pending.userId);
  res.json({ ok: true, token, user: sanitizeUser(user) });
});

app.post('/api/auth/recover', (req, res) => {
  const { email, name, newPassword, newPin } = req.body || {};
  const normEmail = String(email || '').trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normEmail);
  if(!user || user.name.toLowerCase() !== String(name || '').trim().toLowerCase()) return res.status(404).json({ error: 'Matching account not found' });
  const passwordSalt = crypto.randomBytes(16).toString('hex');
  const pinSalt = crypto.randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET password_hash = ?, password_salt = ?, pin_hash = ?, pin_salt = ? WHERE id = ?')
    .run(hashValue(newPassword, passwordSalt), passwordSalt, hashValue(newPin, pinSalt), pinSalt, user.id);
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => res.json({ user: sanitizeUser(req.user) }));
app.delete('/api/me', auth, (req, res) => {
  db.prepare('DELETE FROM entry_tags WHERE entry_id IN (SELECT id FROM entries WHERE user_id = ?)').run(req.user.id);
  db.prepare('DELETE FROM entries WHERE user_id = ?').run(req.user.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(req.user.id);
  sessions.delete(req.token);
  res.json({ ok: true });
});

app.put('/api/profile/photo', auth, (req, res) => {
  const { photo } = req.body || {};
  db.prepare('UPDATE users SET photo = ? WHERE id = ?').run(photo || null, req.user.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  res.json({ ok: true, user: sanitizeUser(user) });
});

app.get('/api/entries', auth, (req, res) => {
  const rows = db.prepare(`SELECT e.* FROM entries e WHERE e.user_id = ? ORDER BY datetime(e.created_at) DESC`).all(req.user.id);
  const tagStmt = db.prepare('SELECT tag FROM entry_tags WHERE entry_id = ? ORDER BY tag ASC');
  const entries = rows.map(r => ({ ...r, tags: tagStmt.all(r.id).map(t => t.tag) }));
  res.json({ entries });
});

app.post('/api/entries', auth, (req, res) => {
  const { title, body, mood, tags, date, image } = req.body || {};
  const info = db.prepare(`INSERT INTO entries (user_id,title,body,mood,entry_date,image) VALUES (?,?,?,?,?,?)`)
    .run(req.user.id, title || '', body || '', mood || '😐 Neutral', date, image || null);
  const entryId = info.lastInsertRowid;
  const insertTag = db.prepare('INSERT INTO entry_tags (entry_id, tag) VALUES (?, ?)');
  for(const tag of Array.isArray(tags) ? [...new Set(tags)] : []) insertTag.run(entryId, String(tag).toLowerCase());
  res.json({ ok: true, id: entryId });
});

app.put('/api/entries/:id', auth, (req, res) => {
  const { title, body, mood, tags, date, image } = req.body || {};
  const entry = db.prepare('SELECT * FROM entries WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if(!entry) return res.status(404).json({ error: 'Entry not found' });
  db.prepare('UPDATE entries SET title=?, body=?, mood=?, entry_date=?, image=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?')
    .run(title || '', body || '', mood || '😐 Neutral', date, image || null, req.params.id, req.user.id);
  db.prepare('DELETE FROM entry_tags WHERE entry_id = ?').run(req.params.id);
  const insertTag = db.prepare('INSERT INTO entry_tags (entry_id, tag) VALUES (?, ?)');
  for(const tag of Array.isArray(tags) ? [...new Set(tags)] : []) insertTag.run(req.params.id, String(tag).toLowerCase());
  res.json({ ok: true });
});

app.delete('/api/entries/:id', auth, (req, res) => {
  db.prepare('DELETE FROM entry_tags WHERE entry_id = ?').run(req.params.id);
  db.prepare('DELETE FROM entries WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.get('/api/export', auth, (req, res) => {
  const entries = db.prepare('SELECT * FROM entries WHERE user_id = ? ORDER BY datetime(created_at) DESC').all(req.user.id);
  const tagStmt = db.prepare('SELECT tag FROM entry_tags WHERE entry_id = ? ORDER BY tag ASC');
  res.json({
    exportedAt: new Date().toISOString(),
    app: 'My Life Journal Connected',
    user: sanitizeUser(req.user),
    entries: entries.map(e => ({...e, tags: tagStmt.all(e.id).map(t => t.tag)}))
  });
});

app.post('/api/import', auth, (req, res) => {
  const payload = req.body || {};
  const entries = Array.isArray(payload.entries) ? payload.entries : [];
  db.prepare('DELETE FROM entry_tags WHERE entry_id IN (SELECT id FROM entries WHERE user_id = ?)').run(req.user.id);
  db.prepare('DELETE FROM entries WHERE user_id = ?').run(req.user.id);
  const insertEntry = db.prepare('INSERT INTO entries (user_id,title,body,mood,entry_date,image,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)');
  const insertTag = db.prepare('INSERT INTO entry_tags (entry_id, tag) VALUES (?, ?)');
  const tx = db.transaction(() => {
    for(const entry of entries){
      const info = insertEntry.run(req.user.id, entry.title || '', entry.body || '', entry.mood || '😐 Neutral', entry.entry_date || entry.date, entry.image || null, entry.created_at || entry.createdAt || new Date().toISOString(), entry.updated_at || entry.updatedAt || null);
      for(const tag of Array.isArray(entry.tags) ? entry.tags : []) insertTag.run(info.lastInsertRowid, String(tag).toLowerCase());
    }
  });
  tx();
  res.json({ ok: true, imported: entries.length });
});

app.listen(PORT, () => console.log(`Journal backend running on http://localhost:${PORT}`));
app.use(cors());

const express = require("express");

app.use(cors());
app.use(express.json());

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
