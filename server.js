// server.js
const express = require('express');
const path = require('path');
const { nanoid } = require('nanoid');
const argon2 = require('argon2');
const db = require('./db');
const { encryptPrivate, decryptPrivate } = require('./crypto');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// In-memory rate limiter (per slug+IP) for unlock attempts (MVP)
const attempts = new Map();
function rateLimitUnlock(req, res, next) {
  const slug = req.params.slug;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const key = `${slug}|${ip}`;
  const now = Date.now();
  const windowMs = 5 * 60 * 1000; // 5 minutes
  const max = 10;

  const rec = attempts.get(key) || { count: 0, ts: now };
  if (now - rec.ts > windowMs) { rec.count = 0; rec.ts = now; }
  rec.count += 1;
  attempts.set(key, rec);

  if (rec.count > max) return res.status(429).json({ error: 'Too many attempts. Try later.' });
  next();
}

// CREATE profile
app.post('/api/profile', async (req, res) => {
  try {
    const {
      public: publicData,
      private: privateData,
      password,         // PIN/password for private access
      slug              // optional custom slug
    } = req.body;

    // Basic validation (keep public minimal!)
    if (!password || typeof password !== 'string' || password.length < 4) {
      return res.status(400).json({ error: 'Password/PIN must be at least 4 chars.' });
    }
    if (!publicData || typeof publicData !== 'object') {
      return res.status(400).json({ error: 'Public data is required.' });
    }
    if (!privateData || typeof privateData !== 'object') {
      return res.status(400).json({ error: 'Private data is required.' });
    }

    const resolvedSlug = (slug && /^[a-zA-Z0-9-_]{4,32}$/.test(slug)) ? slug : nanoid(8);
    const pwdHash = await argon2.hash(password);

    const enc = await encryptPrivate(JSON.stringify(privateData), password);

    const insert = db.prepare(`
      INSERT INTO profiles (slug, public_json, private_cipher, private_iv, private_salt, private_tag, pwd_hash, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insert.run(
      resolvedSlug,
      JSON.stringify(publicData),
      Buffer.from(enc.cipher, 'base64'),
      Buffer.from(enc.iv, 'base64'),
      Buffer.from(enc.salt, 'base64'),
      Buffer.from(enc.tag, 'base64'),
      pwdHash,
      new Date().toISOString()
    );

    const url = `/view.html?slug=${encodeURIComponent(resolvedSlug)}`;
    return res.json({ slug: resolvedSlug, url });
  } catch (e) {
    if (String(e).includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: 'Slug already taken. Try again.' });
    }
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET public data
app.get('/api/public/:slug', (req, res) => {
  const row = db.prepare(`SELECT public_json, created_at FROM profiles WHERE slug = ?`).get(req.params.slug);
  if (!row) return res.status(404).json({ error: 'Not found' });
  return res.json({ public: JSON.parse(row.public_json), createdAt: row.created_at });
});

// UNLOCK private data
app.post('/api/private/:slug/unlock', rateLimitUnlock, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });

  const row = db.prepare(`
    SELECT private_cipher, private_iv, private_salt, private_tag, pwd_hash
    FROM profiles WHERE slug = ?
  `).get(req.params.slug);

  if (!row) return res.status(404).json({ error: 'Not found' });

  const ok = await argon2.verify(row.pwd_hash, password).catch(() => false);
  if (!ok) return res.status(401).json({ error: 'Invalid password' });

  try {
    const encObj = {
      cipher: row.private_cipher.toString('base64'),
      iv: row.private_iv.toString('base64'),
      salt: row.private_salt.toString('base64'),
      tag: row.private_tag.toString('base64')
    };
    const json = await decryptPrivate(encObj, password);
    return res.json({ private: JSON.parse(json) });
  } catch {
    return res.status(400).json({ error: 'Decryption failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`LifeSaver server running on http://localhost:${PORT}`));
