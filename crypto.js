// crypto.js
const crypto = require('crypto');

function buf(b64) { return Buffer.from(b64, 'base64'); }
function b64(buf) { return Buffer.from(buf).toString('base64'); }

/**
 * Encrypts JSON (string) with password using scrypt + AES-256-GCM
 * Returns { cipher, iv, salt, tag } as base64 strings
 */
async function encryptPrivate(jsonString, password) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = await scryptAsync(password, salt, 32);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(jsonString, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    cipher: b64(enc),
    iv: b64(iv),
    salt: b64(salt),
    tag: b64(tag)
  };
}

/**
 * Decrypts to original JSON string
 */
async function decryptPrivate(encObj, password) {
  const salt = buf(encObj.salt);
  const iv = buf(encObj.iv);
  const tag = buf(encObj.tag);
  const cipherBuf = buf(encObj.cipher);
  const key = await scryptAsync(password, salt, 32);

  const dec = crypto.createDecipheriv('aes-256-gcm', key, iv);
  dec.setAuthTag(tag);
  const out = Buffer.concat([dec.update(cipherBuf), dec.final()]);
  return out.toString('utf8');
}

function scryptAsync(password, salt, keylen) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, { N: 16384, r: 8, p: 1 }, (err, key) => {
      if (err) reject(err); else resolve(key);
    });
  });
}

module.exports = { encryptPrivate, decryptPrivate };
