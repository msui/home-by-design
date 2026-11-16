#!/usr/bin/env node
// Encrypts the site so the published index.html is unreadable without the password.
//
//   SITE_PASSWORD='…' node tools/crypt.mjs encrypt private/guide.html index.html
//   SITE_PASSWORD='…' node tools/crypt.mjs decrypt index.html private/guide.html
//
// AES-256-GCM with a key from PBKDF2-SHA256. Fresh salt and IV on every encrypt.
// private/ is git-ignored: never commit the plaintext.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto as crypto } from 'node:crypto';

const ITER = 600000;
const here = dirname(fileURLToPath(import.meta.url));
const [mode, src, out] = process.argv.slice(2);
const pw = process.env.SITE_PASSWORD;

if (!['encrypt', 'decrypt'].includes(mode) || !src || !out) {
  console.error('Usage: SITE_PASSWORD=… node tools/crypt.mjs encrypt|decrypt <in> <out>');
  process.exit(2);
}
if (!pw) { console.error('Set SITE_PASSWORD.'); process.exit(2); }

const b64 = (u) => Buffer.from(u).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));

async function keyFor(salt, iter) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

if (mode === 'encrypt') {
  const plain = readFileSync(src);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await keyFor(salt, ITER);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
  const payload = JSON.stringify({ v: 1, iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) });
  const gate = readFileSync(join(here, 'gate.html'), 'utf8');
  if (!gate.includes('/*PAYLOAD*/')) throw new Error('gate.html is missing the /*PAYLOAD*/ marker');
  writeFileSync(out, gate.replace('/*PAYLOAD*/', () => payload));
  console.log(`Encrypted ${src} -> ${out} (${ct.length} bytes)`);
} else {
  const html = readFileSync(src, 'utf8');
  const m = html.match(/<script id="payload" type="application\/json">([\s\S]*?)<\/script>/);
  if (!m) throw new Error('No encrypted payload found in ' + src);
  const P = JSON.parse(m[1]);
  const key = await keyFor(unb64(P.salt), P.iter);
  let plain;
  try { plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(P.iv) }, key, unb64(P.ct)); }
  catch { console.error('Wrong password.'); process.exit(1); }
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, Buffer.from(plain));
  console.log(`Decrypted ${src} -> ${out}`);
}
