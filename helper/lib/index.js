'use strict';
// @ckrets/helper (for-agents.md §3): reveal a ckrets token and hand the value to a process, a file or stdout, never
// to a transcript. Node built-ins only. The audience proof, in for-agents.md's order unless CKRETS_PROOF names one:
//   key        CKRETS_KEY (a key or lease) as the bearer
//   oidc       inside GitHub Actions with id-token: write, the job's OIDC token for audience https://ckrets.ai
//   signature  CKRETS_SIGNING_KEY (path to a private Ed25519 JWK file): RFC 9421 per /docs/signing.md
// Client-encrypted values: fragment.v1 is decrypted here (the k from the share URL's #k=, best passed on stdin); hpke.v1 too
// (RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, info "ckrets wrap v1": built from Node's own
// X25519, HMAC and AES-GCM), with the recipient's X25519 private key in CKRETS_ENC_KEY (a path to its JWK or PEM file).
// pass.v1 needs Argon2id, which Node does not carry, so it is refused by name. Before revealing, the helper reads the
// free /public view: a value it could not open (pass.v1, or a missing k or CKRETS_ENC_KEY) is refused before the reveal
// is spent.
const crypto = require('crypto'), fs = require('fs');

// the dated API contract this client was built against, sent on every call (Ckrets-Version)
const API_VERSION = '2026-11-06';
const TOKEN = /ck_[0-9A-HJKMNP-TV-Z]{26}/;
const b64u = (b) => Buffer.from(b).toString('base64url');
class CkretsError extends Error { constructor(message, info = {}) { super(message); this.name = 'CkretsError'; Object.assign(this, info); } }

/** A token, or a share URL (its origin becomes the base, its #k= the fragment key). */
function parseTarget(input, env = process.env) {
  const s = String(input || '').trim(), m = TOKEN.exec(s); if (!m) throw new CkretsError('no ckrets token (ck_…) in the argument');
  let base = env.CKRETS_BASE_URL || 'https://ckrets.ai', k = null;
  if (/^https?:\/\//.test(s)) { const u = new URL(s); base = u.origin; const f = new URLSearchParams(u.hash.slice(1)); k = f.get('k'); }
  return { token: m[0], base: base.replace(/\/+$/, ''), k };
}

const thumbprint = (jwk) => b64u(crypto.createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })).digest());
/** RFC 9421 headers for one request, ckrets' profile (/docs/signing.md): @method @authority @path (+ content-digest with a body). */
function signRequest({ method, url, body, jwk, now = Math.floor(Date.now() / 1000) }) {
  const u = new URL(url), comps = ['"@method"', '"@authority"', '"@path"'], lines = [`"@method": ${method}`, `"@authority": ${u.host}`, `"@path": ${u.pathname}`], headers = {};
  if (body !== undefined) { headers['content-digest'] = `sha-256=:${crypto.createHash('sha256').update(body).digest('base64')}:`; comps.push('"content-digest"'); lines.push(`"content-digest": ${headers['content-digest']}`); }
  const params = `(${comps.join(' ')});created=${now};expires=${now + 60};keyid="${thumbprint(jwk)}";alg="ed25519";tag="ckrets-v1"`;
  lines.push(`"@signature-params": ${params}`);
  const sig = crypto.sign(null, Buffer.from(lines.join('\n')), crypto.createPrivateKey({ key: jwk, format: 'jwk' }));
  return { ...headers, 'signature-input': `sig1=${params}`, signature: `sig1=:${sig.toString('base64')}:` };
}

async function githubOidc(env) {
  const r = await fetch(`${env.ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${encodeURIComponent('https://ckrets.ai')}`, { headers: { authorization: `bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` } });
  if (!r.ok) throw new CkretsError(`GitHub's OIDC token: ${r.status} (the job needs permissions: id-token: write)`);
  return (await r.json()).value;
}
/** Which proof to send: CKRETS_PROOF if set, else the first available in for-agents.md's order; null for a bearer token. */
const apiKey = (env) => env.CKRETS_KEY || env.CKRETS_API_KEY;   // CKRETS_KEY, as the docs say; the other an undocumented fallback
function pickProof(env) {
  const have = { key: !!apiKey(env), oidc: !!(env.ACTIONS_ID_TOKEN_REQUEST_URL && env.ACTIONS_ID_TOKEN_REQUEST_TOKEN), signature: !!env.CKRETS_SIGNING_KEY };
  if (env.CKRETS_PROOF) { if (env.CKRETS_PROOF === 'none') return null; if (!have[env.CKRETS_PROOF]) throw new CkretsError(`CKRETS_PROOF=${env.CKRETS_PROOF} but its credential is not set`); return env.CKRETS_PROOF; }
  return ['key', 'oidc', 'signature'].find((p) => have[p]) || null;
}

/** fragment.v1: AES-256-GCM under k, additional data "ckrets:v1" (/docs/client-encryption.md). */
// ---- HPKE open (RFC 9180, base mode) for hpke.v1: the suite /docs/client-encryption.md names
const i2osp = (n, w) => { const b = Buffer.alloc(w); b.writeUIntBE(n, 0, w); return b; };
const KEM_ID = Buffer.concat([Buffer.from('KEM'), i2osp(0x0020, 2)]);
const HPKE_ID = Buffer.concat([Buffer.from('HPKE'), i2osp(0x0020, 2), i2osp(0x0001, 2), i2osp(0x0002, 2)]);
const V1 = Buffer.from('HPKE-v1'), HPKE_INFO = Buffer.from('ckrets wrap v1');
const extract = (salt, ikm) => crypto.createHmac('sha256', salt).update(ikm).digest();   // an empty salt is HashLen zeros (RFC 5869)
function expand(prk, info, len) { let t = Buffer.alloc(0), out = Buffer.alloc(0);
  for (let i = 1; out.length < len; i++) { t = crypto.createHmac('sha256', prk).update(Buffer.concat([t, info, Buffer.from([i])])).digest(); out = Buffer.concat([out, t]); }
  return out.subarray(0, len); }
const lExtract = (sid, salt, label, ikm) => extract(salt, Buffer.concat([V1, sid, Buffer.from(label), ikm]));
const lExpand = (sid, prk, label, info, len) => expand(prk, Buffer.concat([i2osp(len, 2), V1, sid, Buffer.from(label), info]), len);
/** The X25519 private key from a JWK or PEM file. */
function encKey(file) {
  const raw = fs.readFileSync(file, 'utf8').trim();
  const key = raw.startsWith('{') ? crypto.createPrivateKey({ key: JSON.parse(raw), format: 'jwk' }) : crypto.createPrivateKey(raw);
  if (key.asymmetricKeyType !== 'x25519') throw new CkretsError('CKRETS_ENC_KEY is not an X25519 private key');
  return key;
}
/** HPKE base-mode single-shot open of enc.ct with the recipient's private key; returns the plaintext (K). */
function hpkeOpen(enc, ct, skR, info = HPKE_INFO) {
  if (enc.length !== 32 || ct.length < 16) throw new CkretsError('hpke.v1 wrapped key is malformed');
  const pkE = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b64u(enc) }, format: 'jwk' });
  const dh = crypto.diffieHellman({ privateKey: skR, publicKey: pkE });
  const pkRm = Buffer.from(crypto.createPublicKey(skR).export({ format: 'jwk' }).x, 'base64url');
  const ss = lExpand(KEM_ID, lExtract(KEM_ID, Buffer.alloc(0), 'eae_prk', dh), 'shared_secret', Buffer.concat([enc, pkRm]), 32);
  const ctx = Buffer.concat([Buffer.from([0]), lExtract(HPKE_ID, Buffer.alloc(0), 'psk_id_hash', Buffer.alloc(0)), lExtract(HPKE_ID, Buffer.alloc(0), 'info_hash', info)]);
  const secret = lExtract(HPKE_ID, ss, 'secret', Buffer.alloc(0));
  const key = lExpand(HPKE_ID, secret, 'key', ctx, 32), nonce = lExpand(HPKE_ID, secret, 'base_nonce', ctx, 12);
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce); d.setAuthTag(ct.subarray(ct.length - 16));
  try { return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]); } catch { throw new CkretsError('could not open the hpke.v1 wrapped key: CKRETS_ENC_KEY is not the key it was sealed to'); }
}
/** The value sealed under K (v1.<nonce>.<ct>, AAD "ckrets:v1"), as every client-encrypted kind seals it. */
function openValue(value, K) {
  const [v, n, c] = String(value).split('.'); if (v !== 'v1' || !n || !c) throw new CkretsError('client-encrypted value is not in format v1');
  const ct = Buffer.from(c, 'base64url'), d = crypto.createDecipheriv('aes-256-gcm', K, Buffer.from(n, 'base64url'));
  d.setAAD(Buffer.from('ckrets:v1')); d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString('utf8');
}
/** What this helper needs to open a client-encrypted kind, or why it cannot: checked before a reveal is spent. */
function canOpen(kind, k, env) {
  if (kind === 'fragment.v1') return k ? null : 'the value is client-encrypted (fragment.v1): pass the share URL with its #k= (on stdin: reveal -)';
  if (kind === 'hpke.v1') return env.CKRETS_ENC_KEY ? null : 'the value is client-encrypted to an X25519 key (hpke.v1): set CKRETS_ENC_KEY to the path of its private JWK or PEM';
  return `client-encrypted with ${kind}: not supported by this helper version (fragment.v1 and hpke.v1 only; pass.v1 needs Argon2id, which Node lacks)`;
}
function decrypt(value, wrappedKey, k, env = process.env) {
  if (wrappedKey === 'fragment.v1') {
    if (!k) throw new CkretsError('the value is client-encrypted (fragment.v1): pass the share URL with its #k= (on stdin: reveal -)');
    const [v, n, c] = String(value).split('.'); if (v !== 'v1' || !n || !c) throw new CkretsError('client-encrypted value is not in format v1');
    const ct = Buffer.from(c, 'base64url'), d = crypto.createDecipheriv('aes-256-gcm', Buffer.from(k, 'base64url'), Buffer.from(n, 'base64url'));
    d.setAAD(Buffer.from('ckrets:v1')); d.setAuthTag(ct.subarray(ct.length - 16));
    try { return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString('utf8'); } catch { throw new CkretsError('could not decrypt: the k does not match this value'); }
  }
  const kind = String(wrappedKey).split('.').slice(0, 2).join('.');
  if (kind === 'hpke.v1') {
    if (!env.CKRETS_ENC_KEY) throw new CkretsError(canOpen(kind, k, env));
    const [, , e, c] = String(wrappedKey).split('.'); if (!e || !c) throw new CkretsError('hpke.v1 wrapped key is malformed');
    const K = hpkeOpen(Buffer.from(e, 'base64url'), Buffer.from(c, 'base64url'), encKey(env.CKRETS_ENC_KEY));
    try { return openValue(value, K); } catch (e2) { if (e2 instanceof CkretsError) throw e2; throw new CkretsError('could not decrypt the value with the hpke.v1 key'); }
  }
  throw new CkretsError(canOpen(kind, k, env));
}

/** Reveal once. Returns { value, revealsLeft, receipt, digest } with the plaintext; callers decide where it goes. */
async function reveal(target, { passphrase, env = process.env } = {}) {
  const t = typeof target === 'string' ? parseTarget(target, env) : target, url = `${t.base}/v1/secrets/${t.token}`, proof = pickProof(env);
  // the free /public view says whether the value is client-encrypted and how: refuse what cannot be opened before spending
  try { const p = await fetch(`${url}/public`, { headers: { accept: 'application/json', 'ckrets-version': API_VERSION } });
    if (p.status === 200) { const pv = await p.json(); if (pv.clientEncrypted && pv.wrappedKey) { const why = canOpen(pv.wrappedKey, t.k, env); if (why) throw new CkretsError(`${why} (nothing was revealed)`); } }
  } catch (e) { if (e instanceof CkretsError) throw e; /* no view: the reveal decides */ }
  const method = passphrase !== undefined ? 'POST' : 'GET', body = passphrase !== undefined ? JSON.stringify({ passphrase }) : undefined;
  const headers = { accept: 'application/json', 'user-agent': 'ckrets-helper/1', 'ckrets-version': API_VERSION, ...(body ? { 'content-type': 'application/json' } : {}) };
  if (proof === 'key') headers.authorization = `Bearer ${apiKey(env)}`;
  if (proof === 'oidc') headers.authorization = `Bearer ${await githubOidc(env)}`;
  if (proof === 'signature') Object.assign(headers, signRequest({ method, url, body, jwk: JSON.parse(fs.readFileSync(env.CKRETS_SIGNING_KEY, 'utf8')) }));
  const r = await fetch(url, { method, headers, body }), text = await r.text(); let j = {}; try { j = JSON.parse(text); } catch { /* not JSON */ }
  if (r.status !== 200) throw new CkretsError(`${r.status} ${j.title || ''}${j.detail ? `: ${j.detail}` : ''}`.trim(), { status: r.status, type: String(j.type || '').replace('https://ckrets.ai/problems/', ''), retryAfter: r.headers.get('retry-after'), proof });
  const digest = j.digestKey ? `hmac-sha256:${b64u(crypto.createHmac('sha256', Buffer.from(j.digestKey, 'base64url')).update(j.value).digest())}` : undefined;
  let value = j.value;
  // the API answers camelCase (clientEncrypted, wrappedKey); the snake_case names are read too, for a server before that change
  if (j.clientEncrypted ?? j.client_encrypted) { try { value = decrypt(j.value, j.wrappedKey ?? j.wrapped_key, t.k, env); } catch (e) { e.message += ' (the reveal is spent)'; e.receipt = j.receipt; throw e; } }
  // for a client-encrypted value, the keyed digest of the plaintext too, the one the sender's create() returned
  return { value, revealsLeft: j.revealsLeft, receipt: j.receipt, digest, ...(j.digestKey && (j.clientEncrypted ?? j.client_encrypted) ? { plaintextDigest: keyedDigest(j.digestKey, value) } : {}), proof };
}

/** Ask a person for a value through a ckrets page (POST /v1/requests): never in chat. Needs CKRETS_KEY. With encJwk (an
 *  X25519 public JWK) the page encrypts the answer in the person's browser to it. Returns {requestId, url,
 *  expiresAt, state, kind, answerEncryption}: show url to the person. The manage token is dropped (the key polls). */
async function request({ prompt, kind, ttl, encJwk, idempotencyKey = crypto.randomUUID() }, env = process.env) {
  const key = apiKey(env); if (!key) throw new CkretsError('a request needs CKRETS_KEY: the page shows the person which key asks');
  const base = (env.CKRETS_BASE_URL || 'https://ckrets.ai').replace(/\/+$/, ''), body = JSON.stringify({ prompt, ...(kind ? { kind } : {}), ...(ttl ? { ttl } : {}), ...(encJwk ? { encJwk } : {}) });
  const r = await fetch(`${base}/v1/requests`, { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json', 'user-agent': 'ckrets-helper/1', 'ckrets-version': API_VERSION, authorization: `Bearer ${key}`, 'idempotency-key': idempotencyKey }, body });
  const j = await r.json().catch(() => ({}));
  if (r.status !== 201) throw new CkretsError(`${r.status} ${j.title || ''}${j.detail ? `: ${j.detail}` : ''}`.trim(), { status: r.status, type: String(j.type || '').replace('https://ckrets.ai/problems/', ''), retryAfter: r.headers.get('retry-after') });
  return { requestId: j.requestId, url: j.url, expiresAt: j.expiresAt, state: j.state, kind: j.kind, answerEncryption: j.answerEncryption || (encJwk ? 'client' : 'server') };
}
/** Poll a request until the person answers (or it closes): every `everyMs` (at least 5 s), until `timeoutMs`. Returns the
 *  request's status; when fulfilled it carries `token`, which only this key reveals (reveal() with the same env). */
async function wait(requestId, { everyMs = 5000, timeoutMs = 3600000, sleep = (ms) => new Promise((res) => setTimeout(res, ms)) } = {}, env = process.env) {
  const key = apiKey(env); if (!key) throw new CkretsError('waiting needs CKRETS_KEY (the key that asked)');
  const base = (env.CKRETS_BASE_URL || 'https://ckrets.ai').replace(/\/+$/, ''), end = Date.now() + timeoutMs;
  for (;;) {
    const r = await fetch(`${base}/v1/requests/${encodeURIComponent(requestId)}`, { headers: { accept: 'application/json', 'user-agent': 'ckrets-helper/1', 'ckrets-version': API_VERSION, authorization: `Bearer ${key}` } });
    const j = await r.json().catch(() => ({}));
    if (r.status !== 200) throw new CkretsError(`${r.status} ${j.title || ''}${j.detail ? `: ${j.detail}` : ''}`.trim(), { status: r.status, type: String(j.type || '').replace('https://ckrets.ai/problems/', '') });
    if (j.state !== 'pending') return j;
    if (Date.now() + everyMs > end) throw new CkretsError(`still pending after ${Math.round(timeoutMs / 1000)} s (the request stays open until ${j.expiresAt})`);
    await sleep(Math.max(everyMs, 5000));
  }
}

// ---- create, encrypted on this machine by default (the published clients encrypt unless told not to)
/** HPKE base-mode single-shot seal of K to the recipient's X25519 public key (an encJwk); returns hpke.v1.<enc>.<ct>. */
function hpkeSeal(encJwk, K, info = HPKE_INFO) {
  if (!encJwk || encJwk.kty !== 'OKP' || encJwk.crv !== 'X25519' || typeof encJwk.x !== 'string') throw new CkretsError('audience.encJwk is not an X25519 public JWK');
  const pkR = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: encJwk.x }, format: 'jwk' }), skE = crypto.generateKeyPairSync('x25519').privateKey;
  const enc = Buffer.from(crypto.createPublicKey(skE).export({ format: 'jwk' }).x, 'base64url'), pkRm = Buffer.from(encJwk.x, 'base64url');
  const dh = crypto.diffieHellman({ privateKey: skE, publicKey: pkR });
  const ss = lExpand(KEM_ID, lExtract(KEM_ID, Buffer.alloc(0), 'eae_prk', dh), 'shared_secret', Buffer.concat([enc, pkRm]), 32);
  const ctx = Buffer.concat([Buffer.from([0]), lExtract(HPKE_ID, Buffer.alloc(0), 'psk_id_hash', Buffer.alloc(0)), lExtract(HPKE_ID, Buffer.alloc(0), 'info_hash', info)]);
  const secret = lExtract(HPKE_ID, ss, 'secret', Buffer.alloc(0));
  const c = crypto.createCipheriv('aes-256-gcm', lExpand(HPKE_ID, secret, 'key', ctx, 32), lExpand(HPKE_ID, secret, 'base_nonce', ctx, 12));
  return `hpke.v1.${b64u(enc)}.${b64u(Buffer.concat([c.update(K), c.final(), c.getAuthTag()]))}`;
}
/** The value sealed under K in format v1 (AES-256-GCM, a fresh 12-byte nonce, AAD "ckrets:v1"). */
function sealValue(plain, K) {
  const n = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', K, n); c.setAAD(Buffer.from('ckrets:v1'));
  return `v1.${b64u(n)}.${b64u(Buffer.concat([c.update(String(plain), 'utf8'), c.final(), c.getAuthTag()]))}`;
}
/** The keyed digest of a string under a digestKey, in the receipt's format (hmac-sha256:<base64url>). */
const keyedDigest = (digestKey, s) => `hmac-sha256:${b64u(crypto.createHmac('sha256', Buffer.from(digestKey, 'base64url')).update(String(s), 'utf8').digest())}`;
const MAX_STAMP_BITS = 26;
function solveStamp(nonce, difficulty) {
  if (!(difficulty >= 0 && difficulty <= MAX_STAMP_BITS)) throw new CkretsError(`the server asks a ${difficulty}-bit stamp; this client solves at most ${MAX_STAMP_BITS} (is CKRETS_BASE_URL right?)`, { status: 428, type: 'proof-of-work-required' });
  for (let c = 0; ; c++) { const d = crypto.createHash('sha256').update(`${nonce}:${c}`).digest(); let bits = 0;
    for (const b of d) { if (b === 0) { bits += 8; continue; } bits += Math.clz32(b) - 24; break; }
    if (bits >= difficulty) return c; }
}
// One encryption per Idempotency-Key in this process: a retry sends the same ciphertext (a fresh nonce would be another
// request, and the API would answer 409 idempotency-mismatch). A reused key with another value or options is refused here.
const sealedFor = new Map();
const problemOf = (r, j) => new CkretsError(`${r.status} ${j.title || ''}${j.detail ? `: ${j.detail}` : ''}`.trim(), { status: r.status, type: String(j.type || '').replace('https://ckrets.ai/problems/', ''), retryAfter: r.headers.get('retry-after'), problem: j });
/** Create a secret. By default the value is encrypted here and ckrets stores ciphertext it holds no key for:
 *  hpke.v1 when the audience is a publicKey with an encJwk (only that key's holder opens it), else fragment.v1 (the key K
 *  goes in the returned url's #k=, never to ckrets). plaintext: true sends the value for ckrets to seal (it could read it).
 *  A passphrase stays a server-checked gate (attempt limits) on top of the link key: two factors. Before anything is sent
 *  the value is checked here (a string, and it fits the tier once encrypted). Returns the API's answer plus url (with #k=
 *  for fragment.v1), k, encryption ('client' or 'server') and plaintextDigest: the keyed digest of the plaintext under
 *  digestKey, computed here and never sent (the receipt's dig covers the ciphertext); a recipient's reveal() gives the same. */
async function create(value, { ttl, reveals, passphrase, audience, purpose, plaintext = false, idempotencyKey = crypto.randomUUID(), env = process.env, sleep = (ms) => new Promise((res) => setTimeout(res, ms)) } = {}) {
  if (typeof value !== 'string' || !value.length) throw new CkretsError('value must be a non-empty string; nothing was sent');
  if (typeof idempotencyKey !== 'string' || !idempotencyKey.length || idempotencyKey.length > 64) throw new CkretsError('idempotencyKey is 1 to 64 characters; nothing was sent');
  const key = apiKey(env), base = (env.CKRETS_BASE_URL || 'https://ckrets.ai').replace(/\/+$/, '');
  const opts = { ttl, reveals, passphrase, audience, purpose, plaintext: plaintext === true };
  const fp = crypto.createHash('sha256').update(JSON.stringify([value, opts, base, key ? 'key' : 'anonymous'])).digest('hex');
  let s = sealedFor.get(idempotencyKey);
  if (s && s.fp !== fp) throw new CkretsError('this idempotencyKey was used with another value or options; use a new key for a new secret (nothing was sent)');
  if (!s) {
    const fields = { ...(ttl !== undefined ? { ttl } : {}), ...(reveals !== undefined ? { reveals } : {}), ...(passphrase !== undefined ? { passphrase } : {}), ...(audience !== undefined ? { audience } : {}), ...(purpose !== undefined ? { purpose } : {}) };
    if (opts.plaintext) s = { fp, body: { value, ...fields }, k: null };
    else {
      const K = crypto.randomBytes(32), hpke = audience && audience.type === 'publicKey' && audience.encJwk;
      s = { fp, body: { value: sealValue(value, K), clientEncrypted: true, wrappedKey: hpke ? hpkeSeal(audience.encJwk, K) : 'fragment.v1', ...fields }, k: hpke ? null : b64u(K) };
    }
    // the size limit counts the string sent (the ciphertext when encrypted): refused here rather than spent on a 413
    const max = key ? 65536 : 1024, size = Buffer.byteLength(s.body.value, 'utf8');
    if (size > max) throw new CkretsError(`the value is ${size} bytes ${opts.plaintext ? '' : 'once encrypted '}and this tier holds ${max}${key ? '' : ' (a key holds 65,536)'}; nothing was sent`, { type: 'value-too-large' });
    sealedFor.set(idempotencyKey, s);
  }
  const headers = { accept: 'application/json', 'content-type': 'application/json', 'user-agent': 'ckrets-helper/1', 'ckrets-version': API_VERSION, 'idempotency-key': idempotencyKey, ...(key ? { authorization: `Bearer ${key}` } : {}) };
  const body = JSON.stringify(s.body);
  for (let attempt = 1; ; attempt++) {
    let r; try { r = await fetch(`${base}/v1/secrets`, { method: 'POST', headers, body }); }
    catch (e) { if (attempt < 4) { await sleep(500 * attempt); continue; } throw new CkretsError(`ckrets unreachable: ${e.message} (retry with the same idempotencyKey: ${idempotencyKey})`, { idempotencyKey }); }
    const j = await r.json().catch(() => ({}));
    if (r.status === 201) {   // kept: the same call again (an answer the caller lost) replays this secret, not a new one
      if (sealedFor.size > 1000) sealedFor.delete(sealedFor.keys().next().value);
      const enc = r.headers.get('ckrets-encryption') || (s.body.clientEncrypted ? 'client' : 'server');
      return { ...j, url: s.k ? `${j.url}#k=${s.k}` : j.url, ...(s.k ? { k: s.k } : {}), encryption: enc, ...(j.digestKey ? { plaintextDigest: keyedDigest(j.digestKey, value) } : {}), idempotencyKey };
    }
    if (r.status === 428 && j.stamp && j.stamp.nonce && !headers['ckrets-proof']) { headers['ckrets-proof'] = `stamp=${j.stamp.nonce}:${solveStamp(j.stamp.nonce, Number(j.stamp.difficulty ?? 11))}`; continue; }
    const again = (r.status === 409 && /idempotency-in-progress$/.test(j.type || '')) || (r.status === 503 && j.retryable === true);
    if (again && attempt < 4) { await sleep(Math.min(5, Number(r.headers.get('retry-after')) || 1) * 1000); continue; }
    if (r.status < 500 || j.outcome !== 'unknown') sealedFor.delete(idempotencyKey);   // final: a new call encrypts afresh
    throw Object.assign(problemOf(r, j), { idempotencyKey });
  }
}

/** Before a reveal: may a value be written at this path? Never through a symlink; an existing file only with force.
 *  Returns null when it may, else the reason. */
function fileRefusal(file, force) {
  let st = null; try { st = fs.lstatSync(file); } catch (e) { if (e.code !== 'ENOENT') return `${file}: ${e.code}`; }
  if (!st) return null;
  if (st.isSymbolicLink()) return `${file} is a symbolic link: refused, whatever --force says`;
  if (!st.isFile()) return `${file} exists and is not a regular file`;
  return force ? null : `${file} exists: refused (--force replaces it)`;
}
/** Write a value: exclusive create at the mode, never following a link (O_EXCL | O_NOFOLLOW); with force an existing
 *  regular file is removed first, so the value never lands in a file with an older, looser mode. */
function writeSecretFile(file, value, mode, force = false) {
  const why = fileRefusal(file, force); if (why) throw new CkretsError(why);
  if (force && fs.existsSync(file)) fs.unlinkSync(file);
  const C = fs.constants, fd = fs.openSync(file, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, mode);
  try { fs.fchmodSync(fd, mode); fs.writeSync(fd, value); } finally { fs.closeSync(fd); }   // fchmod: the mode exactly, whatever the umask
}

module.exports = { API_VERSION, create, hpkeSeal, sealValue, keyedDigest, solveStamp, request, wait, fileRefusal, writeSecretFile, reveal, parseTarget, signRequest, thumbprint, pickProof, decrypt, hpkeOpen, canOpen, CkretsError, TOKEN };
