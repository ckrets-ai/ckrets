'use strict';
// the published clients encrypt by default. create() in @ckrets/helper sends ciphertext (fragment.v1, the
// key in the url's #k=; hpke.v1 to a publicKey audience with an encJwk) unless plaintext: true; the answer says
// encryption client; a plaintextDigest is computed locally and the recipient's reveal() gives the same one. One encryption
// per Idempotency-Key, so a repeat replays the first secret. The size limit is checked before anything is sent. The CLI
// (ckrets-helper create) and the stdio MCP server's create_secret do the same. Fake LAB_ values only.
const test = require('node:test'), assert = require('node:assert/strict'), crypto = require('crypto'), fs = require('fs'), os = require('os'), path = require('path');
const { spawn, execFileSync } = require('child_process');
const { apiUnderTest } = require('./api-under-test');
const H = require('../helper/lib/index.js');

const ROOT = path.join(__dirname, '..'), HELPER = path.join(ROOT, 'helper', 'bin', 'ckrets-helper.js'), MCP = path.join(ROOT, 'mcp', 'bin', 'ckrets-mcp.js');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ckrets-enc-'));
const lab = () => `LAB_${crypto.randomBytes(8).toString('hex')}`;
const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(CKRETS_|ACTIONS_ID_TOKEN_)/.test(k)));
let srv, sender, env;
const run = (cmd, args, opts) => new Promise((resolve) => { const ch = spawn(cmd, args, opts); let stdout = '', stderr = ''; ch.stdin.end(opts.input || '');
  ch.stdout.on('data', (d) => { stdout += d; }); ch.stderr.on('data', (d) => { stderr += d; }); ch.on('close', (status) => resolve({ status, stdout, stderr })); });
const raw = async (token, bearer) => (await fetch(`${srv.url}/v1/secrets/${token}/public`)).json();
let hasPyHpke = true; try { execFileSync('python3', ['-c', 'from cryptography.hazmat.primitives import hpke']); } catch { hasPyHpke = false; }

test.before(async () => {
  srv = await apiUnderTest();
  sender = await (await fetch(`${srv.url}/v1/keys`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ label: 'LAB sender' }) })).json();
  env = { CKRETS_BASE_URL: srv.url, CKRETS_KEY: sender.key };
});
test.after(() => { if (srv) srv.server.close(); fs.rmSync(TMP, { recursive: true, force: true }); });

test('create() encrypts by default (fragment.v1): ckrets holds ciphertext, the url carries #k=, reveal() opens it and the plaintext digests match', async () => {
  const v = lab(), c = await H.create(v, { ttl: '1h', env });
  assert.equal(c.encryption, 'client'); assert.match(c.url, /#k=[A-Za-z0-9_-]{43}$/); assert.equal(c.url.split('#k=')[1], c.k);
  const pv = await raw(c.token); assert.equal(pv.clientEncrypted, true); assert.equal(pv.wrappedKey, 'fragment.v1');
  assert.equal(JSON.parse(Buffer.from(c.receipt.split('.')[1], 'base64url')).ce, true);
  assert.match(c.plaintextDigest, /^hmac-sha256:/); assert.notEqual(c.plaintextDigest, c.digest, 'the receipt digest covers the ciphertext');
  const r = await H.reveal(c.url, { env: { CKRETS_BASE_URL: srv.url } });
  assert.equal(r.value, v); assert.equal(r.plaintextDigest, c.plaintextDigest);
  // the token alone (no #k=) is refused before the reveal is spent
  const c2 = await H.create(lab(), { env });
  await assert.rejects(H.reveal(c2.token, { env: { CKRETS_BASE_URL: srv.url } }), /#k=.*nothing was revealed/);
});

test('plaintext: true is the opt-out: ckrets seals it and says server', async () => {
  const v = lab(), c = await H.create(v, { plaintext: true, env });
  assert.equal(c.encryption, 'server'); assert.ok(!c.url.includes('#k=')); assert.equal(c.k, undefined); assert.equal(c.plaintextDigest, c.digest);
  assert.equal((await H.reveal(c.url, { env: { CKRETS_BASE_URL: srv.url } })).value, v);
});

test('a passphrase is a second factor on top of the link key: the server still checks it', async () => {
  const v = lab(), c = await H.create(v, { passphrase: 'LAB-pass', env });
  assert.equal(c.encryption, 'client');
  await assert.rejects(H.reveal(c.url, { passphrase: 'LAB-wrong', env: { CKRETS_BASE_URL: srv.url } }), (e) => e.status === 401);
  const c2 = await H.create(v, { passphrase: 'LAB-pass', env });
  assert.equal((await H.reveal(c2.url, { passphrase: 'LAB-pass', env: { CKRETS_BASE_URL: srv.url } })).value, v);
});

test('one encryption per idempotencyKey: the same call again replays the first secret; another value with that key is refused here', async () => {
  const v = lab(), idempotencyKey = crypto.randomUUID();
  const a = await H.create(v, { idempotencyKey, env }), b = await H.create(v, { idempotencyKey, env });
  assert.equal(b.token, a.token); assert.equal(b.url, a.url);
  await assert.rejects(H.create(lab(), { idempotencyKey, env }), /another value or options; .*nothing was sent/);
});

test('the size limit counts the ciphertext and is checked before anything is sent', async () => {
  const anon = { CKRETS_BASE_URL: srv.url };
  await assert.rejects(H.create('x'.repeat(800), { env: anon }), (e) => e.type === 'value-too-large' && /once encrypted.*1024.*nothing was sent/.test(e.message));
  await assert.rejects(H.create('', { env }), /non-empty string/);
});

test('hpke.v1 to a publicKey audience with an encJwk: only that key opens it; Python cryptography opens what the helper seals', async () => {
  const sig = crypto.generateKeyPairSync('ed25519').privateKey, enc = crypto.generateKeyPairSync('x25519').privateKey;
  const sigPub = crypto.createPublicKey(sig).export({ format: 'jwk' }), encPub = crypto.createPublicKey(enc).export({ format: 'jwk' });
  const sigFile = path.join(TMP, 'sig.jwk'), encFile = path.join(TMP, 'enc.jwk');
  fs.writeFileSync(sigFile, JSON.stringify(sig.export({ format: 'jwk' })), { mode: 0o600 }); fs.writeFileSync(encFile, JSON.stringify(enc.export({ format: 'jwk' })), { mode: 0o600 });
  const v = lab(), c = await H.create(v, { audience: { type: 'publicKey', jwk: sigPub, encJwk: encPub }, env });
  assert.equal(c.encryption, 'client'); assert.equal(c.k, undefined); assert.ok(!c.url.includes('#k='));
  assert.match((await raw(c.token)).wrappedKey, /^hpke\.v1$/);
  const r = await H.reveal(c.token, { env: { CKRETS_BASE_URL: srv.url, CKRETS_SIGNING_KEY: sigFile, CKRETS_ENC_KEY: encFile } });
  assert.equal(r.value, v); assert.equal(r.plaintextDigest, c.plaintextDigest);
  // the seal itself, checked by an independent RFC 9180 implementation
  if (hasPyHpke) {
    const K = crypto.randomBytes(32), wk = H.hpkeSeal(encPub, K), [, , e, ct] = wk.split('.');
    const opened = execFileSync('python3', ['-c', `
import sys, base64, json
from cryptography.hazmat.primitives import hpke, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
sk = X25519PrivateKey.from_private_bytes(u(json.loads(open(sys.argv[1]).read())["d"]))
s = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)
print(base64.urlsafe_b64encode(s.decrypt(u(sys.argv[2]) + u(sys.argv[3]), sk, info=b"ckrets wrap v1")).rstrip(b"=").decode())`, encFile, e, ct], { encoding: 'utf8' }).trim();
    assert.equal(opened, K.toString('base64url'));
  }
});

test('a key that requires client encryption works with the default and refuses the opt-out', async () => {
  const k = await (await fetch(`${srv.url}/v1/keys`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ clientEncryptionRequired: true }) })).json();
  const e2 = { CKRETS_BASE_URL: srv.url, CKRETS_KEY: k.key };
  assert.equal((await H.create(lab(), { env: e2 })).encryption, 'client');
  await assert.rejects(H.create(lab(), { plaintext: true, env: e2 }), (e) => e.status === 400 && e.type === 'plaintext-refused');
});

test('ckrets-helper create: the value on stdin, the url (with #k=) and manage token on stdout; --plaintext opts out', async () => {
  const v = lab(), r = await run(process.execPath, [HELPER, 'create', '--ttl', '1h'], { env: { ...clean, ...env }, input: `${v}\n` });
  assert.equal(r.status, 0, r.stderr); const [url, mt] = r.stdout.trim().split('\n');
  assert.match(url, /\/r\/ck_[0-9A-Z]{26}#k=/); assert.match(mt, /^ckm_/); assert.match(r.stderr, /encrypted here \(fragment\.v1\)/); assert.ok(!r.stderr.includes(v) && !r.stdout.includes(v));
  const out = await run(process.execPath, [HELPER, 'reveal', '-', '--print'], { env: { ...clean, CKRETS_BASE_URL: srv.url }, input: url });
  assert.equal(out.stdout, v);
  const p = await run(process.execPath, [HELPER, 'create', '--plaintext'], { env: { ...clean, ...env }, input: lab() });
  assert.equal(p.status, 0, p.stderr); assert.ok(!p.stdout.includes('#k=')); assert.match(p.stderr, /ckrets sealed it and could read it/);
  assert.equal((await run(process.execPath, [HELPER, 'create'], { env: { ...clean, ...env }, input: '' })).status, 2);
});

test('the stdio MCP server: create_secret is described as encrypting here, creates ciphertext, and its url opens with the helper', async () => {
  const ch = spawn(process.execPath, [MCP], { env: { ...clean, ...env } }); let buf = ''; const waiting = new Map();
  ch.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); const w = waiting.get(m.id); if (w) { waiting.delete(m.id); w(m); } } });
  let n = 0; const rpc = (method, params) => new Promise((res) => { const id = ++n; waiting.set(id, res); ch.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`); });
  try {
    await rpc('initialize', {});
    const list = await rpc('tools/list', {}), t = list.result.tools.find((x) => x.name === 'create_secret');
    assert.match(t.description, /encrypted on this machine/); assert.equal(t.inputSchema.properties.plaintext.type, 'boolean');
    const v = lab(), c = await rpc('tools/call', { name: 'create_secret', arguments: { value: v, ttl: '1h' } });
    const sc = c.result.structuredContent; assert.equal(sc.status, 201); assert.equal(sc.encryption, 'client'); assert.match(sc.url, /#k=/); assert.equal(sc.digestKey, undefined); assert.equal(sc.k, undefined);
    assert.ok(!JSON.stringify(c).includes(v), 'the value is not in the answer');
    assert.equal((await H.reveal(sc.url, { env: { CKRETS_BASE_URL: srv.url } })).value, v);
    const p = await rpc('tools/call', { name: 'create_secret', arguments: { value: lab(), plaintext: true } });
    assert.equal(p.result.structuredContent.encryption, 'server');
    const bad = await rpc('tools/call', { name: 'create_secret', arguments: { value: lab(), audeince: {} } });
    assert.equal(bad.result.isError, true); assert.match(bad.result.content[0].text, /unknown argument "audeince"/);
  } finally { ch.kill(); }
});

test('python: create() encrypts by default too; the helper opens its url, and plaintext=True opts out; hpke_seal opens in the helper', { skip: !hasPyHpke && 'python3 with cryptography not available' }, async () => {
  const v = lab(), PY = path.join(ROOT, 'python');
  const out = await run('python3', ['-c', `
import json, sys, os
import ckrets
c = ckrets.create(sys.stdin.read(), ttl="1h")
p = ckrets.create("LAB_plain_" + os.urandom(4).hex(), plaintext=True)
print(json.dumps({"url": c["url"], "enc": c["encryption"], "pd": c["plaintextDigest"], "penc": p["encryption"], "purl": p["url"]}))`],
  { cwd: PY, env: { ...clean, ...env, PYTHONPATH: PY }, input: v });
  assert.equal(out.status, 0, out.stderr); const j = JSON.parse(out.stdout);
  assert.equal(j.enc, 'client'); assert.match(j.url, /#k=/); assert.equal(j.penc, 'server'); assert.ok(!j.purl.includes('#k='));
  const r = await H.reveal(j.url, { env: { CKRETS_BASE_URL: srv.url } }); assert.equal(r.value, v); assert.equal(r.plaintextDigest, j.pd);
  const enc = crypto.generateKeyPairSync('x25519').privateKey, encPub = crypto.createPublicKey(enc).export({ format: 'jwk' }), K = crypto.randomBytes(32);
  const wk = (await run('python3', ['-c', 'import json,sys,base64,ckrets; k=sys.argv[2]; print(ckrets.hpke_seal(json.loads(sys.argv[1]), base64.urlsafe_b64decode(k + "=" * (-len(k) % 4))))', JSON.stringify(encPub), K.toString('base64url')], { cwd: PY, env: { ...clean, PYTHONPATH: PY } })).stdout.trim();
  const [, , e, c] = wk.split('.'); assert.deepEqual(H.hpkeOpen(Buffer.from(e, 'base64url'), Buffer.from(c, 'base64url'), enc), K);
});

test('ckrets-helper request encrypts by default: the key file at 0600, the page gets encJwk, the answer opens with CKRETS_ENC_KEY', async () => {
  const cfg = fs.mkdtempSync(path.join(TMP, 'cfg-')), e = { ...clean, ...env, XDG_CONFIG_HOME: cfg };
  const q = await run(process.execPath, [HELPER, 'request', '--prompt', 'Enter the code from your authenticator', '--kind', 'otp'], { env: e });
  assert.equal(q.status, 0, q.stderr); const [, id] = q.stdout.trim().split('\n');
  const keyFile = path.join(cfg, 'ckrets', 'requests', `${id}.jwk`); assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600); assert.match(q.stderr, /CKRETS_ENC_KEY=/);
  const pv = await (await fetch(`${srv.url}/v1/requests/${id}/public`)).json(); assert.equal(pv.encJwk.crv, 'X25519');
  // the page's part, done here: seal the answer to encJwk
  const code = String(crypto.randomInt(100000, 999999)), K = crypto.randomBytes(32);
  const body = { value: H.sealValue(code, K), clientEncrypted: true, wrappedKey: H.hpkeSeal(pv.encJwk, K) };
  assert.equal((await fetch(`${srv.url}/v1/requests/${id}/answer`, { method: 'POST', headers: { 'content-type': 'application/json', origin: srv.url }, body: JSON.stringify({ value: code }) })).status, 400, 'a plain answer is refused');
  const a = await fetch(`${srv.url}/v1/requests/${id}/answer`, { method: 'POST', headers: { 'content-type': 'application/json', origin: srv.url }, body: JSON.stringify(body) });
  assert.equal(a.status, 200); assert.equal(a.headers.get('ckrets-encryption'), 'client');
  const w = await run(process.execPath, [HELPER, 'wait', id], { env: e }); assert.equal(w.status, 0, w.stderr); assert.match(w.stderr, new RegExp(`CKRETS_ENC_KEY=${keyFile.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  const r = await run(process.execPath, [HELPER, 'reveal', '-', '--print'], { env: { ...e, CKRETS_ENC_KEY: keyFile }, input: w.stdout.trim() });
  assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout, code);
});

const sealFor = async (id) => {   // the page's part, done here: seal an answer to the request's encJwk
  const pv = await (await fetch(`${srv.url}/v1/requests/${id}/public`)).json(), code = String(crypto.randomInt(100000, 999999)), K = crypto.randomBytes(32);
  const a = await fetch(`${srv.url}/v1/requests/${id}/answer`, { method: 'POST', headers: { 'content-type': 'application/json', origin: srv.url }, body: JSON.stringify({ value: H.sealValue(code, K), clientEncrypted: true, wrappedKey: H.hpkeSeal(pv.encJwk, K) }) });
  assert.equal(a.status, 200); return code;
};

test('python: ckrets request makes the key pair by default (0600), and the answer opens with CKRETS_ENC_KEY', { skip: !hasPyHpke && 'python3 with cryptography not available' }, async () => {
  const PY = path.join(ROOT, 'python'), cfg = fs.mkdtempSync(path.join(TMP, 'pycfg-')), e = { ...clean, ...env, XDG_CONFIG_HOME: cfg, PYTHONPATH: PY };
  const q = await run('python3', ['-m', 'ckrets', 'request', '--prompt', 'Enter the code from your authenticator', '--kind', 'otp'], { cwd: PY, env: e });
  assert.equal(q.status, 0, q.stderr); const [, id] = q.stdout.trim().split('\n'), keyFile = path.join(cfg, 'ckrets', 'requests', `${id}.jwk`);
  assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600); assert.match(q.stderr, /CKRETS_ENC_KEY=/);
  const code = await sealFor(id);
  const w = await run('python3', ['-m', 'ckrets', 'wait', id], { cwd: PY, env: e }); assert.equal(w.status, 0, w.stderr); assert.match(w.stderr, /CKRETS_ENC_KEY=/);
  const r = await run('python3', ['-m', 'ckrets', 'reveal', '-', '--print'], { cwd: PY, env: { ...e, CKRETS_ENC_KEY: keyFile }, input: w.stdout.trim() });
  assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout, code);
});

test('the stdio MCP server: request_secret keeps the key here; get_request then deliver_secret opens the answer into a sink', async () => {
  const cfg = fs.mkdtempSync(path.join(TMP, 'mcpcfg-')), sinkDir = fs.mkdtempSync(path.join(TMP, 'sink-'));
  const ch = spawn(process.execPath, [MCP], { env: { ...clean, ...env, XDG_CONFIG_HOME: cfg, CKRETS_SINKS: `file:${sinkDir}/` } }); let buf = ''; const waiting = new Map();
  ch.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); const w = waiting.get(m.id); if (w) { waiting.delete(m.id); w(m); } } });
  let n = 0; const rpc = (method, params) => new Promise((res) => { const id = ++n; waiting.set(id, res); ch.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`); });
  try {
    await rpc('initialize', {});
    const t = (await rpc('tools/list', {})).result.tools.find((x) => x.name === 'request_secret'); assert.match(t.description, /keeps on this machine/); assert.equal(t.inputSchema.properties.plaintext.type, 'boolean');
    const q = (await rpc('tools/call', { name: 'request_secret', arguments: { prompt: 'Enter the code from your authenticator', kind: 'otp' } })).result.structuredContent;
    assert.equal(q.status, 201); const keyFile = path.join(cfg, 'ckrets', 'requests', `${q.requestId}.jwk`); assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600);
    assert.equal((await (await fetch(`${srv.url}/v1/requests/${q.requestId}/public`)).json()).encJwk.crv, 'X25519');
    const code = await sealFor(q.requestId);
    const g = (await rpc('tools/call', { name: 'get_request', arguments: { requestId: q.requestId } })).result.structuredContent; assert.equal(g.state, 'fulfilled');
    const d = await rpc('tools/call', { name: 'deliver_secret', arguments: { token: g.token, sink: `file:${sinkDir}/otp` } });
    assert.notEqual(d.result.isError, true, JSON.stringify(d.result)); assert.equal(fs.readFileSync(path.join(sinkDir, 'otp'), 'utf8'), code); assert.ok(!JSON.stringify(d).includes(code));
    const p = (await rpc('tools/call', { name: 'request_secret', arguments: { prompt: 'A code', kind: 'otp', plaintext: true } })).result.structuredContent;
    assert.equal(p.status, 201); assert.equal((await (await fetch(`${srv.url}/v1/requests/${p.requestId}/public`)).json()).encJwk, undefined);
  } finally { ch.kill(); }
});
