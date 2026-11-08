'use strict';
// hpke.v1 (RFC 9180 base mode, the suite /docs/client-encryption.md names) in the helper, checked against an
// independent implementation: Python cryptography's HPKE seals K to an X25519 key made here, and the helper's
// hpkeOpen must return the same K; then a value sealed under K opens through decrypt(). Skipped where cryptography has
// no HPKE (it arrived in recent versions). A wrong key, a tampered wrap and a missing CKRETS_ENC_KEY are refused.
const test = require('node:test'), assert = require('node:assert/strict'), crypto = require('crypto'), fs = require('fs'), os = require('os'), path = require('path');
const { execFileSync } = require('child_process');
const H = require('../helper/lib/index.js');
const b64u = (b) => Buffer.from(b).toString('base64url');
const LIMIT = { timeout: 30000, killSignal: 'SIGKILL' };   // a stuck child fails the test, never hangs it
const pySeal = (pubX, K) => execFileSync('python3', ['-c', `
import sys, base64
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
s = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)
out = s.encrypt(u(sys.argv[2]), X25519PublicKey.from_public_bytes(u(sys.argv[1])), info=b"ckrets wrap v1")
print(base64.urlsafe_b64encode(out).rstrip(b"=").decode())`, pubX, b64u(K)], { encoding: 'utf8', ...LIMIT }).trim();
const { pythonSkip, PY_HPKE } = require('./python-check');
const noPyHpke = pythonSkip(PY_HPKE);   // a skip reason only when python3 or its HPKE is missing; otherwise it throws
const seal = (K, pt) => { const n = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', K, n); c.setAAD(Buffer.from('ckrets:v1'));
  return `v1.${b64u(n)}.${b64u(Buffer.concat([c.update(pt, 'utf8'), c.final(), c.getAuthTag()]))}`; };

test('hpke.v1: what Python cryptography seals, the helper opens (an independent RFC 9180 implementation)', { skip: noPyHpke }, () => {
  const sk = crypto.generateKeyPairSync('x25519').privateKey, pubX = crypto.createPublicKey(sk).export({ format: 'jwk' }).x;
  for (let i = 0; i < 5; i++) {
    const K = crypto.randomBytes(32), out = Buffer.from(pySeal(pubX, K), 'base64url');
    assert.deepEqual(H.hpkeOpen(out.subarray(0, 32), out.subarray(32), sk), K, `round ${i}`);
  }
  // end to end through decrypt(), with the private key as a JWK file and as a PEM file
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ckrets-hpke-')), K = crypto.randomBytes(32), out = Buffer.from(pySeal(pubX, K), 'base64url');
  const wk = `hpke.v1.${b64u(out.subarray(0, 32))}.${b64u(out.subarray(32))}`, value = seal(K, 'FAKE_hpke_value');
  fs.writeFileSync(path.join(dir, 'enc.jwk'), JSON.stringify(sk.export({ format: 'jwk' })), { mode: 0o600 });
  fs.writeFileSync(path.join(dir, 'enc.pem'), sk.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  for (const f of ['enc.jwk', 'enc.pem']) assert.equal(H.decrypt(value, wk, null, { CKRETS_ENC_KEY: path.join(dir, f) }), 'FAKE_hpke_value', f);
  // another key, a tampered wrap, no key: refused, never a wrong value
  const other = crypto.generateKeyPairSync('x25519').privateKey; fs.writeFileSync(path.join(dir, 'other.jwk'), JSON.stringify(other.export({ format: 'jwk' })));
  assert.throws(() => H.decrypt(value, wk, null, { CKRETS_ENC_KEY: path.join(dir, 'other.jwk') }), /not the key it was sealed to/);
  const bad = Buffer.from(out); bad[40] ^= 1;
  assert.throws(() => H.decrypt(value, `hpke.v1.${b64u(bad.subarray(0, 32))}.${b64u(bad.subarray(32))}`, null, { CKRETS_ENC_KEY: path.join(dir, 'enc.jwk') }), /not the key it was sealed to/);
  assert.throws(() => H.decrypt(value, wk, null, {}), /set CKRETS_ENC_KEY/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('canOpen says, before a reveal, what this helper cannot open', () => {
  assert.equal(H.canOpen('fragment.v1', 'k', {}), null); assert.match(H.canOpen('fragment.v1', null, {}), /#k=/);
  assert.equal(H.canOpen('hpke.v1', null, { CKRETS_ENC_KEY: '/x' }), null); assert.match(H.canOpen('hpke.v1', null, {}), /CKRETS_ENC_KEY/);
  assert.match(H.canOpen('pass.v1', null, {}), /Argon2id/);
});
