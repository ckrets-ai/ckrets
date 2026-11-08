'use strict';
// Webhooks (preview): the receiver's check in both clients (the helper's verifyWebhook and the Python verify_webhook),
// self-contained: the test makes its own EC P-256 event key and a separate receipt key, publishes them as a JWKS and
// signs deliveries the way the ckrets API does (RFC 9421, ecdsa-p256-sha256, tag ckrets-webhook). No API is needed.
// Every refusal is asserted by its why, the same in both languages.
const test = require('node:test'), assert = require('node:assert/strict'), crypto = require('crypto'), path = require('path'), { spawnSync } = require('child_process');
const { verifyWebhook } = require('../helper/lib');

const URL_ = 'https://hooks.example.com/ckrets', NOW = 1_800_000_000_000, NOW_S = NOW / 1000;
const COMPONENTS = ['@method', '@target-uri', 'content-digest', 'content-type', 'webhook-id'];
const ec = () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const EVENT = ec(), RECEIPT = ec(), RSA = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }), P384 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' });
const jwk = (kp, kid, use) => ({ ...kp.publicKey.export({ format: 'jwk' }), kid, use });
const JWKS = { keys: [jwk(EVENT, 'ev1', 'ckrets-event'), jwk(RECEIPT, 'rc1', 'sig')] };
const digest = (body) => `sha-256=:${crypto.createHash('sha256').update(body).digest('base64')}:`;

// sign a delivery as the API does; every field can be overridden to make the bad cases
function deliver({ id = 'evt_01', body, created = NOW_S, expires, kid = 'ev1', key = EVENT.privateKey, alg = 'ecdsa-p256-sha256', tag = 'ckrets-webhook', comps = COMPONENTS, url = URL_, webhookId, sig } = {}) {
  body = body ?? JSON.stringify({ id, type: 'secret.ended', data: { state: 'revoked' } });
  const h = { 'content-type': 'application/json', 'content-digest': digest(body), 'webhook-id': webhookId ?? id };
  const sp = `(${comps.map((c) => `"${c}"`).join(' ')});created=${created};expires=${expires ?? created + 300};keyid="${kid}";alg="${alg}";tag="${tag}"`;
  const v = { '@method': 'POST', '@target-uri': url, ...h };
  const base = `${comps.map((c) => `"${c}": ${v[c]}`).join('\n')}\n"@signature-params": ${sp}`;
  const s = sig ?? (key.asymmetricKeyType === 'ec' ? crypto.sign('sha256', Buffer.from(base), { key, dsaEncoding: 'ieee-p1363' }) : crypto.sign('sha256', Buffer.from(base), key));
  return { body, headers: { ...h, 'signature-input': `sig1=${sp}`, signature: `sig1=:${s.toString('base64')}:` } };
}
// the time options travel to Python as strings when JSON cannot carry them (NaN, Infinity)
const pyNum = (x) => (Number.isFinite(x) ? x : String(x));
const args = (d, extra = {}) => ({ url: URL_, headers: d.headers, body: d.body, jwks: JWKS, now: NOW, ...extra });

// the Python client, on the same inputs (now in seconds there); bodies go as base64 so any bytes survive
function py(cases) {
  const code = 'import sys,json,base64;sys.path.insert(0,sys.argv[1]);import ckrets\n'
    + 'out=[]\nfor a in json.loads(sys.stdin.read()):\n'
    + '  b=base64.b64decode(a["body"]) if a["body"] is not None else None\n'
    + '  o={k:(float(a[k]) if isinstance(a.get(k),str) else a[k]) for k in ("max_age","skew") if k in a}\n'
    + '  out.append(ckrets.verify_webhook(a.get("url"),a.get("headers"),b,a.get("jwks"),now=a["now"],**o))\n'
    + 'print(json.dumps(out))';
  const input = cases.map((a) => ({ url: a.url, headers: a.headers instanceof Map ? Object.fromEntries(a.headers) : a.headers, body: a.body == null ? null : Buffer.from(a.body).toString('base64'), jwks: a.jwks, now: a.now / 1000, ...(a.maxAgeS !== undefined ? { max_age: pyNum(a.maxAgeS) } : {}), ...(a.skewS !== undefined ? { skew: pyNum(a.skewS) } : {}) }));
  const r = spawnSync('python3', ['-I', '-c', code, path.join(__dirname, '..', 'python')], { input: JSON.stringify(input), encoding: 'utf8', timeout: 30000, killSignal: 'SIGKILL' });   // a broken check fails, never hangs
  assert.ifError(r.error); assert.equal(r.status, 0, r.stderr); return JSON.parse(r.stdout);
}

test('a signed delivery verifies in both clients, with the event and its id', () => {
  const d = deliver(), js = verifyWebhook(args(d)), [p] = py([args(d)]);
  assert.equal(js.ok, true, js.why); assert.equal(js.webhookId, 'evt_01'); assert.deepEqual(js.event, JSON.parse(d.body));
  assert.equal(p.ok, true, p.why); assert.equal(p.webhook_id, 'evt_01'); assert.deepEqual(p.event, JSON.parse(d.body));
});

test('header names in any case, a Fetch Headers object, a Map, and a Buffer or Uint8Array body all verify', () => {
  const d = deliver(), upper = Object.fromEntries(Object.entries(d.headers).map(([k, v]) => [k.replace(/(^|-)./g, (c) => c.toUpperCase()), v]));
  for (const a of [args(d, { headers: upper }), args(d, { headers: new Headers(d.headers) }), args(d, { headers: new Map(Object.entries(d.headers)) }), args(d, { body: Buffer.from(d.body) }), args(d, { body: new Uint8Array(Buffer.from(d.body)) })]) {
    const r = verifyWebhook(a); assert.equal(r.ok, true, r.why);
  }
  const [p] = py([args(d, { headers: upper })]); assert.equal(p.ok, true, p.why);
});

test('refused in both, each with its why', () => {
  const d = deliver(), sigFor = (n) => `sig1=:${Buffer.alloc(n, 1).toString('base64')}:`;
  const without = (name) => Object.fromEntries(Object.entries(d.headers).filter(([k]) => k !== name));
  const rs = Buffer.from(/sig1=:(.*):/.exec(d.headers.signature)[1], 'base64');
  const rs65 = Buffer.concat([rs.subarray(0, 32), Buffer.from([0]), rs.subarray(32)]);   // r || 0x00 || s
  const NO_KEY = 'no ckrets-event key with that kid', BAD_KEY = 'the ckrets-event key is not a valid EC P-256 key';
  const jwksWith = (k) => ({ keys: [{ ...k, kid: 'ev1', use: 'ckrets-event' }] });
  const cases = [
    ['a changed body', args(d, { body: d.body.replace('revoked', 'expired') }), 'the body does not match content-digest'],
    ['a changed URL', args(d, { url: 'https://hooks.example.com/other' }), 'the signature does not verify'],
    ['a changed webhook-id', args(d, { headers: { ...d.headers, 'webhook-id': 'evt_02' } }), 'the signature does not verify'],
    ['webhook-id differs from the event id (signed that way)', args(deliver({ webhookId: 'evt_other' })), 'webhook-id is not the event id'],
    ['too old', args(deliver({ created: NOW_S - 400 })), 'too old (a replay, or a clock far off)'],
    ['created in the future', args(deliver({ created: NOW_S + 120 })), 'created is in the future (a clock far off)'],
    ['expired', args(deliver({ created: NOW_S - 200, expires: NOW_S - 100 })), 'expired'],
    ['wrong alg', args(deliver({ alg: 'ecdsa-p384-sha384' })), 'unexpected algorithm, tag or components'],
    ['wrong tag', args(deliver({ tag: 'other' })), 'unexpected algorithm, tag or components'],
    ['wrong components', args(deliver({ comps: COMPONENTS.filter((c) => c !== 'content-type') })), 'unexpected algorithm, tag or components'],
    ['an oversized created', args(d, { headers: { ...d.headers, 'signature-input': d.headers['signature-input'].replace(/created=\d+/, 'created=1' + '0'.repeat(20)) } }), 'no ckrets Signature-Input'],
    ['a trailing newline on Signature-Input', args(d, { headers: { ...d.headers, 'signature-input': d.headers['signature-input'] + '\n' } }), 'no ckrets Signature-Input'],
    ['no Signature-Input', args(d, { headers: without('signature-input') }), 'no ckrets Signature-Input'],
    ['no Signature', args(d, { headers: without('signature') }), 'no sig1 Signature'],
    ['no content-type', args(d, { headers: without('content-type') }), 'missing header: content-type'],
    ['no content-digest', args(d, { headers: without('content-digest') }), 'missing header: content-digest'],
    ['no webhook-id', args(d, { headers: without('webhook-id') }), 'missing header: webhook-id'],
    ['a line break in a covered value', args(d, { url: URL_ + '\n"x": y' }), 'a covered value has a line break'],
    ['a malformed Signature (not base64)', args(d, { headers: { ...d.headers, signature: 'sig1=:not*base64:' } }), 'no sig1 Signature'],
    ['a malformed Signature (bad padding)', args(d, { headers: { ...d.headers, signature: `sig1=:${rs.toString('base64').replace(/=+$/, '')}:` } }), 'no sig1 Signature'],
    ['a 65-byte r || 0 || s signature', args(d, { headers: { ...d.headers, signature: `sig1=:${rs65.toString('base64')}:` } }), 'no sig1 Signature'],
    ['a 63-byte signature', args(d, { headers: { ...d.headers, signature: sigFor(63) } }), 'no sig1 Signature'],
    ['signed with the receipt key, under its own kid', args(deliver({ kid: 'rc1', key: RECEIPT.privateKey })), NO_KEY],
    ['signed with the receipt key, under the event kid', args(deliver({ key: RECEIPT.privateKey })), 'the signature does not verify'],
    ['the right key and kid, but its use is not ckrets-event', args(d, { jwks: { keys: [jwk(EVENT, 'ev1', 'sig')] } }), NO_KEY],
    ['valid P-256 x and y, labelled kty OKP', args(d, { jwks: jwksWith({ ...jwk(EVENT), kty: 'OKP' }) }), BAD_KEY],
    ['valid P-256 x and y, labelled crv secp256k1', args(d, { jwks: jwksWith({ ...jwk(EVENT), crv: 'secp256k1' }) }), BAD_KEY],
    ['a JWKS without the event key', args(d, { jwks: { keys: [jwk(RECEIPT, 'rc1', 'sig')] } }), NO_KEY],
    ['an RSA key labelled ckrets-event (PKCS#1 signature)', args(deliver({ key: RSA.privateKey }), { jwks: jwksWith(RSA.publicKey.export({ format: 'jwk' })) }), BAD_KEY],
    ['a P-384 key labelled ckrets-event', args(d, { jwks: jwksWith(P384.publicKey.export({ format: 'jwk' })) }), BAD_KEY],
    ['an EC key with no x or y', args(d, { jwks: jwksWith({ kty: 'EC', crv: 'P-256' }) }), BAD_KEY],
    ['an EC key off the curve', args(d, { jwks: jwksWith({ kty: 'EC', crv: 'P-256', x: Buffer.alloc(32, 1).toString('base64url'), y: Buffer.alloc(32, 2).toString('base64url') }) }), BAD_KEY],
    ['a JWKS that is null', args(d, { jwks: null }), NO_KEY],
    ['a JWKS whose keys is not a list', args(d, { jwks: { keys: 'x' } }), NO_KEY],
    ['a body of null (signed)', args(deliver({ body: 'null' })), 'the body is not a JSON object'],
    ['a body that is a list (signed)', args(deliver({ body: '[1]' })), 'the body is not a JSON object'],
    ['a body that is not JSON (signed)', args(deliver({ body: 'hello' })), 'the body is not a JSON object'],
    ['a body with NaN in it (signed)', args(deliver({ body: '{"id":"evt_01","n":NaN}' })), 'the body is not a JSON object'],
    ['a body with Infinity in it (signed)', args(deliver({ body: '{"id":"evt_01","n":Infinity}' })), 'the body is not a JSON object'],
    ['a body that is not UTF-8 (signed)', args(deliver({ body: Buffer.concat([Buffer.from('{"id":"evt_01","s":"'), Buffer.from([0xff, 0xfe]), Buffer.from('"}')]) })), 'the body is not a JSON object'],
    ['a body with a byte order mark (signed)', args(deliver({ body: '\ufeff{"id":"evt_01"}' })), 'the body is not a JSON object'],
    ['a covered header whose value is null', args(d, { headers: { ...d.headers, 'content-type': null } }), 'missing header: content-type'],
    ['maxAgeS NaN (the window would be off)', args(deliver({ created: NOW_S - 4000 }), { maxAgeS: NaN }), 'malformed input'],
    ['maxAgeS Infinity', args(deliver({ created: NOW_S - 4000 }), { maxAgeS: Infinity }), 'malformed input'],
    ['maxAgeS below zero', args(d, { maxAgeS: -1 }), 'malformed input'],
    ['skewS NaN', args(deliver({ created: NOW_S + 4000 }), { skewS: NaN }), 'malformed input'],
    ['skewS below zero', args(d, { skewS: -5 }), 'malformed input'],
    ['a header twice, in two cases', args(d, { headers: { ...d.headers, 'Webhook-Id': 'evt_02' } }), 'a header appears twice'],
    ['headers that are null', args(d, { headers: null }), 'no ckrets Signature-Input'],
    ['no body', args(d, { body: null }), null],
    ['no url', args(d, { url: undefined }), 'url must be the endpoint you configured, as a string'],
  ];
  const pys = py(cases.map(([, a]) => a));
  cases.forEach(([name, a, why], i) => {
    const js = verifyWebhook(a), p = pys[i];
    assert.equal(js.ok, false, `helper: ${name}`); assert.equal(p.ok, false, `python: ${name}`);
    if (why) { assert.equal(js.why, why, `helper: ${name}`); assert.equal(p.why, why, `python: ${name}`); }
    else { assert.match(js.why, /^body must be the raw bytes/, `helper: ${name}`); assert.match(p.why, /^body must be the raw bytes/, `python: ${name}`); }
  });
});

test('never throws: junk in every argument is a refusal, not an exception', () => {
  const d = deliver();
  assert.equal(verifyWebhook(args(d, { headers: { ...d.headers, 'webhook-id': undefined } })).why, 'missing header: webhook-id', 'an undefined value is a missing header');
  assert.equal(verifyWebhook(args(d, { maxAgeS: '300' })).why, 'malformed input', 'a time option must be a number');
  for (const a of [undefined, null, {}, { url: URL_ }, args(d, { now: NaN }), args(d, { method: 5 }), args(d, { body: { id: 'evt_01' } }), args(d, { headers: 'x' }), args(d, { jwks: { keys: [null, 5, { kid: 'ev1', use: 'ckrets-event', kty: 'EC', crv: 'P-256', x: 5, y: [] }] } })]) {
    assert.equal(verifyWebhook(a).ok, false);
  }
});
