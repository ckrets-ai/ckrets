'use strict';
// Offline: the three packages against products/ckrets-api's offline server (scripts/serve.js), as an agent's host
// would run them. The value reaches only the sink asked for; refusals are exit 3 with the problem type; a sink the
// operator did not configure is refused before anything is revealed. Fake values only.
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('fs'), path = require('path'), os = require('os'), crypto = require('crypto');
const { spawn } = require('child_process');
const { apiUnderTest } = require('./api-under-test');   // the API: CKRETS_TEST_BASE_URL or a ckrets-api checkout

const ROOT = path.join(__dirname, '..'), HELPER = path.join(ROOT, 'helper', 'bin', 'ckrets-helper.js'), MCP = path.join(ROOT, 'mcp', 'bin', 'ckrets-mcp.js');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ckrets-clients-'));
const fake = () => `FAKE_${crypto.randomBytes(8).toString('hex')}`;
const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(CKRETS_|ACTIONS_ID_TOKEN_)/.test(k)));
let srv, sender;
const api = async (method, p, body, bearer) => {
  const r = await fetch(srv.url + p, { method, headers: { 'content-type': 'application/json', ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
};
const mint = async (label) => (await api('POST', '/v1/keys', { label })).j;
const create = async (body) => (await api('POST', '/v1/secrets', { ttl: '1h', ...body }, sender.key)).j;
// async on purpose: the offline server runs in this process, so a blocking spawnSync would starve it
const run = (cmd, args, opts) => new Promise((resolve) => { const ch = spawn(cmd, args, opts); let stdout = '', stderr = ''; ch.stdin.end(opts.input || '');
  ch.stdout.on('data', (d) => { stdout += d; }); ch.stderr.on('data', (d) => { stderr += d; }); ch.on('close', (status) => resolve({ status, stdout, stderr })); });
const helper = (args, env = {}, input) => run(process.execPath, [HELPER, ...args], { env: { ...clean, CKRETS_BASE_URL: srv.url, ...env }, input });
const py = (args, env = {}, input) => run('python3', ['-m', 'ckrets', ...args], { cwd: path.join(ROOT, 'python'), env: { ...clean, CKRETS_BASE_URL: srv.url, PYTHONPATH: path.join(ROOT, 'python'), ...env }, input });
const { pythonSkip, PY_CRYPTO } = require('./python-check');
const noPy = pythonSkip(PY_CRYPTO);   // a skip reason only when python3 or cryptography is missing; otherwise it throws
const echoEnv = (name) => ['--', process.execPath, '-e', `process.stdout.write(process.env.${name} || '')`];
const ed = () => crypto.generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
const jwkFile = (jwk) => { const f = path.join(TMP, `k-${crypto.randomBytes(4).toString('hex')}.jwk`); fs.writeFileSync(f, JSON.stringify(jwk), { mode: 0o600 }); return f; };
function fragmentSeal(plain) {   // /docs/client-encryption.md "The value", fragment mode
  const K = crypto.randomBytes(32), N = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', K, N); c.setAAD(Buffer.from('ckrets:v1'));
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final(), c.getAuthTag()]);
  return { value: `v1.${N.toString('base64url')}.${ct.toString('base64url')}`, k: K.toString('base64url') };
}

test.before(async () => { srv = await apiUnderTest(); sender = await mint('FAKE clients sender'); });
test.after(() => { if (srv) srv.server.close(); fs.rmSync(TMP, { recursive: true, force: true }); });

test('helper: --env gives the value to the child only; the transcript side sees the digest; a second reveal is exit 3 token-gone', async () => {
  const v = fake(), c = await create({ value: v });
  const r = (await helper(['reveal', c.url, '--env', 'DB_PASSWORD', ...echoEnv('DB_PASSWORD')]));
  assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout, v, 'the child got it');
  assert.ok(!r.stderr.includes(v), 'never on stderr'); assert.match(r.stderr, /revealed hmac-sha256:[\w-]{43} \(0 reveals left\), into DB_PASSWORD/);
  const again = (await helper(['reveal', c.token, '--print']));
  assert.equal(again.status, 3); assert.match(again.stderr, /\[token-gone\]/); assert.equal(again.stdout, '');
});

test('helper: --file only with an explicit --mode; the value reaches stdout only with --print; usage errors spend nothing', async () => {
  const v = fake(), c = await create({ value: v, reveals: 3 }), f = path.join(TMP, 'token');
  for (const bad of [['reveal', c.token], ['reveal', c.token, '--env', 'X'], ['reveal', c.token, '--print', '--file', f], ['reveal', c.token, '--file', f, '--mode', '644'], ['reveal', c.token, '--env', 'bad-name', '--', 'true'], ['reveal', c.token, '--file', f], ['reveal', c.token, '--print', '--mode', '0600']])
    assert.equal((await helper(bad)).status, 2, bad.join(' '));
  assert.ok(!fs.existsSync(f), 'no file without --mode');
  const w = (await helper(['reveal', c.token, '--file', f, '--mode', '0600']));
  assert.equal(w.status, 0, w.stderr); assert.equal(fs.readFileSync(f, 'utf8'), v); assert.equal(fs.statSync(f).mode & 0o777, 0o600);
  assert.equal(w.stdout, '', 'nothing on stdout without --print'); assert.ok(!w.stderr.includes(v), 'nor on stderr');
  const p = (await helper(['reveal', c.token, '--print'])); assert.equal(p.stdout, v); assert.match(p.stderr, /1 reveals left/, 'the usage errors spent no reveal');
});

const left = async (c) => (await api('GET', `/v1/secrets/${c.token}/status`, null, c.manageToken)).j.revealsLeft;
async function fileRules(cli, label) {   // shared by the helper and the Python command
  const v = fake(), c = await create({ value: v, reveals: 4 }), d = fs.mkdtempSync(path.join(TMP, `${label}-`));
  const old = path.join(d, 'old'); fs.writeFileSync(old, 'FAKE_previous', { mode: 0o644 }); fs.chmodSync(old, 0o644);
  const keep = await cli(['reveal', c.token, '--file', old, '--mode', '0600']);
  assert.equal(keep.status, 4, keep.stderr); assert.match(keep.stderr, /exists: refused .*nothing was revealed/); assert.equal(fs.readFileSync(old, 'utf8'), 'FAKE_previous'); assert.equal(await left(c), 4, 'nothing spent');
  const forced = await cli(['reveal', c.token, '--file', old, '--mode', '0600', '--force']);
  assert.equal(forced.status, 0, forced.stderr); assert.equal(fs.readFileSync(old, 'utf8'), v); assert.equal(fs.statSync(old).mode & 0o777, 0o600, 'the old, looser mode does not survive');
  const target = path.join(d, 'target'), link = path.join(d, 'link'); fs.writeFileSync(target, 'FAKE_untouched'); fs.symlinkSync(target, link);
  for (const extra of [[], ['--force']]) {
    const r = await cli(['reveal', c.token, '--file', link, '--mode', '0600', ...extra]);
    assert.equal(r.status, 4); assert.match(r.stderr, /symbolic link: refused/); assert.equal(fs.readFileSync(target, 'utf8'), 'FAKE_untouched');
  }
  assert.equal(await left(c), 3, 'the refusals spent nothing');
  const tight = path.join(d, 'new'); process.umask(0o022);
  assert.equal((await cli(['reveal', c.token, '--file', tight, '--mode', '0400'])).status, 0); assert.equal(fs.statSync(tight).mode & 0o777, 0o400);
  assert.equal((await cli(['reveal', c.token, '--print', '--key', 'abc'])).status, 2, 'no --key: a key on the command line shows in the process list');
}
test('helper: --file creates exclusively at the mode, never through a symlink, an existing file only with --force; no --key', () => fileRules(helper, 'h'));

test('helper: reveal - takes the token or share URL (with its #k=) on stdin, out of the process list; the old CKRETS_API_KEY still works as an undocumented fallback', async () => {
  const v = fake(), s = fragmentSeal(v), c = await create({ value: s.value, client_encrypted: true, wrapped_key: 'fragment.v1' });
  const r = await helper(['reveal', '-', '--print'], {}, `${c.url}#k=${s.k}\n`); assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout, v);
  assert.equal((await helper(['reveal', '-', '--print'], {}, '')).status, 2);
  const R = await mint('FAKE clients alias'), ck = await create({ value: v, audience: { type: 'key', id: R.keyId } });
  assert.equal((await helper(['reveal', ck.token, '--print'], { CKRETS_API_KEY: R.key })).stdout, v);
});

test('helper: the audience proofs: CKRETS_KEY for a key audience, CKRETS_SIGNING_KEY (RFC 9421) for a publicKey audience; the wrong one is 403', async () => {
  const R = await mint('FAKE clients recipient'), O = await mint('FAKE clients other');
  const ck = await create({ value: fake(), audience: { type: 'key', id: R.keyId } });
  const wrong = (await helper(['reveal', ck.token, '--print'], { CKRETS_KEY: O.key }));
  assert.equal(wrong.status, 3); assert.match(wrong.stderr, /\[audience-mismatch\]/);
  await new Promise((r) => setTimeout(r, 2200));   // the reveal cooldown after a denial
  assert.equal((await helper(['reveal', ck.token, '--print'], { CKRETS_KEY: R.key })).status, 0);
  const P = ed(), v = fake(), cp = await create({ value: v, audience: { type: 'publicKey', jwk: { kty: 'OKP', crv: 'Ed25519', x: P.x } } });
  const r = (await helper(['reveal', cp.token, '--print'], { CKRETS_SIGNING_KEY: jwkFile(P) }));
  assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout, v); assert.match(r.stderr, /proof: signature/);
  const pass = await create({ value: v, passphrase: 'FAKE-corvid' });
  assert.equal((await helper(['reveal', pass.token, '--print', '--passphrase-env', 'PP'], { PP: 'FAKE-corvid' })).stdout, v, 'a passphrase from an env var, never argv');
});

test('helper: inside GitHub Actions it asks for the job\'s OIDC token with audience https://ckrets.ai and sends it as the bearer', async () => {
  const http = require('http'); let asked = null;
  const gh = http.createServer((q, s) => { asked = { url: q.url, auth: q.headers.authorization }; s.end(JSON.stringify({ value: 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln' })); });
  await new Promise((r) => gh.listen(0, r));
  const c = await create({ value: fake(), audience: { type: 'oidc', issuer: 'https://token.actions.githubusercontent.com', claims: { repository: 'example-org/example', ref: 'refs/heads/main' } } });
  const r = await new Promise((resolve) => { const ch = spawn(process.execPath, [HELPER, 'reveal', c.token, '--print'], { env: { ...clean, CKRETS_BASE_URL: srv.url, ACTIONS_ID_TOKEN_REQUEST_URL: `http://localhost:${gh.address().port}/token?x=1`, ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'FAKE-request-token' } });
    let err = ''; ch.stderr.on('data', (d) => { err += d; }); ch.on('exit', (code) => resolve({ code, err })); });
  gh.close();
  assert.equal(asked.url, '/token?x=1&audience=https%3A%2F%2Fckrets.ai'); assert.equal(asked.auth, 'bearer FAKE-request-token');
  assert.equal(r.code, 3, 'the made-up token is refused by the API'); assert.match(r.err, /^ckrets: 401/);
});

test('helper: a fragment.v1 value decrypts with the share URL\'s #k=; what it cannot open is refused before the reveal is spent', async () => {
  const v = fake(), s = fragmentSeal(v), c = await create({ value: s.value, client_encrypted: true, wrapped_key: 'fragment.v1' });
  const r = (await helper(['reveal', `${c.url}#k=${s.k}`, '--print'])); assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout, v);
  const h = await create({ value: s.value, client_encrypted: true, wrapped_key: 'hpke.v1.ZW5j.Y3Q' });
  // the /public check refuses before spending: hpke.v1 without CKRETS_ENC_KEY, pass.v1 always (Argon2id), a fragment without its k
  const x = (await helper(['reveal', h.token, '--print'])); assert.equal(x.status, 4); assert.match(x.stderr, /CKRETS_ENC_KEY.*\(nothing was revealed\)/); assert.equal(x.stdout, '');
  const p = await create({ value: s.value, clientEncrypted: true, wrappedKey: 'pass.v1.c2FsdA.65536.3.1' });
  const y = (await helper(['reveal', p.token, '--print'])); assert.equal(y.status, 4); assert.match(y.stderr, /Argon2id.*\(nothing was revealed\)/);
  const f = await create({ value: s.value, clientEncrypted: true, wrappedKey: 'fragment.v1' });
  const z = (await helper(['reveal', f.token, '--print'])); assert.equal(z.status, 4); assert.match(z.stderr, /#k=.*\(nothing was revealed\)/);
  for (const t of [h.token, p.token, f.token]) assert.equal((await (await fetch(`${srv.url}/v1/secrets/${t}/public`)).json()).state, 'pending', 'still unrevealed');
});

function mcpSession(env) {
  const ch = spawn(process.execPath, [MCP], { env: { ...clean, CKRETS_BASE_URL: srv.url, ...env } }); let buf = '', id = 0; const waiting = new Map();
  ch.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); waiting.get(m.id)?.(m); } });
  // a server that exits (a missing dependency, a crash) fails the test at once instead of leaving it waiting forever
  let err = '', dead = null; ch.stderr.on('data', (d) => { err += d; });
  ch.on('exit', (code) => { dead = new Error(`the MCP server exited (${code}): ${err.slice(-300)}`); for (const [, w] of waiting) w.reject(dead); waiting.clear(); });
  ch.stdout.removeAllListeners('data');
  ch.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); const w = waiting.get(m.id); if (w) { waiting.delete(m.id); w.resolve(m); } } });
  const rpc = (method, params) => new Promise((resolve, reject) => { if (dead) return reject(dead); const n = ++id; waiting.set(n, { resolve, reject }); ch.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: n, method, params }) + '\n'); });
  return { rpc, close: () => { ch.removeAllListeners('exit'); ch.kill(); }, notify: (method) => ch.stdin.write(JSON.stringify({ jsonrpc: '2.0', method }) + '\n') };
}

test('mcp: initialize, the remote tools plus deliver_secret; reveal_secret off by default, on only with the operator switch', async () => {
  const s = mcpSession({ CKRETS_KEY: sender.key });
  const init = await s.rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } }); s.notify('notifications/initialized');
  assert.equal(init.result.serverInfo.name, 'ckrets-stdio');
  const tools = (await s.rpc('tools/list', {})).result.tools.map((t) => t.name);
  assert.deepEqual(tools, ['create_secret', 'get_secret_status', 'revoke_secret', 'get_limits', 'get_public_view', 'verify_receipt', 'request_secret', 'get_request', 'deliver_secret']);
  const v = fake(), c = await s.rpc('tools/call', { name: 'create_secret', arguments: { value: v, ttl: '15m' } });
  assert.ok(!c.result.isError, JSON.stringify(c.result)); assert.ok(!JSON.stringify(c.result).includes(v), 'create never echoes the value');
  assert.equal((await s.rpc('tools/call', { name: 'reveal_secret', arguments: { token: 'ck_X' } })).error.code, -32602, 'reveal_secret is off');
  s.close();
  // reveal_secret is off by default (absent and unanswered), and only exactly 'true' turns it on
  assert.equal((await (async () => { const d = mcpSession({ CKRETS_ALLOW_REVEAL_IN_CONTEXT: '1' }); const r = (await d.rpc('tools/list', {})).result.tools.some((t) => t.name === 'reveal_secret'); d.close(); return r; })()), false, '"1" is not true');
  const on = mcpSession({ CKRETS_ALLOW_REVEAL_IN_CONTEXT: 'true' });
  assert.ok((await on.rpc('tools/list', {})).result.tools.some((t) => t.name === 'reveal_secret'), 'listed when the operator turns it on');
  const v2 = fake(), c2 = await create({ value: v2 }), rv = (await on.rpc('tools/call', { name: 'reveal_secret', arguments: { token: c2.token } })).result;
  assert.equal(rv.structuredContent.value, v2); assert.equal(rv.structuredContent.revealsLeft, 0); on.close();
});

test('mcp: deliver_secret writes only to configured sinks, returns the digest not the value; anything else is refused before the reveal', async () => {
  const dir = path.join(TMP, 'sinks') + '/', s = mcpSession({ CKRETS_SINKS: `file:${dir},env:APP_TOKEN` });
  const v = fake(), c = await create({ value: v, reveals: 2 });
  for (const sink of ['file:/etc/passwd', `file:${dir}../escape`, 'env:PATH', 'helper', 'shell:rm']) {
    const r = (await s.rpc('tools/call', { name: 'deliver_secret', arguments: { token: c.token, sink } })).result;
    assert.equal(r.isError, true, sink);
  }
  const ok = (await s.rpc('tools/call', { name: 'deliver_secret', arguments: { token: c.token, sink: `file:${dir}app.token` } })).result;
  assert.ok(!ok.isError, JSON.stringify(ok)); assert.equal(fs.readFileSync(`${dir}app.token`, 'utf8'), v); assert.equal(fs.statSync(`${dir}app.token`).mode & 0o777, 0o600);
  assert.ok(!JSON.stringify(ok).includes(v), 'the value is not in the tool result'); assert.match(ok.structuredContent.digest, /^hmac-sha256:/);
  assert.equal(ok.structuredContent.revealsLeft, 1, 'the five refused sinks spent nothing');
  const env = (await s.rpc('tools/call', { name: 'deliver_secret', arguments: { token: c.token, sink: 'env:APP_TOKEN' } })).result;
  assert.ok(!env.isError); assert.ok(!JSON.stringify(env).includes(v)); s.close();
});

test('mcp: a loader, shell or server variable is never a sink, even when the operator lists it; nothing is spent', async () => {
  const bad = ['env:LD_PRELOAD', 'env:DYLD_INSERT_LIBRARIES', 'env:NODE_OPTIONS', 'env:BASH_ENV', 'env:PYTHONPATH', 'env:HTTPS_PROXY', 'env:CKRETS_KEY', 'env:CKRETS_BASE_URL',
    'env:REQUESTS_CA_BUNDLE', 'env:CURL_CA_BUNDLE', 'env:GIT_CONFIG_COUNT', 'env:GIT_CONFIG_KEY_0', 'env:GIT_CONFIG_VALUE_12', 'env:PROMPT_COMMAND', 'env:GIT_ASKPASS', 'env:SSH_ASKPASS'];
  const s = mcpSession({ CKRETS_SINKS: [...bad, 'env:APP_TOKEN'].join(',') }), c = await create({ value: fake(), reveals: 2 });
  for (const sink of bad) {
    const r = (await s.rpc('tools/call', { name: 'deliver_secret', arguments: { token: c.token, sink } })).result;
    assert.equal(r.isError, true, sink); assert.match(r.content[0].text, /never a sink; nothing was revealed/, sink);
  }
  const ok = (await s.rpc('tools/call', { name: 'deliver_secret', arguments: { token: c.token, sink: 'env:APP_TOKEN' } })).result;
  assert.ok(!ok.isError, JSON.stringify(ok)); assert.equal(ok.structuredContent.revealsLeft, 1, 'the refused sinks spent nothing'); s.close();
});

test('python: ckrets reveal --env, --file, --print; key and publicKey proofs; fragment.v1; the API in Python', { skip: noPy }, async () => {
  const v = fake(), c = await create({ value: v, reveals: 3 }), f = path.join(TMP, 'py.token');
  const e = (await py(['reveal', c.url, '--env', 'X', ...echoEnv('X')])); assert.equal(e.status, 0, e.stderr); assert.equal(e.stdout, v); assert.ok(!e.stderr.includes(v));
  assert.equal((await py(['reveal', c.token, '--file', f])).status, 2, '--file needs --mode'); assert.ok(!fs.existsSync(f));
  const pf = await py(['reveal', c.token, '--file', f, '--mode', '0600']); assert.equal(pf.status, 0, pf.stderr); assert.equal(fs.readFileSync(f, 'utf8'), v); assert.equal(fs.statSync(f).mode & 0o777, 0o600);
  assert.equal(pf.stdout, ''); assert.ok(!pf.stderr.includes(v));
  assert.equal((await py(['reveal', c.token, '--print'])).stdout, v); assert.match((await py(['reveal', c.token, '--print'])).stderr, /\[token-gone\]/);
  assert.equal((await py(['reveal', c.token])).status, 2);
  const R = await mint('FAKE py recipient'), ck = await create({ value: v, audience: { type: 'key', id: R.keyId } });
  assert.equal((await py(['reveal', ck.token, '--print'], { CKRETS_KEY: R.key })).stdout, v);
  const P = ed(), cp = await create({ value: v, audience: { type: 'publicKey', jwk: { kty: 'OKP', crv: 'Ed25519', x: P.x } } });
  const sig = (await py(['reveal', cp.token, '--print'], { CKRETS_SIGNING_KEY: jwkFile(P) })); assert.equal(sig.status, 0, sig.stderr); assert.equal(sig.stdout, v);
  const s = fragmentSeal(v), cf = await create({ value: s.value, client_encrypted: true, wrapped_key: 'fragment.v1' });
  assert.equal((await py(['reveal', `${cf.url}#k=${s.k}`, '--print'])).stdout, v);
  const lib = await run('python3', ['-c', 'import ckrets,json; c=ckrets.create("FAKE_py_api", ttl="15m"); r=ckrets.reveal(c["url"]); print(json.dumps([r["value"], ckrets.status(c["token"], c["manageToken"])["state"]]))'],
    { env: { ...clean, CKRETS_BASE_URL: srv.url, PYTHONPATH: path.join(ROOT, 'python') } });
  assert.deepEqual(JSON.parse(lib.stdout), ['FAKE_py_api', 'revealed'], lib.stderr);
});

test('python: the same file rules, stdin and no --key', { skip: noPy }, async () => {
  await fileRules(py, 'p');
  const v = fake(), c = await create({ value: v });
  const r = await py(['reveal', '-', '--print'], {}, `${c.url}\n`); assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout, v);
});

test('mcp: a file sink that exists, or is a symlink, is refused before the reveal', async () => {
  const dir = fs.mkdtempSync(path.join(TMP, 'm-')) + '/', s = mcpSession({ CKRETS_SINKS: `file:${dir}` });
  const c = await create({ value: fake(), reveals: 2 }); fs.writeFileSync(`${dir}there`, 'FAKE_previous'); fs.writeFileSync(`${dir}t`, 'FAKE_untouched'); fs.symlinkSync(`${dir}t`, `${dir}ln`);
  for (const f of ['there', 'ln']) { const r = (await s.rpc('tools/call', { name: 'deliver_secret', arguments: { token: c.token, sink: `file:${dir}${f}` } })).result; assert.equal(r.isError, true, f); assert.match(r.content[0].text, /nothing was revealed/); }
  assert.equal(fs.readFileSync(`${dir}there`, 'utf8'), 'FAKE_previous'); assert.equal(fs.readFileSync(`${dir}t`, 'utf8'), 'FAKE_untouched'); assert.equal(await left(c), 2); s.close();
});

test('unpublished and consistent: private packages, the registry entry names the npm package and the remote, versions agree', async () => {
  const h = require('../helper/package.json'), m = require('../mcp/package.json'), reg = require('../registry/server.json');
  assert.equal(h.private, true); assert.equal(m.private, true);
  assert.match(fs.readFileSync(path.join(ROOT, 'python', 'pyproject.toml'), 'utf8'), /Private :: Do Not Upload/);
  assert.equal(reg.name, m.mcpName); assert.equal(reg.packages[0].identifier, m.name); assert.equal(reg.packages[0].version, m.version); assert.equal(reg.version, m.version);
  assert.deepEqual(reg.remotes, [{ type: 'streamable-http', url: 'https://ckrets.ai/mcp' }]);
  assert.equal(m.dependencies['@ckrets/helper'], h.version);
  const spec = await (await fetch(`${srv.url}/mcp-tools.json`)).json();   // the published schemas, from the API under test
  const deliver = spec.tools.find((t) => t.name === 'deliver_secret'), mine = require('../mcp/lib/server.js');
  assert.ok(deliver && mine, 'deliver_secret is in the published schemas');
});

test('publishing: trusted publishing only (no token), off by default, tests against staging and the quickstart against production first, each upload gated on its review, refused while private; the helper has no dependencies and Python exactly one (cryptography)', () => {
  const wf = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'publish.yml'), 'utf8');
  assert.match(wf, /^on: workflow_dispatch$/m); assert.equal((wf.match(/if: vars\.CKRETS_PUBLISH == 'on'/g) || []).length, 3, 'every job is off unless CKRETS_PUBLISH is on');
  assert.ok(!/NPM_TOKEN|NODE_AUTH_TOKEN|PYPI_TOKEN|password:|secrets\./.test(wf), 'no publishing token anywhere');
  assert.match(wf, /REFUSED: \$\{p\} is still private/); assert.match(wf, /REFUSED: 0\.0\.0 is the PyPI placeholder/);
  const jobs = Object.fromEntries(wf.slice(wf.indexOf('\njobs:\n') + 7).split(/\n(?=  [a-z]+:\n)/).map((b) => [b.trim().split(':')[0], b]));
  assert.deepEqual(Object.keys(jobs), ['test', 'npm', 'pypi']);
  // the tests against ckapi-staging, then the quickstart from a fresh install against production's door, before any upload
  assert.match(jobs.test, /CKRETS_TEST_BASE_URL: '\$\{\{ vars\.CKRETS_STAGING_URL \}\}'/); assert.match(jobs.test, /bash scripts\/quickstart\.sh https:\/\/ckrets\.ai/);
  assert.ok(!/id-token: write/.test(jobs.test), 'the test job cannot publish');
  assert.match(jobs.npm, /needs: test/); assert.match(jobs.npm, /environment: release\n/); assert.match(jobs.npm, /id-token: write/); assert.match(jobs.npm, /ENV_NAME: release/);
  for (const w of ['helper', 'mcp']) assert.match(jobs.npm, new RegExp(`npm publish --workspace ${w} --access public --provenance`));
  // PyPI's trusted publisher names environment pypi and this file
  assert.match(jobs.pypi, /needs: npm/); assert.match(jobs.pypi, /environment: pypi\n/); assert.match(jobs.pypi, /id-token: write/); assert.match(jobs.pypi, /ENV_NAME: pypi/);
  assert.match(jobs.pypi, /pypa\/gh-action-pypi-publish@/); assert.ok(!/pypa\/gh-action-pypi-publish@/.test(jobs.npm + jobs.test) && !/npm publish/.test(jobs.pypi + jobs.test), 'each registry from its own job');
  for (const j of ['npm', 'pypi']) assert.match(jobs[j], /required_reviewers/);
  for (const u of [...wf.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1])) assert.match(u, /@[0-9a-f]{40}$/, u);
  assert.equal(require('../helper/package.json').dependencies, undefined, 'the helper has no dependencies');
  assert.deepEqual(Object.keys(require('../mcp/package.json').dependencies), ['@ckrets/helper'], 'the MCP server only our own helper');
  // exactly one runtime dependency, cryptography at a current major, so a bare install encrypts
  assert.match(fs.readFileSync(path.join(ROOT, 'python', 'pyproject.toml'), 'utf8'), /^dependencies = \["cryptography>=4[2-9]"\]/m);
  // the beta's first real release is 0.9.0 everywhere (never the PyPI placeholder 0.0.0), and every pin agrees
  // semver from 0.9.0 on (0.9.x fixes, 0.10.0 the next minor); the packages may diverge, so each is checked against
  // itself: never the PyPI placeholder 0.0.0, the MCP server's helper dependency and the registry entry follow their
  // packages, and a pin in a README or the code names the package's own version
  const SEMVER = /^0\.(9|[1-9]\d+)\.\d+$/, helperV = require('../helper/package.json').version, mcp = require('../mcp/package.json'), reg = JSON.parse(fs.readFileSync(path.join(ROOT, 'registry', 'server.json'), 'utf8'));
  const pyV = (/^version = "([^"]+)"$/m.exec(fs.readFileSync(path.join(ROOT, 'python', 'pyproject.toml'), 'utf8')) || [])[1];
  for (const [n, v] of [['helper', helperV], ['mcp', mcp.version], ['python', pyV]]) assert.match(v || '', SEMVER, `${n} ${v}: a release from 0.9.0 on, never the placeholder 0.0.0`);
  assert.equal(mcp.dependencies['@ckrets/helper'], helperV, 'the MCP server depends on the helper as released');
  assert.equal(reg.version, mcp.version); for (const p of reg.packages) assert.equal(p.version, mcp.version, 'the registry entry names the MCP package as released');
  assert.match(fs.readFileSync(path.join(ROOT, 'python', 'ckrets', '__init__.py'), 'utf8'), new RegExp(`^__version__ = "${pyV.replace(/\./g, '\\.')}"$`, 'm'));
  const own = { helper: helperV, mcp: mcp.version, sdk: null }, pins = [];
  for (const f of ['README.md', 'helper/README.md', 'mcp/README.md', 'python/README.md', 'helper/lib/index.js', 'mcp/lib/server.js', 'python/ckrets/__init__.py'])
    if (fs.existsSync(path.join(ROOT, f))) for (const m of fs.readFileSync(path.join(ROOT, f), 'utf8').matchAll(/@ckrets\/([a-z]+)@([0-9][0-9A-Za-z.-]*[0-9A-Za-z])/g)) pins.push([f, m[1], m[2]]);
  assert.deepEqual(pins.filter(([, pkg, v]) => (own[pkg] ? v !== own[pkg] : !SEMVER.test(v))).map(([f, pkg, v]) => `${f}: @ckrets/${pkg}@${v}`), [], 'every pin names the package as released');
});

test('quickstart: packed, installed fresh, the helper and the Python CLI reveal and the MCP server lists its tools, against the API under test', async () => {
  const r = await run('bash', [path.join(ROOT, 'scripts', 'quickstart.sh'), srv.url], { env: { ...clean } });
  assert.equal(r.status, 0, r.stdout + r.stderr); assert.match(r.stdout, /quickstart ok against/);
  assert.ok(!/FAKE_[0-9a-f]{16}/.test(r.stdout + r.stderr), 'no value is printed');
});

test('python: an anonymous create answers a 428 by solving its stamp and sending again (a busy tier, or a test deployment that always asks)', { skip: noPy }, async () => {
  // offline the server runs in this process, so this makes it ask every time; staging asks every time already
  const was = process.env.STAMP_MODE; process.env.STAMP_MODE = 'always';
  try {
    const r = await run('python3', ['-c', 'import ckrets,json; c=ckrets.create("FAKE_py_stamp", ttl="15m"); print(json.dumps([bool(c.get("token")), bool(c.get("manageToken"))]))'],
      { cwd: path.join(__dirname, '..', 'python'), env: { ...clean, CKRETS_BASE_URL: srv.url } });
    assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout.trim(), '[true, true]');
  } finally { if (was === undefined) delete process.env.STAMP_MODE; else process.env.STAMP_MODE = was; }
});

test('python: a stamp over 26 bits is refused at once with a clear error (a wrong base URL cannot make it spin)', { skip: noPy }, async () => {
  const r = await run('python3', ['-c', 'import ckrets\ntry:\n  ckrets.solve_stamp("x", 40)\nexcept ckrets.CkretsError as e:\n  print(e.status, "at most 26" in str(e))'], { cwd: path.join(__dirname, '..', 'python'), env: { ...clean } });
  assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout.trim(), '428 True');
});

test('python parity: revoke, limits, mint_key, an Idempotency-Key on every create (a retry replays), clientEncrypted in camelCase', { skip: noPy }, async () => {
  const r = await run('python3', ['-c', `
import ckrets, json, os
k = ckrets.mint_key(label="FAKE python parity")
env = {**os.environ, "CKRETS_KEY": k["key"]}
lim = ckrets.limits(env=env)
a = ckrets.create("FAKE_py_idem", ttl="15m", idempotency_key="FAKE-py-idem-1", env=env)
b = ckrets.create("FAKE_py_idem", ttl="15m", idempotency_key="FAKE-py-idem-1", env=env)
c = ckrets.create("FAKE_py_auto", ttl="15m", env=env); d = ckrets.create("FAKE_py_auto", ttl="15m", env=env)
e = ckrets.create("v1.AAAAAAAAAAAAAAAA.BBBB", ttl="15m", client_encrypted=True, wrapped_key="fragment.v1", env=env)
pub = ckrets._request("GET", os.environ["CKRETS_BASE_URL"] + "/v1/secrets/" + e["token"] + "/public")[1]
rv = ckrets.revoke(a["token"], a["manageToken"], env=env)
st = ckrets.status(a["token"], a["manageToken"], env=env)["state"]
print(json.dumps({"tier": lim.get("tier"), "same": a["token"] == b["token"], "auto_differ": c["token"] != d["token"], "kid": k["keyId"][:4],
  "ce": [pub.get("clientEncrypted"), pub.get("wrappedKey")], "revoked": rv, "state": st}))`], { env: { ...clean, CKRETS_BASE_URL: srv.url, PYTHONPATH: path.join(ROOT, 'python') } });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), { tier: 'free', same: true, auto_differ: true, kid: 'key_', ce: [true, 'fragment.v1'], revoked: true, state: 'revoked' });
});

test('python: hpke.v1 opens what Python cryptography\'s own HPKE seals; refused before the reveal without CKRETS_ENC_KEY', { skip: noPy }, async () => {
  const r = await run('python3', ['-c', `
import ckrets, os, json
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
s = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)
ok = 0
for _ in range(5):
    sk = X25519PrivateKey.generate(); K = os.urandom(32); out = s.encrypt(K, sk.public_key(), info=b"ckrets wrap v1")
    ok += ckrets.hpke_open(out[:32], out[32:], sk) == K
print(json.dumps({"ok": ok, "refuse": ckrets.can_open("hpke.v1", None, {}) is not None}))`], { env: { ...clean, PYTHONPATH: path.join(ROOT, 'python') } });
  assert.equal(r.status, 0, r.stderr); assert.deepEqual(JSON.parse(r.stdout), { ok: 5, refuse: true });
});

// ask a person through a page, never in chat. request prints the page url (and the requestId); the person answers
// on the page (same origin); wait prints the token, which only the asking key reveals.
for (const [name, cli] of [['helper', helper], ['python', py]]) {
  test(`${name}: request prints the page url, wait prints the token once answered, and only the asking key reveals it`, { skip: name === 'python' && noPy }, async () => {
    const k = await mint(`FAKE clients ${name} asker`), env = { CKRETS_KEY: k.key };
    assert.equal((await cli(['request', '--prompt', 'Your code'])).status, 2, 'no key: refused before any call');
    const q = await cli(['request', '--prompt', 'Enter the code from your authenticator', '--kind', 'otp', '--plaintext'], env);   // the plain path (both encrypt by default)
    assert.equal(q.status, 0, q.stderr); const [url, id] = q.stdout.trim().split('\n');
    assert.equal(url, `${srv.url}/q/${id}`); assert.match(id, /^ckq_[0-9A-Z]{26}$/); assert.ok(!q.stdout.includes('ckm_'), 'no manage token printed');
    const code = String(crypto.randomInt(100000, 999999));
    const a = await fetch(`${srv.url}/v1/requests/${id}/answer`, { method: 'POST', headers: { 'content-type': 'application/json', origin: srv.url }, body: JSON.stringify({ value: code }) });
    assert.equal(a.status, 200);
    const w = await cli(['wait', id], env); assert.equal(w.status, 0, w.stderr); const token = w.stdout.trim(); assert.match(token, /^ck_[0-9A-Z]{26}$/);
    const other = await mint(`FAKE clients ${name} other`);
    assert.equal((await cli(['reveal', token, '--print'], { CKRETS_KEY: other.key })).status, 3, 'another key is refused');
    const r = await cli(['reveal', '-', '--env', 'OTP', ...echoEnv('OTP')], env, token);
    assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout, code);
  });
}

// every client sends the dated contract it was built against (Ckrets-Version); the API serves that date and
// echoes its own on every answer
test('the helper, the MCP server and the Python client send one Ckrets-Version, and the API serves it', async () => {
  const H = require('../helper/lib'), pyv = /^API_VERSION = "(\d{4}-\d{2}-\d{2})"/m.exec(fs.readFileSync(path.join(ROOT, 'python', 'ckrets', '__init__.py'), 'utf8'));
  assert.match(H.API_VERSION, /^\d{4}-\d{2}-\d{2}$/); assert.equal(pyv && pyv[1], H.API_VERSION, 'Python sends the same date');
  assert.match(fs.readFileSync(path.join(ROOT, 'mcp', 'lib', 'server.js'), 'utf8'), /'ckrets-version': require\('@ckrets\/helper'\)\.API_VERSION/);
  const r = await fetch(`${srv.url}/v1/limits`, { headers: { 'ckrets-version': H.API_VERSION } }); assert.equal(r.status, 200);
  assert.equal(r.headers.get('ckrets-version'), H.API_VERSION, 'the API serves the date the clients send');
});
