'use strict';
// @ckrets/mcp (for-agents.md §4): the stdio MCP server. JSON-RPC 2.0, one message per line on stdin/stdout.
// create_secret encrypts the value here and creates over the REST API (ckrets stores ciphertext); get_secret_status,
// revoke_secret, get_limits, get_public_view, verify_receipt, request_secret and get_request are forwarded to the remote
// server (<base>/mcp), so both answer the same; deliver_secret reveals here, through @ckrets/helper, into a sink the operator configured and
// returns only the digest and the receipt. reveal_secret, the one tool that returns a value, is listed and answered only
// when the operator sets CKRETS_ALLOW_REVEAL_IN_CONTEXT=true (for-agents.md §4); off by default.
//   CKRETS_BASE_URL   default https://ckrets.ai          CKRETS_KEY       the bearer for every call (optional: anonymous)
//   CKRETS_SINKS      comma-separated sinks deliver_secret may use: env:NAME, file:/exact/path or file:/dir/ (a prefix
//                     ending in /), helper. Nothing else is written, whatever the model asks (a prompt cannot add one).
//                     A file sink is created exclusively at 0600 and never through a symlink; an existing file is refused.
const fs = require('fs'), path = require('path'), os = require('os'), crypto = require('crypto'), { reveal, create, fileRefusal, writeSecretFile } = require('@ckrets/helper');

const VERSION = '2025-06-18', NAME = 'ckrets-stdio', PKG = require('../package.json');
const DELIVER = { name: 'deliver_secret', description: 'Reveal a token into a sink the operator configured, never into this conversation: an environment variable of this server process, a file with mode 0600, or the ckrets helper. Counts as the reveal; returns the receipt and the digest.',
  inputSchema: { type: 'object', required: ['token', 'sink'], properties: { token: { type: 'string', description: 'The token, or the whole share url: a value encrypted on the sender\'s machine (create_secret here does that) needs the url, whose #k= holds its key' }, passphrase: { type: 'string' }, sink: { type: 'string', pattern: '^(env:[A-Z_][A-Z0-9_]*|file:.+|helper)$', description: 'env:NAME, file:/path (0600), or helper; only sinks listed in CKRETS_SINKS' } } },
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true } };
const REVEAL = { name: 'reveal_secret', description: 'Return a value into this conversation. Enabled by the operator (CKRETS_ALLOW_REVEAL_IN_CONTEXT=true); prefer deliver_secret. Counts as the reveal.',
  inputSchema: { type: 'object', required: ['token'], properties: { token: { type: 'string', description: 'The token, or the whole share url (its #k= opens a value encrypted on the sender\'s machine)' }, passphrase: { type: 'string' } } }, annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true } };
// create_secret runs here, not on the remote server: the value is encrypted on this machine (fragment.v1, or
// hpke.v1 to a publicKey audience with an encJwk) and ckrets stores ciphertext; plaintext: true opts out. A value the
// caller already encrypted (clientEncrypted) is forwarded as it is.
const CREATE_DESC = 'Store a value and get a link that reveals it once. The value is encrypted on this machine before it is sent: ckrets stores ciphertext it holds no key for, and the key is in the returned url after #k= (give the recipient the whole url; for a publicKey audience with an encJwk only that key opens it). plaintext: true sends it for ckrets to seal instead. Returns url, token, manageToken, expiresAt, digest, plaintextDigest, encryption and a signed receipt; never the value. The digestKey is left out unless includeDigestKey: true. Do not send short values (codes, PINs) through this tool.';
// request_secret makes an X25519 key pair here, keeps the private JWK at 0600 on this machine
// (~/.config/ckrets/requests/<requestId>.jwk, as the helper does) and sends encJwk, so the person's browser encrypts the
// answer to it; get_request remembers which key opens the token, and deliver_secret and reveal_secret use it.
const REQUEST_NOTE = ' Here the answer is encrypted in the person\'s browser to a key this server makes and keeps on this machine (deliver_secret opens it); plaintext: true lets ckrets seal it instead.';
const REMOTE = ['create_secret', 'get_secret_status', 'revoke_secret', 'get_limits', 'get_public_view', 'verify_receipt', 'request_secret', 'get_request'];
// Variables that change how programs load or run, or how this server runs, are never
// a sink, even if the operator listed one: a value written there would run as code (LD_PRELOAD, NODE_OPTIONS, BASH_ENV),
// redirect a lookup (PATH, PYTHONPATH, a proxy or CA file), or reconfigure this server (CKRETS_KEY is read on every call)
const REFUSED_ENV = /^(?:LD_[A-Z0-9_]*|DYLD_[A-Z0-9_]*|CKRETS_[A-Z0-9_]*|PATH|NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|BASH_ENV|ENV|ZDOTDIR|SHELLOPTS|IFS|PS4|PERL5LIB|PERL5OPT|RUBYOPT|RUBYLIB|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|HOME|TMPDIR|SSL_CERT_FILE|SSL_CERT_DIR|HTTP_PROXY|HTTPS_PROXY|NO_PROXY|ALL_PROXY|GIT_SSH_COMMAND|GIT_EXEC_PATH|GIT_ASKPASS|SSH_ASKPASS|GIT_CONFIG_COUNT|GIT_CONFIG_KEY_[0-9]+|GIT_CONFIG_VALUE_[0-9]+|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|PROMPT_COMMAND)$/;
const refusedSink = (sink) => sink.startsWith('env:') && REFUSED_ENV.test(sink.slice(4));

function createServer(env = process.env) {
  const revealOn = env.CKRETS_ALLOW_REVEAL_IN_CONTEXT === 'true';   // exactly 'true', nothing looser
  const base = (env.CKRETS_BASE_URL || 'https://ckrets.ai').replace(/\/+$/, ''), held = {};   // env: sinks live in this process
  const listed = String(env.CKRETS_SINKS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const sinks = listed.filter((s) => !refusedSink(s));   // a refused variable is dropped from the operator's list, said once on stderr
  for (const s of listed.filter(refusedSink)) process.stderr.write(`ckrets-mcp: CKRETS_SINKS ${s} is a loader, shell or server variable and is never a sink; ignored\n`);
  const allowed = (sink) => sinks.some((s) => s === sink || (s.startsWith('file:/') && s.endsWith('/') && sink.startsWith(s) && !sink.slice(s.length).split('/').includes('..')));
  async function remote(method, params) {
    const r = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'ckrets-version': require('@ckrets/helper').API_VERSION, ...((env.CKRETS_KEY || env.CKRETS_API_KEY) ? { authorization: `Bearer ${env.CKRETS_KEY || env.CKRETS_API_KEY}` } : {}) },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
    const j = await r.json(); if (j.error) throw Object.assign(new Error(j.error.message), { rpc: j.error }); return j.result;
  }
  const reqDir = () => path.join(env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'ckrets', 'requests'), tokenKeys = {};
  async function localRequest(a) {
    const { plaintext, ...args } = a;
    if (plaintext === true || args.encJwk) return remote('tools/call', { name: 'request_secret', arguments: args });
    const sk = crypto.generateKeyPairSync('x25519').privateKey, encJwk = { kty: 'OKP', crv: 'X25519', x: crypto.createPublicKey(sk).export({ format: 'jwk' }).x };
    fs.mkdirSync(reqDir(), { recursive: true, mode: 0o700 });
    const tmp = path.join(reqDir(), `pending-${crypto.randomBytes(6).toString('hex')}.jwk`);
    writeSecretFile(tmp, JSON.stringify(sk.export({ format: 'jwk' })), 0o600);   // before the request is sent: a lost key would strand the answer
    let r; try { r = await remote('tools/call', { name: 'request_secret', arguments: { ...args, encJwk } }); } catch (e) { fs.rmSync(tmp, { force: true }); throw e; }
    const id = r && r.structuredContent && r.structuredContent.requestId;
    if (!id) { fs.rmSync(tmp, { force: true }); return r; }
    fs.renameSync(tmp, path.join(reqDir(), `${id}.jwk`));
    return r;
  }
  async function localGetRequest(params) {
    const r = await remote('tools/call', params), sc = r && r.structuredContent;
    if (sc && sc.state === 'fulfilled' && sc.token && sc.requestId) { const f = path.join(reqDir(), `${sc.requestId}.jwk`); if (fs.existsSync(f)) tokenKeys[sc.token] = f; }
    return r;
  }
  // the env for a reveal: the request's own key when this server made it
  const revealEnv = (token) => { const m = /ck_[0-9A-HJKMNP-TV-Z]{26}/.exec(String(token || '')); return m && tokenKeys[m[0]] ? { ...env, CKRETS_ENC_KEY: tokenKeys[m[0]] } : env; };
  const text = (t, isError = false, structured) => ({ content: [{ type: 'text', text: t }], ...(structured ? { structuredContent: structured } : {}), ...(isError ? { isError: true } : {}) });
  async function deliver(a) {
    if (!/^(env:[A-Z_][A-Z0-9_]*|file:.+|helper)$/.test(String(a.sink || ''))) return text('sink must be env:NAME, file:/path or helper', true);
    if (refusedSink(a.sink)) return text(`sink ${a.sink} is a loader, shell or server variable and is never a sink; nothing was revealed`, true);
    if (!allowed(a.sink)) return text(`sink ${a.sink} is not one the operator configured (CKRETS_SINKS); nothing was revealed`, true);
    if (a.sink === 'helper') return text('the helper sink is not in this version: use env: or file:, or run npx @ckrets/helper reveal yourself; nothing was revealed', true);
    if (a.sink.startsWith('file:')) { const why = fileRefusal(a.sink.slice(5), false); if (why) return text(`${why}; nothing was revealed (the operator removes it first)`, true); }
    let r; try { r = await reveal(String(a.token || ''), { passphrase: a.passphrase, env: revealEnv(a.token) }); } catch (e) { return text(`ckrets: ${e.message}${e.type ? ` [${e.type}]` : ''}`, true); }
    if (a.sink.startsWith('env:')) { held[a.sink.slice(4)] = true; process.env[a.sink.slice(4)] = r.value; }
    else { const f = a.sink.slice(5); fs.mkdirSync(path.dirname(f), { recursive: true, mode: 0o700 }); writeSecretFile(f, r.value, 0o600); }   // exclusive, no link followed
    const out = { delivered: true, sink: a.sink, digest: r.digest, revealsLeft: r.revealsLeft, receipt: r.receipt };
    return text(`Delivered into ${a.sink}. digest ${r.digest}, ${r.revealsLeft} reveals left. The value is not in this conversation.`, false, out);
  }
  async function localCreate(a) {
    const { value, includeDigestKey, idempotencyKey, plaintext, ttl, reveals, passphrase, audience, purpose, ...rest } = a;
    const unknown = Object.keys(rest)[0]; if (unknown) return text(`unknown argument "${unknown}"; nothing was created`, true, { status: 400 });
    let r; try { r = await create(value, { ttl, reveals, passphrase, audience, purpose, plaintext: plaintext === true, ...(idempotencyKey !== undefined ? { idempotencyKey } : {}), env }); }
    catch (e) { return text(`ckrets: ${e.message}${e.type ? ` [${e.type}]` : ''}`, true, { status: e.status || 400, ...(e.type ? { type: e.type } : {}) }); }
    const { digestKey, k, idempotencyKey: _ik, ...out } = r, result = { status: 201, ...out, ...(includeDigestKey === true && digestKey ? { digestKey } : {}) };
    return { ...text(JSON.stringify(result), false, result), isError: false };
  }
  async function handle(msg) {
    const { id, method, params = {} } = msg;
    if (id === undefined) return null;   // notifications (notifications/initialized and the like)
    try {
      if (method === 'initialize') return { protocolVersion: VERSION, capabilities: { tools: { listChanged: false } }, serverInfo: { name: NAME, version: PKG.version },
        instructions: 'Create secret tokens (encrypted on this machine before they are sent), check status and revoke them; deliver a token into a configured sink with deliver_secret. Give recipients the url or token, never the value.' };
      if (method === 'ping') return {};
      if (method === 'tools/list') {
        const tools = (await remote('tools/list', {})).tools.filter((t) => REMOTE.includes(t.name)).map((t) => (t.name !== 'create_secret' ? t
          : { ...t, description: CREATE_DESC, inputSchema: { ...t.inputSchema, properties: { ...(t.inputSchema.properties || {}), plaintext: { type: 'boolean', default: false, description: 'Send the value for ckrets to seal (ckrets could read it) instead of encrypting it here' } } } }))
          .map((t) => (t.name !== 'request_secret' ? t : { ...t, description: t.description + REQUEST_NOTE, inputSchema: { ...t.inputSchema, properties: { ...(t.inputSchema.properties || {}), plaintext: { type: 'boolean', default: false, description: 'Let ckrets seal the answer (it could read it) instead of having it encrypted in the person\'s browser' } } } }));
        return { tools: [...tools, DELIVER, ...(revealOn ? [REVEAL] : [])] };
      }
      if (method === 'tools/call') {
        const a = params.arguments || {};
        if (params.name === 'create_secret' && a.clientEncrypted === undefined && a.wrappedKey === undefined) return await localCreate(a);
        if (params.name === 'request_secret') return await localRequest(a);
        if (params.name === 'get_request') return await localGetRequest(params);
        if (REMOTE.includes(params.name)) return await remote('tools/call', { ...params, arguments: params.name === 'create_secret' ? (({ plaintext, ...x }) => x)(a) : params.arguments });
        if (params.name === 'deliver_secret') return await deliver(a);
        if (params.name === 'reveal_secret' && revealOn) {
          try { const r = await reveal(String(a.token || ''), { passphrase: a.passphrase, env: revealEnv(a.token) }); return text(r.value, false, { value: r.value, revealsLeft: r.revealsLeft, receipt: r.receipt }); }
          catch (e) { return text(`ckrets: ${e.message}${e.type ? ` [${e.type}]` : ''}`, true); }
        }
        return { __error: [-32602, `unknown tool ${params.name}`] };
      }
      return { __error: [-32601, `method not found: ${method}`] };
    } catch (e) { return { __error: [-32603, e.rpc ? e.rpc.message : `ckrets unreachable: ${e.message}`] }; }
  }
  return { handle: async (msg) => { const r = await handle(msg); if (r === null) return null; return r.__error ? { jsonrpc: '2.0', id: msg.id, error: { code: r.__error[0], message: r.__error[1] } } : { jsonrpc: '2.0', id: msg.id, result: r }; }, held };
}

function serveStdio(env = process.env, input = process.stdin, output = process.stdout) {
  const s = createServer(env); let buf = '';
  input.setEncoding('utf8');
  input.on('data', (d) => {
    buf += d; let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1); if (!line) continue;
      let msg; try { msg = JSON.parse(line); } catch { output.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }) + '\n'); continue; }
      s.handle(msg).then((r) => { if (r) output.write(JSON.stringify(r) + '\n'); });
    }
  });
  return s;
}
module.exports = { createServer, serveStdio };
