'use strict';
// our hand-written stdio server against the official MCP SDK's client (@modelcontextprotocol/sdk, a pinned
// dev dependency of this folder only; no published package depends on it): initialize, tools/list, tools/call over stdio.
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('fs'), path = require('path'), os = require('os'), crypto = require('crypto');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');
const { apiUnderTest } = require('./api-under-test');   // the API: CKRETS_TEST_BASE_URL or a ckrets-api checkout

const MCP = path.join(__dirname, '..', 'mcp', 'bin', 'ckrets-mcp.js'), TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ckrets-sdk-'));
const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(CKRETS_|ACTIONS_ID_TOKEN_)/.test(k)));
let srv;
test.before(async () => { srv = await apiUnderTest(); });
test.after(() => { srv.server.close(); fs.rmSync(TMP, { recursive: true, force: true }); });

async function connect(env = {}) {
  const client = new Client({ name: 'ckrets-interop', version: '0.0.0' });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [MCP], env: { ...clean, CKRETS_BASE_URL: srv.url, ...env } }));
  return client;
}

test('the official SDK client: initialize, tools/list (no reveal_secret by default), create_secret and deliver_secret over stdio', async () => {
  const client = await connect({ CKRETS_SINKS: `file:${TMP}/` });
  try {   // a failed assertion must fail the test, never leave the server running and the run hanging
  assert.equal(client.getServerVersion().name, 'ckrets-stdio');
  const names = (await client.listTools()).tools.map((t) => t.name);
  assert.deepEqual(names, ['create_secret', 'get_secret_status', 'revoke_secret', 'get_limits', 'get_public_view', 'verify_receipt', 'request_secret', 'get_request', 'deliver_secret']);
  const value = `FAKE_${crypto.randomBytes(8).toString('hex')}`;
  const created = await client.callTool({ name: 'create_secret', arguments: { value, ttl: '15m' } });
  assert.equal(created.isError, false); assert.equal(created.structuredContent.status, 201); assert.ok(!JSON.stringify(created).includes(value));
  const delivered = await client.callTool({ name: 'deliver_secret', arguments: { token: created.structuredContent.url, sink: `file:${TMP}/sdk.token` } });   // encrypted here, so the whole url (its #k=) opens it
  assert.notEqual(delivered.isError, true, JSON.stringify(delivered)); assert.equal(fs.readFileSync(`${TMP}/sdk.token`, 'utf8'), value);
  assert.ok(!JSON.stringify(delivered).includes(value), 'the value stays out of the result');
  const limits = await client.callTool({ name: 'get_limits', arguments: {} }); assert.equal(limits.structuredContent.status, 200);
  // the SDK checks each result against the tool's outputSchema: the free public view and the receipt check
  const c2 = await client.callTool({ name: 'create_secret', arguments: { value: `FAKE_${crypto.randomBytes(8).toString('hex')}`, ttl: '15m' } });
  const pv = await client.callTool({ name: 'get_public_view', arguments: { token: c2.structuredContent.token } }); assert.equal(pv.structuredContent.state, 'pending');
  const vr = await client.callTool({ name: 'verify_receipt', arguments: { receipt: c2.structuredContent.receipt } }); assert.equal(vr.structuredContent.valid, true);
  } finally { await client.close(); }
});

test('the official SDK client sees reveal_secret only when the operator turns it on', async () => {
  const client = await connect({ CKRETS_ALLOW_REVEAL_IN_CONTEXT: 'true' });
  try { assert.ok((await client.listTools()).tools.some((t) => t.name === 'reveal_secret')); } finally { await client.close(); }
});
