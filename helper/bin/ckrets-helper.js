#!/usr/bin/env node
'use strict';
// ckrets-helper reveal <token|share URL|-> (--env NAME -- command [args…] | --file PATH --mode 0600 [--force] | --print)
//                      [--passphrase-env VAR]
// ckrets-helper request --prompt TEXT [--kind otp|password|text] [--ttl 10m] [--enc-key PATH | --plaintext]   prints the page's
//                      url (show it to the person) and the requestId; never asks for the value itself. The answer is
//                      encrypted in the person's browser to an X25519 key made here (its private JWK at 0600 in PATH, else
//                      ~/.config/ckrets/requests/<requestId>.jwk); --plaintext lets ckrets seal it instead
// ckrets-helper wait <requestId> [--timeout SECONDS]   polls until the person answers; prints the token (only CKRETS_KEY opens it)
// ckrets-helper create [--ttl 15m] [--reveals N] [--purpose TEXT] [--audience-key KEYID] [--passphrase-env VAR] [--plaintext]
//                      reads the value from stdin and encrypts it here (fragment.v1: the key is in the printed url's #k=,
//                      never sent to ckrets); --plaintext sends it for ckrets to seal instead. Prints the url, then the
//                      manage token, on stdout; the encryption, expiry, digests and receipt go to stderr.
// `-` reads the token or share URL from stdin, so neither it nor its #k= shows in the process list. --file creates the
// file exclusively at the mode and never follows a symlink; an existing file is refused unless --force (a link always).
// The value goes only where you say: a child process's environment, a file, or stdout with --print (for apiKeyHelper
// and the like). Everything else, including the digest and reveals left, goes to stderr. Exit codes: the child's own
// with --env; 0 done; 2 usage; 3 refused by ckrets (the problem type is printed); 4 could not deliver.
const fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto'), { spawn } = require('child_process'), { reveal, request, wait, create, CkretsError, fileRefusal, writeSecretFile } = require('../lib');

const USAGE = 'usage: ckrets-helper reveal <token|url|-> (--env NAME -- command [args...] | --file PATH --mode 0600 [--force] | --print) [--passphrase-env VAR]\n       ckrets-helper request --prompt TEXT [--kind otp|password|text] [--ttl 10m] [--enc-key PATH | --plaintext]\n       ckrets-helper wait <requestId> [--timeout SECONDS]\n       ckrets-helper create [--ttl 15m] [--reveals N] [--purpose TEXT] [--audience-key KEYID] [--passphrase-env VAR] [--plaintext]   (the value on stdin)';
function parse(argv) {
  const [cmd, target, ...rest] = argv, o = { cmd, target }; let i = 0;
  while (i < rest.length) {
    const a = rest[i++];
    if (a === '--') { o.command = rest.slice(i); break; }
    if (a === '--print') o.print = true;
    else if (a === '--force') o.force = true;
    else if (['--env', '--file', '--mode', '--passphrase-env'].includes(a)) { if (i >= rest.length) throw new Error(`${a} needs a value`); o[a.slice(2).replace(/-(\w)/g, (_, c) => c.toUpperCase())] = rest[i++]; }
    else throw new Error(`unknown argument ${a}`);
  }
  if (o.cmd !== 'reveal' || !o.target) throw new Error('reveal <token|url> is required');
  const sinks = [o.env, o.file, o.print].filter(Boolean).length; if (sinks !== 1) throw new Error('exactly one of --env, --file or --print');
  if (o.env && !/^[A-Z_][A-Z0-9_]*$/.test(o.env)) throw new Error('--env takes a variable name (A-Z, 0-9, _)');
  if (o.env && !(o.command && o.command.length)) throw new Error('--env NAME needs -- command [args...]: the value goes to that process only');
  if (o.file && !o.mode) throw new Error('--file PATH needs --mode (say 0600): a value is never written with a default mode');
  if (o.mode && !o.file) throw new Error('--mode goes with --file');
  if (o.force && !o.file) throw new Error('--force goes with --file');
  if (o.mode && !/^0[0-7]{3}$/.test(o.mode)) throw new Error('--mode is octal, like 0600');
  return o;
}

const refused = (e) => { if (e instanceof CkretsError) { console.error(`ckrets: ${e.message}${e.type ? ` [${e.type}]` : ''}${e.retryAfter ? ` (retry after ${e.retryAfter} s)` : ''}`); process.exit(e.status ? 3 : 4); } throw e; };
/** request and wait: the person answers on a ckrets page, never in this terminal or a chat. */
async function asking(argv) {
  const [cmd, ...rest] = argv, o = {}; let pos = null;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (['--prompt', '--kind', '--ttl', '--timeout', '--enc-key'].includes(a)) { if (i + 1 >= rest.length) throw new Error(`${a} needs a value`); o[a.slice(2).replace(/-(\w)/g, (_, c) => c.toUpperCase())] = rest[++i]; }
    else if (a === '--plaintext') o.plaintext = true;
    else if (!a.startsWith('--') && pos === null) pos = a; else throw new Error(`unknown argument ${a}`);
  }
  if (!process.env.CKRETS_KEY && !process.env.CKRETS_API_KEY) throw new Error(`${cmd} needs CKRETS_KEY: the page names the key that asks, and only it opens the answer`);
  if (cmd === 'request') {
    if (!o.prompt || pos !== null) throw new Error('request needs --prompt TEXT');
    // by default the answer is encrypted in the person's browser to a key made here; its private half goes to a
    // file at 0600 (--enc-key PATH, else ~/.config/ckrets/requests/<requestId>.jwk), written before the request is sent
    let encJwk, keyFile, tmp;
    if (!o.plaintext) {
      const sk = crypto.generateKeyPairSync('x25519').privateKey; encJwk = { kty: 'OKP', crv: 'X25519', x: crypto.createPublicKey(sk).export({ format: 'jwk' }).x };
      const dir = path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'ckrets', 'requests');
      keyFile = o.encKey || path.join(dir, `pending-${crypto.randomBytes(6).toString('hex')}.jwk`); tmp = !o.encKey;
      fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o700 });
      writeSecretFile(keyFile, JSON.stringify(sk.export({ format: 'jwk' })), 0o600);   // exclusive, no link followed: an existing file is refused
    }
    const r = await request({ prompt: o.prompt, kind: o.kind, ttl: o.ttl, encJwk }).catch((e) => { if (tmp) fs.rmSync(keyFile, { force: true }); return refused(e); });
    if (tmp) { const named = path.join(path.dirname(keyFile), `${r.requestId}.jwk`); fs.renameSync(keyFile, named); keyFile = named; }
    console.error(`show this page to the person (open until ${r.expiresAt}); then: ckrets-helper wait ${r.requestId}`);
    console.error(keyFile ? `the answer is encrypted in their browser to your key in ${keyFile}: reveal with CKRETS_ENC_KEY=${keyFile}` : 'the answer is sealed by ckrets (--plaintext), which could read it');
    process.stdout.write(`${r.url}\n${r.requestId}\n`); return;
  }
  if (!pos) throw new Error('wait needs <requestId>');
  const st = await wait(pos, { timeoutMs: (Number(o.timeout) || 3600) * 1000 }).catch(refused);
  if (st.state !== 'fulfilled') { console.error(`the request is ${st.state}: nothing to reveal`); process.exit(3); }
  const kf = st.answerEncryption === 'client' ? path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'ckrets', 'requests', `${pos}.jwk`) : null;
  console.error(`answered ${st.fulfilledAt} (${st.answeredBy}); create receipt ${st.receiptId}. Reveal with: ${kf ? `CKRETS_ENC_KEY=${kf} ` : ''}ckrets-helper reveal - --env NAME -- command`);
  process.stdout.write(`${st.token}\n`);
}

/** create: the value comes on stdin (never an argument, so it stays out of the process list) and is encrypted here. */
async function creating(argv) {
  const o = {};
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--plaintext') o.plaintext = true;
    else if (['--ttl', '--reveals', '--purpose', '--audience-key', '--passphrase-env'].includes(a)) { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); o[a.slice(2).replace(/-(\w)/g, (_, c) => c.toUpperCase())] = argv[++i]; }
    else throw new Error(`unknown argument ${a}`);
  }
  if (o.reveals !== undefined && !/^[1-9][0-9]*$/.test(o.reveals)) throw new Error('--reveals is a whole number, 1 or more');
  const passphrase = o.passphraseEnv ? process.env[o.passphraseEnv] : undefined;
  if (o.passphraseEnv && passphrase === undefined) throw new Error(`--passphrase-env ${o.passphraseEnv}: that variable is not set`);
  const value = fs.readFileSync(0, 'utf8').replace(/\r?\n$/, '');   // one trailing newline (from echo or a heredoc) is not part of the value
  if (!value) throw new Error('create: nothing on stdin (pipe the value in)');
  const r = await create(value, { ttl: o.ttl, reveals: o.reveals !== undefined ? Number(o.reveals) : undefined, purpose: o.purpose, passphrase, plaintext: o.plaintext === true,
    audience: o.audienceKey ? { type: 'key', id: o.audienceKey } : undefined }).catch(refused);
  console.error(r.encryption === 'client' ? 'encrypted here (fragment.v1): ckrets stores ciphertext; the key is only in the url after #k=. Share the whole url.' : 'sent as plaintext (--plaintext): ckrets sealed it and could read it.');
  console.error(`expires ${r.expiresAt}, ${r.revealsLeft} reveal(s); digest ${r.digest}${r.plaintextDigest ? `, plaintext digest ${r.plaintextDigest}` : ''}`);
  console.error(`receipt ${r.receipt}`);
  process.stdout.write(`${r.url}\n${r.manageToken}\n`);
}

(async () => {
  if (process.argv[2] === 'create') { try { return await creating(process.argv.slice(2)); } catch (e) { if (e instanceof CkretsError) throw e; console.error(`${e.message}\n${USAGE}`); process.exit(2); } }
  if (['request', 'wait'].includes(process.argv[2])) { try { return await asking(process.argv.slice(2)); } catch (e) { if (e instanceof CkretsError) throw e; console.error(`${e.message}\n${USAGE}`); process.exit(2); } }
  let o; try { o = parse(process.argv.slice(2)); } catch (e) { console.error(`${e.message}\n${USAGE}`); process.exit(2); }
  const passphrase = o.passphraseEnv ? process.env[o.passphraseEnv] : undefined;
  if (o.passphraseEnv && passphrase === undefined) { console.error(`--passphrase-env ${o.passphraseEnv}: that variable is not set`); process.exit(2); }
  if (o.target === '-') { o.target = fs.readFileSync(0, 'utf8').trim(); if (!o.target) { console.error('reveal -: nothing on stdin'); process.exit(2); } }
  if (o.file) { const why = fileRefusal(o.file, o.force); if (why) { console.error(`${why}; nothing was revealed`); process.exit(4); } }   // before the reveal: a refusal spends nothing
  let r; try { r = await reveal(o.target, { passphrase }); }
  catch (e) { if (e instanceof CkretsError) { console.error(`ckrets: ${e.message}${e.type ? ` [${e.type}]` : ''}${e.retryAfter ? ` (retry after ${e.retryAfter} s)` : ''}`); process.exit(e.status ? 3 : 4); } throw e; }
  const note = `revealed ${r.digest || ''} (${r.revealsLeft} reveals left${r.proof ? `, proof: ${r.proof}` : ''})`;
  if (o.print) { process.stdout.write(r.value); console.error(note); return; }
  if (o.file) {
    try { writeSecretFile(o.file, r.value, parseInt(o.mode, 8), o.force); }
    catch (e) { console.error(`could not write ${o.file}: ${e.code || e.message} (the reveal is spent; its receipt is below)`); console.error(r.receipt); process.exit(4); }
    console.error(`${note}, into ${o.file} (mode ${o.mode})`); return;
  }
  console.error(`${note}, into ${o.env} for ${o.command[0]}`);
  const child = spawn(o.command[0], o.command.slice(1), { stdio: 'inherit', env: { ...process.env, [o.env]: r.value } });
  child.on('error', (e) => { console.error(`could not start ${o.command[0]}: ${e.code}`); process.exit(4); });
  child.on('exit', (code, signal) => process.exit(signal ? 128 : code));
})();
