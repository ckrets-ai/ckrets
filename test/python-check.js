'use strict';
// Whether python3, with the module a test needs, is here. Shared by every test that drives the Python client.
// Only a missing interpreter (ENOENT) or a missing module (ModuleNotFoundError or ImportError) gives a skip reason;
// anything else (a timeout, a signal, another error such as an OpenSSL mismatch) throws, so a broken check fails the
// file instead of skipping quietly. With CKRETS_REQUIRE_PYTHON=1 (CI sets it), a missing one fails too.
const { spawnSync } = require('child_process');

function pythonSkip(code, env = process.env) {
  const r = spawnSync('python3', ['-c', code], { encoding: 'utf8', timeout: 30000, killSignal: 'SIGKILL' });
  let missing;
  if (r.error && r.error.code === 'ENOENT') missing = 'python3 is not installed';
  else if (r.error || r.signal) throw new Error(`the Python check did not finish (${(r.error && r.error.code) || r.signal})`);
  else if (r.status === 0) return false;
  else {
    const m = /^(ModuleNotFoundError|ImportError): .*$/m.exec(r.stderr || '');
    if (!m) throw new Error(`the Python check failed (exit ${r.status}): ${String(r.stderr || '').trim().split('\n').pop()}`);
    missing = m[0];
  }
  if (env.CKRETS_REQUIRE_PYTHON === '1') throw new Error(`CKRETS_REQUIRE_PYTHON=1, but ${missing}`);
  return missing;   // a skip reason
}
module.exports = { pythonSkip, PY_CRYPTOGRAPHY: 'import cryptography', PY_HPKE: 'from cryptography.hazmat.primitives import hpke' };
