'use strict';
// which ckrets API the client tests run against, as { url, server }.
//   CKRETS_TEST_BASE_URL   a running API over HTTPS (for example ckapi-staging's door); nothing is started
//   CKRETS_API_DIR         a products/ckrets-api checkout, whose offline server (scripts/serve.js) is started here
//                          (default: the sibling folder, when these tests sit in the ckrets API repository)
// Neither one: the suite fails with the reason. It never skips, since a missing API is a failure, not a pass.
const fs = require('fs'), path = require('path');

async function apiUnderTest() {
  const base = process.env.CKRETS_TEST_BASE_URL;
  if (base) {
    if (!/^https?:\/\/[A-Za-z0-9.:-]+\/?$/.test(base)) throw new Error('CKRETS_TEST_BASE_URL must be an origin, like https://staging.ckrets.ai');
    return { url: base.replace(/\/+$/, ''), server: { close() {} }, remote: true };
  }
  const dir = process.env.CKRETS_API_DIR || path.join(__dirname, '..', '..', 'ckrets-api'), serve = path.join(dir, 'scripts', 'serve.js');
  if (!fs.existsSync(serve)) throw new Error(`no ckrets API to test against: set CKRETS_TEST_BASE_URL, or CKRETS_API_DIR to a products/ckrets-api checkout (no ${serve})`);
  return require(serve).start(0);
}
module.exports = { apiUnderTest };
