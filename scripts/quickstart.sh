#!/usr/bin/env bash
# The done check, run by publish.yml before any upload: the packages as an agent installs them (packed, then installed
# fresh in an empty folder), used against one ckrets API: the helper reveals a fresh secret, the Python CLI reveals
# another, the MCP server answers initialize and lists its tools. Fake values only; a value is compared, never printed.
#   bash scripts/quickstart.sh <base url>        e.g. https://ckrets.ai (publish.yml), or an offline server's URL (the test)
set -euo pipefail
BASE=${1:?usage: quickstart.sh <base url>}; ROOT=$(cd "$(dirname "$0")/.." && pwd); T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cd "$ROOT"
npm pack --silent --workspace helper --workspace mcp --pack-destination "$T" > /dev/null
python3 -m build -q python --outdir "$T/py" > /dev/null 2>&1 || python3 -m build python --outdir "$T/py"
cd "$T" && npm init -y > /dev/null && npm install --silent --no-audit --no-fund ./ckrets-helper-*.tgz ./ckrets-mcp-*.tgz
python3 -m venv v && v/bin/pip install -q py/*.whl
export CKRETS_BASE_URL=$BASE
# a fresh anonymous secret (solving the proof-of-work stamp if the tier asks), as the docs' first example does; prints only its share URL
mint() { node -e '
  const crypto = require("crypto"), base = process.env.CKRETS_BASE_URL, value = process.argv[1];
  const zeros = (b) => { let n = 0; for (const x of b) { if (x === 0) { n += 8; continue; } n += Math.clz32(x) - 24; break; } return n; };
  (async () => { const send = (h = {}) => fetch(base + "/v1/secrets", { method: "POST", headers: { "content-type": "application/json", ...h }, body: JSON.stringify({ value, ttl: "15m" }) });
    let r = await send(), j = await r.json();
    if (r.status === 428) { const s = j.stamp; let c = 0; while (zeros(crypto.createHash("sha256").update(`${s.nonce}:${c}`).digest()) < s.difficulty) c++; r = await send({ "ckrets-proof": `stamp=${s.nonce}:${c}` }); j = await r.json(); }
    if (r.status !== 201) { console.error(`create: ${r.status} ${j.type || ""}`); process.exit(3); } process.stdout.write(j.url); })();' "$1"; }
check() { [ "$2" = "$3" ] && echo "ok   $1" || { echo "FAIL $1: the revealed value differs"; exit 1; }; }
v1=FAKE_$(openssl rand -hex 8); u1=$(mint "$v1"); check "helper reveal (npm, fresh install)" "$(node_modules/.bin/ckrets-helper reveal "$u1" --print)" "$v1"
v2=FAKE_$(openssl rand -hex 8); u2=$(mint "$v2"); check "ckrets reveal (PyPI, fresh install)" "$(v/bin/ckrets reveal "$u2" --print)" "$v2"
tools=$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"quickstart","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | timeout 30 node_modules/.bin/ckrets-mcp | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const m=s.trim().split("\n").map(JSON.parse).find(x=>x.id===2);process.stdout.write(((m&&m.result&&m.result.tools)||[]).map(t=>t.name).join(","))})' || true)
case ",$tools," in *,create_secret,*) echo "ok   ckrets-mcp (npm, fresh install): $tools" ;; *) echo "FAIL ckrets-mcp: tools/list gave '$tools'"; exit 1 ;; esac
echo "quickstart ok against $BASE"
