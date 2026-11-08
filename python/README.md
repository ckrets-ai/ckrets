# ckrets (Python)

Not on PyPI yet: until the first release, install it from the repository (`pip install ckrets` does not fetch this code
yet).

```bash
git clone https://github.com/ckrets-ai/ckrets.git
python3 -m venv .venv && .venv/bin/pip install ./ckrets/python && . .venv/bin/activate
ckrets reveal ck_SRG73… --env DATABASE_URL -- ./deploy.sh
ckrets reveal https://ckrets.ai/r/ck_SRG73…#k=… --file ~/.config/app/token --mode 0600
ckrets reveal ck_SRG73… --print
```

On Windows, activate with `.venv\Scripts\activate` (or use WSL).

Send a value from a file to a named recipient (its key id, never its key):

```python
import ckrets, pathlib
value = pathlib.Path("db-password.txt").read_text()
c = ckrets.create(value, ttl="1h", audience={"type": "key", "id": "key_7TQM4C…"}, purpose="staging db password")
print(c["url"], c["plaintextDigest"])             # hand on the whole url; never print the value
```

The recipient, with `CKRETS_KEY` in its environment, reveals it into the program that needs it:
`ckrets reveal <token> --env DATABASE_URL -- ./deploy.sh`. The value goes straight there, and your servers handle only
tokens (vault to endpoint). `ckrets.reveal(token)["value"]` in a backend is allowed, but that server then holds the
plaintext: for card data it is in your PCI DSS scope, and for health data it is a system holding ePHI under HIPAA.

Also: `ckrets.status(token, manage_token)`, `ckrets.revoke(token, manage_token)`, `ckrets.limits()` and
`ckrets.mint_key(label=...)`. Every `create` sends an `Idempotency-Key` (a fresh UUID unless you pass
`idempotency_key=`), so a retry with the same one after a lost answer returns the first secret instead of a second.
`create` encrypts the value on your machine before it is sent (`fragment.v1`, the key in the returned `url` after `#k=`;
`hpke.v1` to a `publicKey` audience with an `encJwk`); `plaintext=True` sends it for ckrets to seal instead. A reveal
opens `fragment.v1` from the share URL's `#k=`, and `hpke.v1` with your X25519 private key in `CKRETS_ENC_KEY`. A value this client cannot open is refused before the reveal is spent.

The same proofs and rules as `@ckrets/helper` (https://ckrets.ai/for-agents.md §3): `CKRETS_KEY`, the GitHub Actions
OIDC token, or `CKRETS_SIGNING_KEY`; the value goes only where you say.

Receiving ckrets webhooks (preview)? Check each delivery before acting on it, then dedupe on `webhook_id` (delivery is
at least once):

```python
jwks = ...  # https://ckrets.ai/.well-known/jwks.json, fetched and cached
r = ckrets.verify_webhook("https://hooks.example.com/ckrets", request.headers, request.get_data(), jwks)
if not r["ok"]:
    abort(401)  # r["why"] says what failed
```

`url` is the endpoint you configured, never rebuilt from the `Host` header; the body is the raw bytes as received;
`now`, if you pass it, is in seconds. Only an EC P-256 key whose `use` is `ckrets-event` is accepted. Anything
malformed or missing is `{"ok": False, "why": ...}`; it never raises.
