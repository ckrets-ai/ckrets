# ckrets clients

The open-source clients for [ckrets.ai](https://ckrets.ai), one-time secret hand-offs for agents and people:

| Folder | Package | What it does |
|---|---|---|
| `helper/` | `@ckrets/helper` (npm) | `create` a secret, encrypted on your machine first; `reveal` one into a child process's environment, a 0600 file or stdout, never into a transcript; `request` a value from a person through a ckrets page, and `wait` for the answer |
| `mcp/` | `@ckrets/mcp` (npm) | the ckrets MCP server over stdio: `create_secret` encrypts locally, `deliver_secret` reveals into a sink the operator configured, and the remote tools are forwarded to `https://ckrets.ai/mcp` |
| `python/` | `ckrets` (PyPI) | the same in Python: `create`, `reveal`, `status`, `revoke`, `request`, `wait`, and the `ckrets` command |
| `registry/` | `server.json` | the MCP registry entry (`ai.ckrets/ckrets`) |

**Status: beta (0.9.0), not yet published to npm or PyPI.** The API is live at https://ckrets.ai; the guide for agents is
https://ckrets.ai/for-agents.md.

## Encrypted on your machine by default

`create` (in the helper, the Python client and the MCP server's `create_secret`) encrypts the value before it is sent:

- `fragment.v1`: AES-256-GCM under a fresh key, and the key goes in the returned `url` after `#k=`. Browsers and HTTP
  clients never send a fragment to the server, so ckrets stores ciphertext it holds no key for. Give the recipient the
  whole `url`; the token alone can't open the value, and a lost `#k=` can't be recovered.
- `hpke.v1`: when the audience is a `publicKey` with an `encJwk`, the key is sealed to that X25519 key with HPKE (RFC 9180).
- `plaintext: true` (`--plaintext`, `plaintext=True`) opts out: ckrets then seals the value itself and could read it.
  Every answer says which happened (`encryption: "client"` or `"server"`), and so does the signed receipt (`ce`).

The format is public: https://ckrets.ai/docs/client-encryption.md. `request` works the same way: the person's answer is
encrypted in their browser to a key pair made here, and the private key stays on your machine at 0600.

ckrets always sees metadata: who created a secret, when, how big it is, and who revealed it.

## Use

```bash
printf '%s' "$DB_PASSWORD" | npx -y @ckrets/helper@0.9.0 create --ttl 1h        # prints the url (with #k=), then the manage token
npx -y @ckrets/helper@0.9.0 reveal - --env DATABASE_URL -- ./deploy.sh            # the url on stdin; the child process gets the value
npx -y @ckrets/mcp@0.9.0                                                           # the MCP server over stdio
pip install ckrets && ckrets reveal - --file ~/.config/app/token --mode 0600
```

`CKRETS_KEY` is your ckrets key (optional for anonymous use), `CKRETS_BASE_URL` points elsewhere (default
`https://ckrets.ai`), `CKRETS_SIGNING_KEY` and `CKRETS_ENC_KEY` hold the paths of your signing and X25519 key files.

## Develop

Node 22 or later, and Python 3.9 or later with `cryptography>=42`.

```bash
npm ci
CKRETS_TEST_BASE_URL=<a ckrets API you may test against> npm test
bash scripts/quickstart.sh <base url>     # packs, installs fresh and uses each package against that API
```

The tests never skip: without `CKRETS_TEST_BASE_URL` (or `CKRETS_API_DIR`, a checkout of the API with its offline
server) they fail and say so. A test that starts a child process closes it in a `finally`, so a failed assertion never
leaves `node --test` hanging. Every client sends `Ckrets-Version`, the dated API contract it was built against
(`API_VERSION` in `helper/lib/index.js` and `python/ckrets/__init__.py`).

Releases are published only from `.github/workflows/publish.yml`, by trusted publishing (npm provenance and a PyPI
trusted publisher, from GitHub's OIDC token): no registry token exists.

## Security

Report a vulnerability privately through this repository's **Security** tab ("Report a vulnerability"), not in a
public issue.

## Licence

Apache-2.0: see `LICENSE` and `NOTICE`.
