"""ckrets.ai from Python : create, reveal, status, revoke, limits and key minting. create encrypts on this machine by
default (needs the crypto extra, or plaintext=True); the rest is standard library only.

The reveal proof follows for-agents.md section 3 (CKRETS_PROOF names one; otherwise the first available):
key (CKRETS_KEY), oidc (GitHub Actions' id token for audience https://ckrets.ai), signature (CKRETS_SIGNING_KEY, a
private Ed25519 JWK file; needs the crypto extra). Client-encrypted values (the crypto extra): fragment.v1, and hpke.v1
with the recipient's X25519 private key in CKRETS_ENC_KEY (a JWK or PEM file); pass.v1 (Argon2id) is refused by name.
Before a reveal, the free /public view is read, so a value this client could not open is refused before it is spent.
Every create sends an Idempotency-Key (a fresh UUID unless you pass one), so a retry after a lost answer is safe.
"""
import base64, hashlib, hmac, json, os, re, time, urllib.error, urllib.parse, urllib.request, uuid

__version__ = "0.9.0"
API_VERSION = "2026-11-06"  # the dated API contract this client was built against, sent as Ckrets-Version
TOKEN = re.compile(r"ck_[0-9A-HJKMNP-TV-Z]{26}")


class CkretsError(Exception):
    def __init__(self, message, status=None, type=None, retry_after=None, problem=None):
        super().__init__(message)
        self.status, self.type, self.retry_after, self.problem = status, type, retry_after, problem or {}


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _base(env):
    return (env.get("CKRETS_BASE_URL") or "https://ckrets.ai").rstrip("/")


def parse_target(target, env=None):
    """A token, or a share URL: its origin becomes the base and its #k= the fragment key."""
    env = os.environ if env is None else env
    m = TOKEN.search(str(target or ""))
    if not m:
        raise CkretsError("no ckrets token (ck_...) in the argument")
    base, k = _base(env), None
    if re.match(r"^https?://", str(target)):
        u = urllib.parse.urlsplit(str(target))
        base, k = f"{u.scheme}://{u.netloc}", dict(urllib.parse.parse_qsl(u.fragment)).get("k")
    return m.group(0), base, k


def _request(method, url, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"accept": "application/json", "user-agent": f"ckrets-python/{__version__}", "ckrets-version": API_VERSION, **({"content-type": "application/json"} if data else {}), **(headers or {})}
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            text = r.read().decode()
            return r.status, (json.loads(text) if text else {}), dict(r.headers)
    except urllib.error.HTTPError as e:
        text = e.read().decode()
        try:
            j = json.loads(text)
        except ValueError:
            j = {}
        t = str(j.get("type", "")).replace("https://ckrets.ai/problems/", "")
        raise CkretsError(f"{e.code} {j.get('title', '')}{': ' + j['detail'] if j.get('detail') else ''}".strip(), e.code, t, e.headers.get("retry-after"), j) from None


_SEALED = {}  # one encryption per Idempotency-Key in this process, so a repeat sends the same ciphertext


def _seal_value(plain, K):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    n = os.urandom(12)
    return f"v1.{_b64u(n)}.{_b64u(AESGCM(K).encrypt(n, plain.encode(), b'ckrets:v1'))}"


def hpke_seal(enc_jwk, K, info=b"ckrets wrap v1"):
    """HPKE base-mode single-shot seal of K to an X25519 public JWK (an audience's encJwk); returns hpke.v1.<enc>.<ct>."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization as s
    if not isinstance(enc_jwk, dict) or enc_jwk.get("kty") != "OKP" or enc_jwk.get("crv") != "X25519" or not isinstance(enc_jwk.get("x"), str):
        raise CkretsError("audience.encJwk is not an X25519 public JWK")
    pkrm, ske = _unb64u(enc_jwk["x"]), X25519PrivateKey.generate()
    enc = ske.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    dh = ske.exchange(X25519PublicKey.from_public_bytes(pkrm))
    ss = _lexpand(_KEM_ID, _lextract(_KEM_ID, b"", b"eae_prk", dh), b"shared_secret", enc + pkrm, 32)
    ctx = b"\x00" + _lextract(_HPKE_ID, b"", b"psk_id_hash", b"") + _lextract(_HPKE_ID, b"", b"info_hash", info)
    secret = _lextract(_HPKE_ID, ss, b"secret", b"")
    key, nonce = _lexpand(_HPKE_ID, secret, b"key", ctx, 32), _lexpand(_HPKE_ID, secret, b"base_nonce", ctx, 12)
    return f"hpke.v1.{_b64u(enc)}.{_b64u(AESGCM(key).encrypt(nonce, K, b''))}"


def _keyed_digest(digest_key, s):
    return "hmac-sha256:" + _b64u(hmac.new(_unb64u(digest_key), s.encode(), hashlib.sha256).digest())


def create(value, ttl=None, reveals=None, passphrase=None, audience=None, purpose=None, client_encrypted=None, wrapped_key=None, idempotency_key=None, env=None, plaintext=False):
    """Create a secret, encrypted here by default: ckrets stores ciphertext it holds no key for. hpke.v1 when
    the audience is a publicKey with an encJwk, else fragment.v1 (the key K goes in the returned url's #k=, never to
    ckrets). plaintext=True sends the value for ckrets to seal (it could read it). A passphrase stays a server-checked
    gate on top of the link key. A value you encrypted yourself goes as given with client_encrypted and wrapped_key.
    Sends an Idempotency-Key (a fresh UUID unless given): the same call with the same key sends the same ciphertext and
    replays the first secret. Returns the API's answer plus url (with #k= for fragment.v1), k, encryption ("client" or
    "server") and plaintextDigest, the keyed digest of the plaintext computed here (the receipt's dig covers the ciphertext)."""
    env = os.environ if env is None else env
    if not isinstance(value, str) or not value:
        raise CkretsError("value must be a non-empty string; nothing was sent")
    idem = idempotency_key or str(uuid.uuid4())
    fields = {k: v for k, v in {"ttl": ttl, "reveals": reveals, "passphrase": passphrase, "audience": audience, "purpose": purpose}.items() if v is not None}
    own = client_encrypted is not None or wrapped_key is not None
    fp = hashlib.sha256(json.dumps([value, fields, bool(plaintext), own, client_encrypted, wrapped_key, _base(env), bool(_api_key(env))], sort_keys=True).encode()).hexdigest()
    sealed = _SEALED.get(idem)
    if sealed and sealed["fp"] != fp:
        raise CkretsError("this idempotency_key was used with another value or options; use a new key for a new secret (nothing was sent)")
    if not sealed:
        if own:
            body, k = {"value": value, **fields, **{x: y for x, y in {"clientEncrypted": client_encrypted, "wrappedKey": wrapped_key}.items() if y is not None}}, None
        elif plaintext:
            body, k = {"value": value, **fields}, None
        else:
            try:
                K = os.urandom(32)
                hpke = isinstance(audience, dict) and audience.get("type") == "publicKey" and audience.get("encJwk")
                body = {"value": _seal_value(value, K), "clientEncrypted": True, "wrappedKey": hpke_seal(audience["encJwk"], K) if hpke else "fragment.v1", **fields}
            except ImportError:
                raise CkretsError("encrypting needs the cryptography package: pip install 'ckrets[crypto]' (or pass plaintext=True); nothing was sent") from None
            k = None if hpke else _b64u(K)
        cap = 65536 if _api_key(env) else 1024
        size = len(body["value"].encode())
        if size > cap:
            raise CkretsError(f"the value is {size} bytes{'' if plaintext or own else ' once encrypted'} and this tier holds {cap}; nothing was sent", type="value-too-large")
        sealed = _SEALED[idem] = {"fp": fp, "body": body, "k": k}
        if len(_SEALED) > 1000:
            _SEALED.pop(next(iter(_SEALED)))
    body, k = sealed["body"], sealed["k"]
    auth = {"authorization": f"Bearer {_api_key(env)}"} if _api_key(env) else {}
    auth["idempotency-key"] = idem
    try:
        _, j, h = _request("POST", f"{_base(env)}/v1/secrets", body, auth)
    except CkretsError as e:
        # an anonymous create when the tier is busy (or on a test deployment that always asks): 428 carries a stamp;
        # solve it and send the create again once, as the docs say (limits.md, the stamp)
        st = e.problem.get("stamp") if e.status == 428 else None
        if not st or not st.get("nonce"):
            raise
        _, j, h = _request("POST", f"{_base(env)}/v1/secrets", body, {**auth, "ckrets-proof": f"stamp={st['nonce']}:{solve_stamp(st['nonce'], int(st.get('difficulty', 11)))}"})
    hl = {x.lower(): y for x, y in (h or {}).items()}
    out = {**j, "encryption": hl.get("ckrets-encryption") or ("client" if body.get("clientEncrypted") else "server")}
    if k:
        out["url"], out["k"] = f"{j['url']}#k={k}", k
    if j.get("digestKey") and not own:
        out["plaintextDigest"] = _keyed_digest(j["digestKey"], value)
    return out


MAX_STAMP_BITS = 26  # the docs ask 11 bits (about 2,000 hashes); 26 is about 67 million, past which a server is not ckrets


def solve_stamp(nonce, difficulty):
    """The smallest counter whose sha256(nonce + ":" + counter) starts with `difficulty` zero bits. Refuses more than
    MAX_STAMP_BITS, so a wrong base URL cannot make the client spin for ever."""
    need, c = int(difficulty), 0
    if need < 0 or need > MAX_STAMP_BITS:
        raise CkretsError(f"428 the server asks a {need}-bit stamp; this client solves at most {MAX_STAMP_BITS} (is CKRETS_BASE_URL right?)", 428, "proof-of-work-required")
    while True:
        d = hashlib.sha256(f"{nonce}:{c}".encode()).digest()
        bits = 0
        for b in d:
            if b == 0:
                bits += 8
                continue
            bits += 8 - b.bit_length()
            break
        if bits >= need:
            return c
        c += 1


def status(token, manage_token=None, env=None):
    env = os.environ if env is None else env
    bearer = manage_token or _api_key(env)
    return _request("GET", f"{_base(env)}/v1/secrets/{token}/status", None, {"authorization": f"Bearer {bearer}"} if bearer else {})[1]


def revoke(token, manage_token=None, env=None):
    """Revoke a secret with its manage token or the creator's key. True when revoked (204; idempotent)."""
    env = os.environ if env is None else env
    bearer = manage_token or _api_key(env)
    return _request("DELETE", f"{_base(env)}/v1/secrets/{token}", None, {"authorization": f"Bearer {bearer}"} if bearer else {})[0] == 204


def limits(env=None):
    """The caller's tier, counters and resets (GET /v1/limits); its stage says which deployment answered."""
    env = os.environ if env is None else env
    return _request("GET", f"{_base(env)}/v1/limits", None, {"authorization": f"Bearer {_api_key(env)}"} if _api_key(env) else {})[1]


def _requests_dir(env):
    return os.path.join(env.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config"), "ckrets", "requests")


def request(prompt, kind=None, ttl=None, idempotency_key=None, env=None, plaintext=False, enc_key=None):
    """Ask a person for a value through a ckrets page (POST /v1/requests), never in chat. Needs CKRETS_KEY (the page
    names it). By default the answer is encrypted in the person's browser to an X25519 key made here: its
    private JWK is written at 0600 before the request is sent (enc_key=PATH, else ~/.config/ckrets/requests/<requestId>.jwk)
    and the reveal needs it as CKRETS_ENC_KEY. plaintext=True lets ckrets seal the answer instead. Returns {requestId,
    url, expiresAt, state, kind, answerEncryption, encKeyFile}: show url to the person. The manage token is dropped."""
    env = os.environ if env is None else env
    key = _api_key(env)
    if not key:
        raise CkretsError("a request needs CKRETS_KEY: the page shows the person which key asks")
    body = {k: v for k, v in {"prompt": prompt, "kind": kind, "ttl": ttl}.items() if v is not None}
    key_file, tmp = None, False
    if not plaintext:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization as s
        sk = X25519PrivateKey.generate()
        d = sk.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
        x = sk.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
        body["encJwk"] = {"kty": "OKP", "crv": "X25519", "x": _b64u(x)}
        key_file = enc_key or os.path.join(_requests_dir(env), f"pending-{os.urandom(6).hex()}.jwk")
        tmp = enc_key is None
        os.makedirs(os.path.dirname(key_file) or ".", mode=0o700, exist_ok=True)
        write_secret_file(key_file, json.dumps({"kty": "OKP", "crv": "X25519", "x": _b64u(x), "d": _b64u(d)}), 0o600)  # exclusive, no link followed
    try:
        j = _request("POST", f"{_base(env)}/v1/requests", body, {"authorization": f"Bearer {key}", "idempotency-key": idempotency_key or str(uuid.uuid4())})[1]
    except CkretsError:
        if tmp:
            os.remove(key_file)
        raise
    if tmp:
        named = os.path.join(os.path.dirname(key_file), f"{j['requestId']}.jwk")
        os.rename(key_file, named)
        key_file = named
    out = {k: j.get(k) for k in ("requestId", "url", "expiresAt", "state", "kind")}
    out["answerEncryption"] = j.get("answerEncryption") or ("client" if key_file else "server")
    out["encKeyFile"] = key_file
    return out


def wait(request_id, every=5.0, timeout=3600.0, env=None, sleep=time.sleep):
    """Poll a request until the person answers or it closes (every `every` seconds, at least 5). Returns its status;
    when fulfilled it carries `token`, which only this key reveals (reveal() with the same env)."""
    env = os.environ if env is None else env
    key = _api_key(env)
    if not key:
        raise CkretsError("waiting needs CKRETS_KEY (the key that asked)")
    end = time.time() + timeout
    while True:
        j = _request("GET", f"{_base(env)}/v1/requests/{urllib.parse.quote(request_id)}", None, {"authorization": f"Bearer {key}"})[1]
        if j.get("state") != "pending":
            return j
        if time.time() + every > end:
            raise CkretsError(f"still pending after {int(timeout)} s (the request stays open until {j.get('expiresAt')})")
        sleep(max(every, 5.0))


def mint_key(label=None, scope=None, email=None, domain=None, env=None):
    """Mint a free key (a lease): {key, keyId, tier, lease, limits}. Keep the key secret; hand senders the keyId."""
    env = os.environ if env is None else env
    body = {k: v for k, v in {"label": label, "scope": scope, "email": email, "domain": domain}.items() if v is not None}
    return _request("POST", f"{_base(env)}/v1/keys", body)[1]


def _api_key(env):
    return env.get("CKRETS_KEY") or env.get("CKRETS_API_KEY")  # CKRETS_KEY as documented; the other an undocumented fallback


def pick_proof(env):
    have = {"key": bool(_api_key(env)), "oidc": bool(env.get("ACTIONS_ID_TOKEN_REQUEST_URL") and env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")), "signature": bool(env.get("CKRETS_SIGNING_KEY"))}
    p = env.get("CKRETS_PROOF")
    if p:
        if p == "none":
            return None
        if not have.get(p):
            raise CkretsError(f"CKRETS_PROOF={p} but its credential is not set")
        return p
    return next((x for x in ("key", "oidc", "signature") if have[x]), None)


def _sign(method, url, body, jwk):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        raise CkretsError("publicKey proofs need the crypto extra: pip install 'ckrets[crypto]'") from None
    u, now = urllib.parse.urlsplit(url), int(time.time())
    comps, lines, extra = ['"@method"', '"@authority"', '"@path"'], [f'"@method": {method}', f'"@authority": {u.netloc}', f'"@path": {u.path}'], {}
    if body is not None:
        extra["content-digest"] = "sha-256=:" + base64.b64encode(hashlib.sha256(json.dumps(body).encode()).digest()).decode() + ":"
        comps.append('"content-digest"'); lines.append(f'"content-digest": {extra["content-digest"]}')
    keyid = _b64u(hashlib.sha256(json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}, separators=(",", ":")).encode()).digest())
    params = f'({" ".join(comps)});created={now};expires={now + 60};keyid="{keyid}";alg="ed25519";tag="ckrets-v1"'
    lines.append(f'"@signature-params": {params}')
    sig = Ed25519PrivateKey.from_private_bytes(_unb64u(jwk["d"])).sign("\n".join(lines).encode())
    return {**extra, "signature-input": f"sig1={params}", "signature": f"sig1=:{base64.b64encode(sig).decode()}:"}


# ---- HPKE open (RFC 9180, base mode) for hpke.v1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, info "ckrets wrap v1"
_KEM_ID = b"KEM" + (0x0020).to_bytes(2, "big")
_HPKE_ID = b"HPKE" + (0x0020).to_bytes(2, "big") + (0x0001).to_bytes(2, "big") + (0x0002).to_bytes(2, "big")


def _extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()  # an empty salt is HashLen zeros (RFC 5869)


def _expand(prk, info, n):
    t, out, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
    return out[:n]


def _lextract(sid, salt, label, ikm):
    return _extract(salt, b"HPKE-v1" + sid + label + ikm)


def _lexpand(sid, prk, label, info, n):
    return _expand(prk, n.to_bytes(2, "big") + b"HPKE-v1" + sid + label + info, n)


def _enc_key(path):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    raw = open(path, "rb").read().strip()
    key = X25519PrivateKey.from_private_bytes(_unb64u(json.loads(raw)["d"])) if raw.startswith(b"{") else serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, X25519PrivateKey):
        raise CkretsError("CKRETS_ENC_KEY is not an X25519 private key")
    return key


def hpke_open(enc, ct, sk, info=b"ckrets wrap v1"):
    """HPKE base-mode single-shot open of enc.ct with the recipient's X25519 private key; returns the plaintext (K)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization as s
    if len(enc) != 32 or len(ct) < 16:
        raise CkretsError("hpke.v1 wrapped key is malformed")
    dh = sk.exchange(X25519PublicKey.from_public_bytes(enc))
    pkrm = sk.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    ss = _lexpand(_KEM_ID, _lextract(_KEM_ID, b"", b"eae_prk", dh), b"shared_secret", enc + pkrm, 32)
    ctx = b"\x00" + _lextract(_HPKE_ID, b"", b"psk_id_hash", b"") + _lextract(_HPKE_ID, b"", b"info_hash", info)
    secret = _lextract(_HPKE_ID, ss, b"secret", b"")
    key, nonce = _lexpand(_HPKE_ID, secret, b"key", ctx, 32), _lexpand(_HPKE_ID, secret, b"base_nonce", ctx, 12)
    try:
        return AESGCM(key).decrypt(nonce, ct, b"")
    except Exception:
        raise CkretsError("could not open the hpke.v1 wrapped key: CKRETS_ENC_KEY is not the key it was sealed to") from None


def can_open(kind, k, env):
    """Before a reveal: None if this client can open a value of that kind, else why not."""
    if kind == "fragment.v1":
        return None if k else "the value is client-encrypted (fragment.v1): pass the share URL with its #k= (on stdin: reveal -)"
    if kind == "hpke.v1":
        return None if env.get("CKRETS_ENC_KEY") else "the value is client-encrypted to an X25519 key (hpke.v1): set CKRETS_ENC_KEY to the path of its private JWK or PEM"
    return f"client-encrypted with {kind}: not supported by this version (fragment.v1 and hpke.v1 only; pass.v1 needs Argon2id)"


def decrypt(value, wrapped_key, k, env=None):
    if wrapped_key == "fragment.v1":
        if not k:
            raise CkretsError("the value is client-encrypted (fragment.v1): pass the share URL with its #k= (on stdin: reveal -)")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise CkretsError("client-encrypted values need the crypto extra: pip install 'ckrets[crypto]'") from None
        _, n, c = str(value).split(".")
        try:
            return AESGCM(_unb64u(k)).decrypt(_unb64u(n), _unb64u(c), b"ckrets:v1").decode()
        except Exception:
            raise CkretsError("could not decrypt: the k does not match this value") from None
    env = os.environ if env is None else env
    kind = ".".join(str(wrapped_key).split(".")[:2])
    if kind == "hpke.v1":
        if not env.get("CKRETS_ENC_KEY"):
            raise CkretsError(can_open(kind, k, env))
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise CkretsError("client-encrypted values need the crypto extra: pip install 'ckrets[crypto]'") from None
        parts = str(wrapped_key).split(".")
        if len(parts) != 4:
            raise CkretsError("hpke.v1 wrapped key is malformed")
        K = hpke_open(_unb64u(parts[2]), _unb64u(parts[3]), _enc_key(env["CKRETS_ENC_KEY"]))
        _, n, c = str(value).split(".")
        try:
            return AESGCM(K).decrypt(_unb64u(n), _unb64u(c), b"ckrets:v1").decode()
        except Exception:
            raise CkretsError("could not decrypt the value with the hpke.v1 key") from None
    raise CkretsError(can_open(kind, k, env))


def reveal(target, passphrase=None, env=None):
    """Reveal once: {value, revealsLeft, receipt, digest, proof}. The caller decides where the value goes."""
    env = os.environ if env is None else env
    token, base, k = parse_target(target, env)
    url, proof = f"{base}/v1/secrets/{token}", pick_proof(env)
    # the free /public view says whether the value is client-encrypted and how: refuse what cannot be opened before spending
    try:
        pv = _request("GET", f"{url}/public")[1]
    except CkretsError:
        pv = {}
    if pv.get("clientEncrypted") and pv.get("wrappedKey"):
        why = can_open(pv["wrappedKey"], k, env)
        if why:
            raise CkretsError(f"{why} (nothing was revealed)")
    method, body = ("POST", {"passphrase": passphrase}) if passphrase is not None else ("GET", None)
    headers = {}
    if proof == "key":
        headers["authorization"] = f"Bearer {_api_key(env)}"
    elif proof == "oidc":
        _, j, _ = _request("GET", f"{env['ACTIONS_ID_TOKEN_REQUEST_URL']}&audience={urllib.parse.quote('https://ckrets.ai', safe='')}", None, {"authorization": f"bearer {env['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}"})
        headers["authorization"] = f"Bearer {j['value']}"
    elif proof == "signature":
        with open(env["CKRETS_SIGNING_KEY"]) as f:
            headers.update(_sign(method, url, body, json.load(f)))
    _, j, _ = _request(method, url, body, headers)
    digest = "hmac-sha256:" + _b64u(hmac.new(_unb64u(j["digestKey"]), j["value"].encode(), hashlib.sha256).digest()) if j.get("digestKey") else None
    value = j["value"]
    # the API answers camelCase (clientEncrypted, wrappedKey); the snake_case names are read too, for a server before that change
    if j.get("clientEncrypted", j.get("client_encrypted")):
        try:
            value = decrypt(j["value"], j.get("wrappedKey", j.get("wrapped_key")), k, env)
        except CkretsError as e:
            raise CkretsError(f"{e} (the reveal is spent)") from None
    out = {"value": value, "revealsLeft": j.get("revealsLeft"), "receipt": j.get("receipt"), "digest": digest, "proof": proof}
    if j.get("digestKey") and j.get("clientEncrypted", j.get("client_encrypted")):
        out["plaintextDigest"] = _keyed_digest(j["digestKey"], value)  # the same one the sender's create() returned
    return out


def file_refusal(path, force=False):
    """Before a reveal: None if a value may be written at path, else why not. Never a symlink; an existing file only with force."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    import stat as _s
    if _s.S_ISLNK(st.st_mode):
        return f"{path} is a symbolic link: refused, whatever --force says"
    if not _s.S_ISREG(st.st_mode):
        return f"{path} exists and is not a regular file"
    return None if force else f"{path} exists: refused (--force replaces it)"


def write_secret_file(path, value, mode, force=False):
    """Exclusive create at the mode, never following a link (O_EXCL | O_NOFOLLOW); with force an existing regular file is removed first."""
    why = file_refusal(path, force)
    if why:
        raise CkretsError(why)
    if force and os.path.lexists(path):
        os.unlink(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.fchmod(fd, mode)
        os.write(fd, value.encode())
    finally:
        os.close(fd)
