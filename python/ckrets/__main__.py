"""ckrets reveal <token|url|-> (--env NAME -- command [args...] | --file PATH --mode 0600 [--force] | --print) [--passphrase-env VAR]

Also: ckrets request --prompt TEXT [--kind otp|password|text] [--ttl 10m] [--enc-key PATH | --plaintext] (prints the page url
to show the person, then the requestId; the answer is encrypted in their browser to a key made here, kept at 0600) and ckrets wait <requestId> [--timeout SECONDS] (prints the token once answered; only CKRETS_KEY opens it).

The same command and exit codes as @ckrets/helper: the child's own with --env; 0 done; 2 usage; 3 refused by ckrets;
4 could not deliver. The value goes only where you say; everything else to stderr. `-` reads the token or URL from
stdin (not in the process list). --file creates exclusively at the mode, never through a symlink; an existing file only
with --force.
"""
import os, re, subprocess, sys

from . import CkretsError, _requests_dir, file_refusal, request, reveal, wait, write_secret_file

USAGE = __doc__.splitlines()[0]


def parse(argv):
    if len(argv) < 2 or argv[0] != "reveal":
        raise ValueError("reveal <token|url> is required")
    o, rest, i = {"target": argv[1]}, argv[2:], 0
    while i < len(rest):
        a = rest[i]; i += 1
        if a == "--":
            o["command"] = rest[i:]; break
        if a == "--print":
            o["print"] = True
        elif a == "--force":
            o["force"] = True
        elif a in ("--env", "--file", "--mode", "--passphrase-env"):
            if i >= len(rest):
                raise ValueError(f"{a} needs a value")
            o[a[2:].replace("-", "_")] = rest[i]; i += 1
        else:
            raise ValueError(f"unknown argument {a}")
    if sum(bool(o.get(k)) for k in ("env", "file", "print")) != 1:
        raise ValueError("exactly one of --env, --file or --print")
    if o.get("file") and not o.get("mode"):
        raise ValueError("--file PATH needs --mode (say 0600): a value is never written with a default mode")
    if o.get("force") and not o.get("file"):
        raise ValueError("--force goes with --file")
    if o.get("mode") and not o.get("file"):
        raise ValueError("--mode goes with --file")
    if o.get("mode") and not re.match(r"^0[0-7]{3}$", o["mode"]):
        raise ValueError("--mode is octal, like 0600")
    if o.get("env") and not o.get("command"):
        raise ValueError("--env NAME needs -- command [args...]: the value goes to that process only")
    return o


def asking(argv):
    """request and wait: the person answers on a ckrets page, never in this terminal or a chat."""
    cmd, rest, o, pos, i = argv[0], argv[1:], {}, None, 0
    while i < len(rest):
        a = rest[i]; i += 1
        if a in ("--prompt", "--kind", "--ttl", "--timeout", "--enc-key"):
            if i >= len(rest):
                print(f"{a} needs a value\nusage: {USAGE}", file=sys.stderr); return 2
            o[a[2:].replace("-", "_")] = rest[i]; i += 1
        elif a == "--plaintext":
            o["plaintext"] = True
        elif not a.startswith("--") and pos is None:
            pos = a
        else:
            print(f"unknown argument {a}\nusage: {USAGE}", file=sys.stderr); return 2
    if not (os.environ.get("CKRETS_KEY") or os.environ.get("CKRETS_API_KEY")):
        print(f"{cmd} needs CKRETS_KEY: the page names the key that asks, and only it opens the answer\nusage: {USAGE}", file=sys.stderr); return 2
    try:
        if cmd == "request":
            if not o.get("prompt") or pos is not None:
                print(f"request needs --prompt TEXT\nusage: {USAGE}", file=sys.stderr); return 2
            r = request(o["prompt"], kind=o.get("kind"), ttl=o.get("ttl"), plaintext=o.get("plaintext", False), enc_key=o.get("enc_key"))
            print(f"show this page to the person (open until {r['expiresAt']}); then: ckrets wait {r['requestId']}", file=sys.stderr)
            print(f"the answer is encrypted in their browser to your key in {r['encKeyFile']}: reveal with CKRETS_ENC_KEY={r['encKeyFile']}" if r["encKeyFile"] else "the answer is sealed by ckrets (--plaintext), which could read it", file=sys.stderr)
            sys.stdout.write(f"{r['url']}\n{r['requestId']}\n"); return 0
        if not pos:
            print(f"wait needs <requestId>\nusage: {USAGE}", file=sys.stderr); return 2
        st = wait(pos, timeout=float(o.get("timeout") or 3600))
    except CkretsError as e:
        print(f"ckrets: {e}{' [' + e.type + ']' if e.type else ''}", file=sys.stderr); return 3 if e.status else 4
    if st.get("state") != "fulfilled":
        print(f"the request is {st.get('state')}: nothing to reveal", file=sys.stderr); return 3
    kf = os.path.join(_requests_dir(os.environ), f"{pos}.jwk") if st.get("answerEncryption") == "client" else None
    print(f"answered {st.get('fulfilledAt')} ({st.get('answeredBy')}); create receipt {st.get('receiptId')}. Reveal with: {'CKRETS_ENC_KEY=' + kf + ' ' if kf else ''}ckrets reveal - --env NAME -- command", file=sys.stderr)
    sys.stdout.write(f"{st['token']}\n"); return 0


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] in ("request", "wait"):
        return asking(args)
    try:
        o = parse(args)
    except ValueError as e:
        print(f"{e}\nusage: {USAGE}", file=sys.stderr); return 2
    passphrase = os.environ.get(o["passphrase_env"]) if o.get("passphrase_env") else None
    if o.get("passphrase_env") and passphrase is None:
        print(f"--passphrase-env {o['passphrase_env']}: that variable is not set", file=sys.stderr); return 2
    if o["target"] == "-":
        o["target"] = sys.stdin.read().strip()
        if not o["target"]:
            print("reveal -: nothing on stdin", file=sys.stderr); return 2
    if o.get("file"):
        why = file_refusal(o["file"], o.get("force"))
        if why:
            print(f"{why}; nothing was revealed", file=sys.stderr); return 4
    try:
        r = reveal(o["target"], passphrase=passphrase)
    except CkretsError as e:
        print(f"ckrets: {e}{f' [{e.type}]' if e.type else ''}", file=sys.stderr); return 3 if e.status else 4
    note = f"revealed {r['digest'] or ''} ({r['revealsLeft']} reveals left{', proof: ' + r['proof'] if r['proof'] else ''})"
    if o.get("print"):
        sys.stdout.write(r["value"]); sys.stdout.flush(); print(note, file=sys.stderr); return 0
    if o.get("file"):
        try:
            write_secret_file(o["file"], r["value"], int(o["mode"], 8), o.get("force", False))
        except (OSError, CkretsError) as e:
            print(f"could not write {o['file']}: {getattr(e, 'strerror', None) or e} (the reveal is spent)", file=sys.stderr); return 4
        print(f"{note}, into {o['file']} (mode {o['mode']})", file=sys.stderr); return 0
    print(f"{note}, into {o['env']} for {o['command'][0]}", file=sys.stderr)
    try:
        return subprocess.call(o["command"], env={**os.environ, o["env"]: r["value"]})
    except OSError as e:
        print(f"could not start {o['command'][0]}: {e.strerror}", file=sys.stderr); return 4


if __name__ == "__main__":
    sys.exit(main())
