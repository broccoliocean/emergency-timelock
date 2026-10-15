#!/usr/bin/env python3
"""Time-lock between the Emergency Code and the Outside Code.

The Emergency Code opens a puzzle; solving it takes a fixed number of sequential
modular squarings (Rivest-Shamir-Wagner), which cannot be split across cores or
machines; the result reveals the Outside Code. The vault itself is untouched:
the Outside Code then goes into decode_outside_vault as always.

  timelock.py bench                        squarings/s of each available backend
  timelock.py create --hours H --out F     reads the Outside Code, checks it against
                                           the vault, prints a fresh Emergency Code, writes F
  timelock.py solve F|TL1:...  [--state P] reads the Emergency Code, solves (resumable),
                                           prints the Outside Code

The puzzle is one line of text, "TL1:" + base32, useless without the Emergency Code, so it may
be stored and printed openly. Standard library only; gmpy2 makes solving ~16x
faster and is what the puzzle is calibrated against.
"""
import argparse, base64, getpass, hashlib, hmac, os, secrets, shutil, struct, subprocess, sys, time

try:
    import gmpy2
except ImportError:
    gmpy2 = None

ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"   # no I L O 0 1
PREFIX = "TL1:"
CHUNK = 1 << 20                                   # squarings per pow() call
PBKDF2_ITERS = 600_000
VAULT_KEY = "/Users/Shared/block_distractions/keys/private_key.enc"


# ------------------------------------------------------------------ primitives
def _keys(secret, salt, iters):
    k = hashlib.pbkdf2_hmac("sha256", secret, salt, iters, dklen=64)
    return k[:32], k[32:]


def _xor(data, ek, salt):
    return bytes(a ^ b for a, b in zip(data, hashlib.shake_256(ek + salt).digest(len(data))))


def seal(secret, plaintext, iters):
    salt = secrets.token_bytes(16)
    ek, mk = _keys(secret, salt, iters)
    ct = _xor(plaintext, ek, salt)
    return salt + hmac.new(mk, salt + ct, "sha256").digest() + ct


def unseal(secret, box, iters):
    salt, tag, ct = box[:16], box[16:48], box[48:]
    ek, mk = _keys(secret, salt, iters)
    if not hmac.compare_digest(tag, hmac.new(mk, salt + ct, "sha256").digest()):
        return None
    return _xor(ct, ek, salt)


def norm_code(s):
    return "".join(c for c in s.upper() if c.isalnum()).encode()


def encode_puzzle(raw):
    return PREFIX + base64.b32encode(raw).decode().rstrip("=")


def decode_puzzle(text):
    s = "".join(text.split()).upper()
    if not s.startswith(PREFIX):
        sys.exit(f"Not a puzzle: expected text starting with {PREFIX}")
    s = s[len(PREFIX):]
    return base64.b32decode(s + "=" * (-len(s) % 8))


def is_probable_prime(n, rounds=40):
    if n < 4:
        return n in (2, 3)
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(rounds):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(c):
            return c


def square_chain(y, k, n):
    """y^(2^k) mod n: exactly k sequential squarings."""
    if gmpy2:
        return int(gmpy2.powmod(gmpy2.mpz(y), gmpy2.mpz(1) << k, gmpy2.mpz(n)))
    return pow(y, 1 << k, n)


def read_secret(prompt):
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return sys.stdin.readline().rstrip("\n")


def opens_vault(code, path):
    """True if code decrypts the vault's age key, exactly as decode_outside_vault does."""
    for ssl in dict.fromkeys(filter(None, [shutil.which("openssl"), "/opt/homebrew/bin/openssl", "/usr/bin/openssl"])):
        r = subprocess.run([ssl, "aes-256-cbc", "-d", "-salt", "-pbkdf2", "-in", path, "-pass", "env:TL_CODE"],
                           env={"TL_CODE": code}, capture_output=True)
        if r.returncode == 0 and b"AGE-SECRET-KEY-" in r.stdout:
            return True
    return False


# ------------------------------------------------------------------ commands
def bench(seconds=5.0):
    n = random_prime(1024) * random_prime(1024)
    y = secrets.randbelow(n)
    results = {}
    backends = [("python-int", lambda y, k: pow(y, 1 << k, n))]
    if gmpy2:
        backends.append(("gmpy2", lambda y, k: int(gmpy2.powmod(gmpy2.mpz(y), gmpy2.mpz(1) << k, gmpy2.mpz(n)))))
    for name, fn in backends:
        done, k, t0 = 0, 1 << 14, time.perf_counter()
        while time.perf_counter() - t0 < seconds:
            y = fn(y, k); done += k
        results[name] = done / (time.perf_counter() - t0)
    return results


def cmd_bench(a):
    for name, rate in bench(a.seconds).items():
        print(f"{name:11} {rate:12,.0f} squarings/s  -> 24h = {rate * 86400:,.0f}")


def cmd_create(a):
    rate = a.rate or max(bench(3.0).values())
    t = int(rate * a.hours * 3600)
    OC = read_secret("Outside Code to time-lock: ")
    if sys.stdin.isatty() and read_secret("Again: ") != OC:
        sys.exit("Codes differ; nothing written.")
    if a.vault != "none" and not opens_vault(OC, a.vault):
        sys.exit(f"That code does not open {a.vault}; nothing written.")
    EC = "-".join("".join(secrets.choice(ALPHABET) for _ in range(7)) for _ in range(4))

    p, q = random_prime(1024), random_prime(1024)
    n, phi = p * q, (p - 1) * (q - 1)
    y = pow(2, pow(2, t, phi), n)                     # the trapdoor shortcut
    del p, q, phi

    inner = struct.pack(">Q", t) + n.to_bytes(256, "big") + seal(y.to_bytes(256, "big"), OC.encode(), 1)
    text = encode_puzzle(seal(norm_code(EC), inner, PBKDF2_ITERS))

    # Verify the written form round-trips before anything is kept.
    chk = unseal(norm_code(EC), decode_puzzle(text), PBKDF2_ITERS)
    assert unseal(y.to_bytes(256, "big"), chk[264:], 1) == OC.encode()

    with open(a.out, "w") as f:
        f.write(text + "\n")
    os.chmod(a.out, 0o644)
    print(f"Wrote {a.out}: {len(text)} chars, t = {t:,} squarings = {a.hours:g} h at {rate:,.0f}/s.")
    print(f"\nEmergency Code (save it in your Passwords; it is stored nowhere else):\n\n    {EC}\n")


def cmd_solve(a):
    src = a.puzzle
    text = open(src).read() if os.path.exists(src) else src
    EC = read_secret("Emergency Code: ")
    inner = unseal(norm_code(EC), decode_puzzle(text), PBKDF2_ITERS)
    if inner is None:
        sys.exit("Wrong Emergency Code, or the puzzle text is damaged.")
    t, n, lock = struct.unpack(">Q", inner[:8])[0], int.from_bytes(inner[8:264], "big"), inner[264:]
    if not gmpy2:
        print("gmpy2 not installed: solving will take ~16x longer. `pip install gmpy2` and restart;"
              " progress is kept.", file=sys.stderr)
    state = a.state or os.path.expanduser(f"~/.timelock_{hashlib.sha256(inner).hexdigest()[:16]}")

    i, y = 0, 2
    if os.path.exists(state):
        with open(state) as f:
            i, y = (int(v) for v in f.read().split())
        print(f"Resuming at {i:,} / {t:,}.")

    t0, i0, last_save = time.time(), i, time.time()
    while i < t:
        k = min(CHUNK, t - i)
        y = square_chain(y, k, n); i += k
        now = time.time()
        if now - last_save > 30 or i == t:
            with open(state + ".tmp", "w") as f:
                f.write(f"{i} {y}\n")
            os.replace(state + ".tmp", state); last_save = now
            rate = (i - i0) / max(now - t0, 1e-9)
            print(f"\r{100 * i / t:6.2f}%  {rate:,.0f}/s  ETA {(t - i) / rate / 3600:5.1f} h ", end="", flush=True)
    print()

    oc = unseal(y.to_bytes(256, "big"), lock, 1)
    if oc is None:
        sys.exit(f"Solved, but the result does not open the lock. Checkpoint kept: {state}")
    os.remove(state)
    print(f"\nOutside Code:\n\n    {oc.decode()}\n\nNext: decode_outside_vault (README step 4).")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bench"); b.add_argument("--seconds", type=float, default=5.0); b.set_defaults(fn=cmd_bench)
    c = sub.add_parser("create")
    c.add_argument("--hours", type=float, required=True)
    c.add_argument("--rate", type=float, help="squarings/s to calibrate against (default: fastest local backend)")
    c.add_argument("--vault", default=VAULT_KEY, help="private_key.enc to check the Outside Code against ('none' to skip)")
    c.add_argument("--out", required=True); c.set_defaults(fn=cmd_create)
    s = sub.add_parser("solve"); s.add_argument("puzzle", help="puzzle file, or the TL1:... text itself")
    s.add_argument("--state"); s.set_defaults(fn=cmd_solve)
    a = ap.parse_args(); a.fn(a)


if __name__ == "__main__":
    main()
