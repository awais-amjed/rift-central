#!/usr/bin/env python3
"""Write central's .env and the config files rendered from it.

    ./setup.py                                   a local stack, 127.0.0.1:28000
    ./setup.py --domain central.example.com      a real one, behind Caddy's TLS
    ./setup.py --fcm firebase-service-account.json

The first run generates every secret into `.env`. Later runs keep them — a
regenerated key would no longer match a database that already trusts the old
one — and only add what is missing, apply the options given, and render
`volumes/api/kong.yml` and `volumes/caddy/Caddyfile` again. Options can be
given on any run: adding `--fcm` to a running stack is `./setup.py --fcm …`
followed by `./up.sh`.

Everything written is readable by its owner only, and nothing secret is
printed. Two things are filled in by hand in `.env`: SMTP (`SMTP_*`) and the
backup bucket (`BACKUP_S3_*`).

The keys are the set rift-self-host's console makes, for the same reasons
(`console/src/setup/secrets.ts` and `signing_keys.ts` there): sessions are
signed ES256 with the legacy HS256 secret carried alongside, and clients hold
opaque `sb_publishable_` / `sb_secret_` keys that Kong swaps for signed JWTs.

Needs Python 3 with `cryptography`.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import string
import sys
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = Path(__file__).resolve().parent
ENV = HERE / ".env"
ALPHABET = string.ascii_letters + string.digits
KEY_LIFETIME = 10 * 365 * 24 * 60 * 60
LOCAL_PORT = "28000"

# Filled in by hand. Written empty so the names are there to fill.
SMTP_KEYS = ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_SENDER")


def random_string(length: int) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_int(value: int) -> str:
    return b64url(value.to_bytes(32, "big"))


def jwt(header: dict, claims: dict, sign) -> str:
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
    return f"{signing_input}.{b64url(sign(signing_input.encode()))}"


def api_key_claims(role: str) -> dict:
    now = int(time.time())
    return {"role": role, "iss": "supabase", "iat": now, "exp": now + KEY_LIFETIME}


def signing_secrets() -> dict:
    jwt_secret = random_string(64)
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.private_numbers()
    kid = str(uuid.uuid4())
    common = {"alg": "ES256", "use": "sig", "kid": kid, "ext": True}
    public_jwk = {"kty": "EC", "crv": "P-256",
                  "x": b64url_int(numbers.public_numbers.x),
                  "y": b64url_int(numbers.public_numbers.y), **common}
    # No key_ops on the legacy secret, so Auth never picks it to sign with.
    legacy = {"kty": "oct", "alg": "HS256", "k": b64url(jwt_secret.encode())}

    def sign_hs(data: bytes) -> bytes:
        return hmac.new(jwt_secret.encode(), data, hashlib.sha256).digest()

    def sign_es(data: bytes) -> bytes:
        r, s = decode_dss_signature(private.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    hs = {"alg": "HS256", "typ": "JWT"}
    es = {"alg": "ES256", "typ": "JWT", "kid": kid}
    return {
        "JWT_SECRET": jwt_secret,
        "JWT_KEYS": json.dumps([{**public_jwk, "d": b64url_int(numbers.private_value),
                                 "key_ops": ["sign", "verify"]}, legacy]),
        "JWT_JWKS": json.dumps({"keys": [{**public_jwk, "key_ops": ["verify"]}, legacy]}),
        "PUBLISHABLE_KEY": f"sb_publishable_{random_string(32)}",
        "SECRET_KEY": f"sb_secret_{random_string(32)}",
        "ANON_KEY": jwt(hs, api_key_claims("anon"), sign_hs),
        "SERVICE_ROLE_KEY": jwt(hs, api_key_claims("service_role"), sign_hs),
        "ANON_KEY_ASYMMETRIC": jwt(es, api_key_claims("anon"), sign_es),
        "SERVICE_ROLE_KEY_ASYMMETRIC": jwt(es, api_key_claims("service_role"), sign_es),
    }


def defaults() -> dict:
    """Everything a new stack starts with, secrets included."""
    return {
        "POSTGRES_PASSWORD": random_string(32),
        **signing_secrets(),
        "JWT_EXPIRY": "3600",
        "SECRET_KEY_BASE": random_string(64),
        "REALTIME_DB_ENC_KEY": random_string(16),
        # The two secrets the database sends to its own functions (the
        # config rows up.sh writes); the functions check them.
        "PUSH_SECRET": random_string(48),
        "ATTACHMENT_SWEEP_SECRET": random_string(48),
        "FCM_SERVICE_ACCOUNT": "",
        "KONG_PORT": LOCAL_PORT,
        "DOMAIN": "",
        "COMPOSE_PROFILES": "",
        "API_EXTERNAL_URL": f"http://localhost:{LOCAL_PORT}",
        "MAILER_AUTOCONFIRM": "true",
        **{key: "" for key in SMTP_KEYS},
        # Backups (backup.sh). The bucket's address and key are filled in by
        # hand; the password encrypts everything sent there and must be kept
        # offline with this file — without it no backup can be read.
        "BACKUP_S3_PROVIDER": "Cloudflare",
        "BACKUP_S3_ENDPOINT": "",
        "BACKUP_S3_ACCESS_KEY_ID": "",
        "BACKUP_S3_SECRET_ACCESS_KEY": "",
        "BACKUP_BUCKET": "rift-central-backups",
        "BACKUP_PASSWORD": random_string(48),
        "BACKUP_SALT": random_string(48),
        "BACKUP_PING_URL": "",
    }


def read_env() -> dict:
    values = {}
    for line in ENV.read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            values[name] = value[1:-1] if value[:1] == "'" and value[-1:] == "'" else value
    return values


def write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(path, 0o600)


def write_env(values: dict) -> None:
    for name, value in values.items():
        # Single-quoted, which Compose takes literally — JSON included — and
        # which therefore cannot hold a quote of its own.
        if "'" in value or "\n" in value:
            sys.exit(f"{name} cannot contain a single quote or a newline.")
    write_private(ENV, "# Central's secrets and settings, from setup.py. Never commit this file.\n"
                  "# SMTP_* and the BACKUP_S3_* keys are filled in by hand; the rest is setup.py's.\n"
                  + "".join(f"{k}='{v}'\n" for k, v in values.items()))


def render(template: str, values: dict, names: tuple) -> str:
    for name in names:
        template = template.replace("{{" + name + "}}", values[name])
    if "{{" in template:
        sys.exit("A template still has a placeholder setup.py does not know.")
    return template


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--domain", help="serve on this domain, with TLS (its A record must point here)")
    parser.add_argument("--local", action="store_true", help="go back to a local stack with no domain")
    parser.add_argument("--fcm", type=Path, help="Firebase service-account JSON, for push")
    parser.add_argument("--no-fcm", action="store_true", help="forget the Firebase key and turn push off")
    args = parser.parse_args()

    if ENV.exists():
        values = read_env()
        added = [k for k in defaults() if k not in values]
        fresh = defaults()
        for key in added:
            values[key] = fresh[key]
        print("Kept the existing .env" + (f", and added {', '.join(added)}." if added else "."))
    else:
        values = defaults()
        print("Generated every secret into .env.")

    if args.domain:
        domain = args.domain.strip().lower()
        if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", domain):
            sys.exit("That does not look like a domain name.")
        values.update(DOMAIN=domain, COMPOSE_PROFILES="tls",
                      API_EXTERNAL_URL=f"https://{domain}",
                      # A real stack confirms addresses, so it needs SMTP.
                      MAILER_AUTOCONFIRM="false")
        print(f"Serving on https://{domain}.")
    elif args.local:
        values.update(DOMAIN="", COMPOSE_PROFILES="",
                      API_EXTERNAL_URL=f"http://localhost:{values['KONG_PORT']}",
                      MAILER_AUTOCONFIRM="true")
        print("Back to a local stack.")

    if args.fcm:
        try:
            account = json.loads(args.fcm.read_text())
        except (OSError, ValueError) as e:
            sys.exit(f"Could not read {args.fcm} as JSON: {e}")
        if account.get("type") != "service_account" or "private_key" not in account:
            sys.exit(f"{args.fcm} is not a Google service-account key.")
        values["FCM_SERVICE_ACCOUNT"] = json.dumps(account, separators=(",", ":"))
        print("Stored the Firebase service account; push is on after ./up.sh.")

    elif args.no_fcm:
        values["FCM_SERVICE_ACCOUNT"] = ""
        print("Forgot the Firebase service account; push is off after ./up.sh.")

    write_env(values)

    kong = (HERE / "templates" / "kong.yml").read_text()
    write_private(HERE / "volumes" / "api" / "kong.yml",
                  render(kong, values, ("PUBLISHABLE_KEY", "SECRET_KEY", "ANON_KEY", "SERVICE_ROLE_KEY",
                                        "ANON_KEY_ASYMMETRIC", "SERVICE_ROLE_KEY_ASYMMETRIC")))
    if values["DOMAIN"]:
        caddy = (HERE / "templates" / "Caddyfile").read_text()
        write_private(HERE / "volumes" / "caddy" / "Caddyfile", render(caddy, values, ("DOMAIN",)))

    if values["DOMAIN"] and not values["SMTP_HOST"]:
        print("Fill in SMTP_* in .env before anybody signs up: this stack confirms addresses.")


if __name__ == "__main__":
    main()
