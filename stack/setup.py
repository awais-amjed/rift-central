#!/usr/bin/env python3
"""Generate central's secrets and render Kong's config, once.

Writes `.env` and `volumes/api/kong.yml`, both readable by their owner only,
and prints nothing secret. An existing `.env` is kept and only Kong's file is
rendered again from it: regenerating would change every key under a database
that already trusts the old ones.

The keys are the same set rift-self-host's console makes, for the same reasons
(`console/src/setup/secrets.ts` and `signing_keys.ts` there): sessions are
signed ES256 with the legacy HS256 secret carried alongside, and clients hold
opaque `sb_publishable_` / `sb_secret_` keys that Kong swaps for signed JWTs.

Needs Python 3 with `cryptography`.
"""
import base64
import json
import os
import secrets
import string
import sys
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import hmac
import hashlib

HERE = Path(__file__).resolve().parent
ENV = HERE / ".env"
KONG = HERE / "volumes" / "api" / "kong.yml"
ALPHABET = string.ascii_letters + string.digits
KEY_LIFETIME = 10 * 365 * 24 * 60 * 60


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


def generate() -> dict:
    jwt_secret = random_string(64)
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.private_numbers()
    kid = str(uuid.uuid4())
    common = {"alg": "ES256", "use": "sig", "kid": kid, "ext": True}
    public_jwk = {"kty": "EC", "crv": "P-256",
                  "x": b64url_int(numbers.public_numbers.x),
                  "y": b64url_int(numbers.public_numbers.y), **common}
    # No key_ops on the legacy secret, so GoTrue never picks it to sign with.
    legacy = {"kty": "oct", "alg": "HS256", "k": b64url(jwt_secret.encode())}

    def sign_hs(data: bytes) -> bytes:
        return hmac.new(jwt_secret.encode(), data, hashlib.sha256).digest()

    def sign_es(data: bytes) -> bytes:
        r, s = decode_dss_signature(private.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    hs = {"alg": "HS256", "typ": "JWT"}
    es = {"alg": "ES256", "typ": "JWT", "kid": kid}
    return {
        "POSTGRES_PASSWORD": random_string(32),
        "JWT_SECRET": jwt_secret,
        "JWT_EXPIRY": "3600",
        "JWT_KEYS": json.dumps([{**public_jwk, "d": b64url_int(numbers.private_value),
                                 "key_ops": ["sign", "verify"]}, legacy]),
        "JWT_JWKS": json.dumps({"keys": [{**public_jwk, "key_ops": ["verify"]}, legacy]}),
        "PUBLISHABLE_KEY": f"sb_publishable_{random_string(32)}",
        "SECRET_KEY": f"sb_secret_{random_string(32)}",
        "ANON_KEY": jwt(hs, api_key_claims("anon"), sign_hs),
        "SERVICE_ROLE_KEY": jwt(hs, api_key_claims("service_role"), sign_hs),
        "ANON_KEY_ASYMMETRIC": jwt(es, api_key_claims("anon"), sign_es),
        "SERVICE_ROLE_KEY_ASYMMETRIC": jwt(es, api_key_claims("service_role"), sign_es),
        "SECRET_KEY_BASE": random_string(64),
        "REALTIME_DB_ENC_KEY": random_string(16),
        "REALTIME_SEED": "true",
        "KONG_PORT": "28000",
        "API_EXTERNAL_URL": "http://localhost:28000",
        "MAILER_AUTOCONFIRM": "true",
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


def main() -> None:
    if ENV.exists():
        values = read_env()
        print("Kept the existing .env.")
    else:
        values = generate()
        # Single-quoted: Compose takes the JSON values literally that way.
        write_private(ENV, "# Central's secrets, from setup.py. Never commit this file.\n"
                      + "".join(f"{k}='{v}'\n" for k, v in values.items()))
        print("Wrote .env with fresh secrets.")

    template = (HERE / "templates" / "kong.yml").read_text()
    for name in ("PUBLISHABLE_KEY", "SECRET_KEY", "ANON_KEY", "SERVICE_ROLE_KEY",
                 "ANON_KEY_ASYMMETRIC", "SERVICE_ROLE_KEY_ASYMMETRIC"):
        template = template.replace("{{" + name + "}}", values[name])
    if "{{" in template:
        sys.exit("kong.yml still has a placeholder setup.py does not know.")
    write_private(KONG, template)
    print("Rendered volumes/api/kong.yml.")


if __name__ == "__main__":
    main()
