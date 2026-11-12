import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import time

PIN_FILE = os.path.expanduser("~/.selfheal-pin.json")
_fails = {"count": 0, "until": 0.0}


def _hash(pin, salt):
    return hashlib.scrypt(pin.encode(), salt=salt, n=2**14, r=8, p=1).hex()


def set_pin(pin):
    salt = secrets.token_bytes(16)
    with open(PIN_FILE, "w") as f:
        json.dump({"salt": salt.hex(), "hash": _hash(pin, salt)}, f)
    os.chmod(PIN_FILE, 0o600)


def check_pin(pin):
    if time.time() < _fails["until"]:
        return False, "Too many wrong tries. Wait a minute."
    try:
        with open(PIN_FILE) as f:
            data = json.load(f)
    except FileNotFoundError:
        return False, "No PIN set. Run: python src/pin.py setpin"
    if hmac.compare_digest(_hash(pin, bytes.fromhex(data["salt"])), data["hash"]):
        _fails["count"] = 0
        return True, "ok"
    _fails["count"] += 1
    if _fails["count"] >= 3:
        _fails.update(count=0, until=time.time() + 60)
    return False, "Wrong PIN."


if __name__ == "__main__" and sys.argv[1:] == ["setpin"]:
    p1 = getpass.getpass("New PIN: ")
    if p1 and p1 == getpass.getpass("Repeat PIN: "):
        set_pin(p1)
        print("PIN saved.")
    else:
        print("PINs didn't match.")
