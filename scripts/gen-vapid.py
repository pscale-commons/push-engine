#!/usr/bin/env python3
"""gen-vapid.py — mint the engine's VAPID pair, once.

Prints the two env lines. Custody: the private key lives in the service env
(Railway) and nowhere else; the public key is served at GET /vapid for any
door's subscribe call. Rotation = mint a new pair, set the env, and every
device re-subscribes at its next visit (the engine prunes gone endpoints on
delivery). Needs the cryptography package (rides in with pywebpush).
"""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


key = ec.generate_private_key(ec.SECP256R1())
private_raw = key.private_numbers().private_value.to_bytes(32, "big")
public_raw = key.public_key().public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

print("VAPID_PRIVATE=%s" % b64u(private_raw))
print("VAPID_PUBLIC=%s" % b64u(public_raw))
