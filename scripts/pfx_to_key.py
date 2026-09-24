import base64
import sys

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    pkcs12,
)

pfx = base64.b64decode(sys.argv[1])
password = sys.argv[2].encode()
out_path = sys.argv[3]
key, _cert, _extra = pkcs12.load_key_and_certificates(pfx, password)
pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
with open(out_path, "wb") as fh:
    fh.write(pem)
