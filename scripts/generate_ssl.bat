@echo off
REM BARAQ SSL Certificate Generator
REM Generates self-signed certificates for HTTPS deployment.
REM
REM Usage:
REM   scripts\generate_ssl.bat
REM   scripts\generate_ssl.bat --domain soc.example.com
REM
REM Outputs:
REM   certs\baraq.crt  (public certificate)
REM   certs\baraq.key  (private key)

setlocal

set DOMAIN=%1
if "%DOMAIN%"=="" set DOMAIN=localhost

set CERT_DIR=certs
set DURATION=365

echo.
echo ========================================
echo   BARAQ SSL Certificate Generator
echo ========================================
echo.
echo  Domain: %DOMAIN%
echo  Output: %CERT_DIR%\
echo  Duration: %DURATION% days
echo.

REM Create certs directory
if not exist "%CERT_DIR%" mkdir "%CERT_DIR%"

REM Generate certificate using Python (no OpenSSL needed)
python -c "
import ssl, socket, os, datetime
from pathlib import Path

domain = '%DOMAIN%'
cert_dir = Path('%CERT_DIR%')
cert_file = cert_dir / 'baraq.crt'
key_file = cert_dir / 'baraq.key'

# Generate self-signed cert
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_default_certs()

# Use built-in certgen
from http.server import HTTPServer
import tempfile

# Generate with cryptography if available, else use openssl
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain),
                x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_dir.mkdir(exist_ok=True)
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    print(f'Certificate: {cert_file}')
    print(f'Private key: {key_file}')
    print('Done! Use in BARAQ: start.bat secure lan')
except ImportError:
    print('cryptography not installed. Install with: pip install cryptography')
    print('Or use OpenSSL: openssl req -x509 -newkey rsa:2048 -keyout certs/baraq.key -out certs/baraq.crt -days 365 -nodes')
"

echo.
echo ========================================
echo   SSL Setup Complete
echo ========================================
echo.
echo  To start BARAQ with HTTPS:
echo    start.bat secure lan
echo.
echo  The server will be available at:
echo    https://%DOMAIN%:8443
echo.
echo  Agents should connect with:
echo    python scripts/agent.py --server https://%DOMAIN%:8443 --tls-ca %CERT_DIR%/baraq.crt
echo.

endlocal
