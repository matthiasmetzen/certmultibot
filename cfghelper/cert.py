import os
import subprocess
from termcolor import colored
from pathlib import Path
from cryptography import x509
from datetime import datetime, timedelta


def generate_selfsigned_cert(hostname, basepath, ip_addresses=None, key=None, time_days=90):
    """Generates self signed certificate for a hostname, and optional IP addresses."""
    #from https://gist.github.com/bloodearnest/9017111a313777b9cce5
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    # Generate our key
    if key is None:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
    
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])
 
    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.    
    alt_names = [x509.DNSName(hostname)]
    
    # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios 
    if ip_addresses:
        for addr in ip_addresses:
            # openssl wants DNSnames for ips...
            alt_names.append(x509.DNSName(addr))
            # ... whereas golang's crypto/tls is stricter, and needs IPAddresses
            # note: older versions of cryptography do not understand ip_address objects
            alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))
    
    san = x509.SubjectAlternativeName(alt_names)
    
    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=time_days))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    
    bp = Path(basepath)
    outdir = bp.joinpath(hostname)
    pub_file = outdir.joinpath("fullchain.pem")
    priv_file = outdir.joinpath("privkey.pem")
    
    outdir.mkdir(parents=True, exist_ok=True)
    
    with pub_file.open("wb") as f:
        f.write(cert_pem)
    with priv_file.open("wb") as f:
        f.write(key_pem)
        
def readCertificate(certfile):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    if os.path.exists(certfile) and os.path.isfile(certfile):
        with open(certfile, "rb") as cf:
            return x509.load_pem_x509_certificate(cf.read(), default_backend())
            
def getCertDomains(certificate):
    ext = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    return ext.value.get_values_for_type(x509.DNSName)
    
def requestCert(domains, args):
    args = args.copy()
    for d in domains:
        args.append(f"-d {d}")
    print(f"Requesting certificate for {domains}...")
    cmd = " ".join((["certbot", "certonly"] + args))
    p = subprocess.run(cmd, shell=True, universal_newlines=True)

    if not p.returncode == 0:
        print(colored("[ERROR] Could not request certificate", "red"))
        return False
    else:
        print("Successfully retrieved certificate")
        return True