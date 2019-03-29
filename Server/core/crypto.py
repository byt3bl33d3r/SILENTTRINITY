
import hmac
import logging
import datetime
import json
from secrets import token_bytes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP521R1


class CryptoException(Exception):
    pass


class ECDHE:

    def __init__(self, pubkey):
        logging.debug('Generating new pub/priv key pair')
        self.dh = ec.generate_private_key(SECP521R1(), default_backend())
        self.peer_public_key = self.pubkey_from_json(pubkey)
        logging.debug('Imported peer public key')

        self.shared_key = self.dh.exchange(ec.ECDH(), self.peer_public_key)
        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256.update(self.shared_key)
        self.derived_key = sha256.finalize()

        logging.debug(f"Derived encryption key: {self.derived_key.hex()}")

    @property
    def public_key(self):
        ec_numbers = self.dh.public_key().public_numbers()

        return json.dumps({'x': ec_numbers.x, 'y': ec_numbers.y})

    @staticmethod
    def pubkey_from_json(json_string):
        my_json = json_string.decode('utf8').replace("'", '"')
        root = json.loads(my_json)

        x = int(root.get('x'), 16)
        y = int(root.get('y'), 16)

        return EllipticCurvePublicNumbers(x, y, SECP521R1()).public_key(backend=default_backend())

    def generate_private_key(self):
        logging.debug('Generating new pub/priv key pair')
        self.dh = ec.generate_private_key(SECP521R1(), default_backend())

    def encrypt(self, data):
        iv = token_bytes(16)

        aes = Cipher(algorithms.AES(self.derived_key), modes.CBC(iv), backend=default_backend())
        encryptor = aes.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        mac = hmac.digest(self.derived_key, (iv + encrypted_data), 'sha256')

        return iv + encrypted_data + mac

    def decrypt(self, data):
        iv, ciphertext, data_hmac = data[:16], data[16:-32], data[-32:]

        if hmac.compare_digest(data_hmac, hmac.digest(self.derived_key, (iv + ciphertext), 'sha256')):

            aes = Cipher(algorithms.AES(self.derived_key), modes.CBC(iv), backend=default_backend())
            decryptor = aes.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()

            return unpadder.update(decrypted_data) + unpadder.finalize()

        raise CryptoException("HMAC not valid")


# https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
def create_self_signed_cert(key_path="./data/key.pem", cert_path="./data/cert.pem"):
    logging.info('Creating self-signed certificate')
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
                ))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])

    # Sign our certificate with our private key

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 9999 days
        datetime.datetime.utcnow() + datetime.timedelta(days=9999)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    logging.info(f"Self-signed certificate written to {key_path} and {cert_path}")
