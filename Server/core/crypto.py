
import hmac
import logging
import datetime
import defusedxml.ElementTree as ET
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

    pubkey_xml_tpl = '''<ECDHKeyValue xmlns="http://www.w3.org/2001/04/xmldsig-more#">
      <DomainParameters>
        <NamedCurve URN="urn:oid:1.3.132.0.35" />
      </DomainParameters>
      <PublicKey>
        <X Value="X_VALUE" xsi:type="PrimeFieldElemType" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" />
        <Y Value="Y_VALUE" xsi:type="PrimeFieldElemType" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" />
      </PublicKey>
    </ECDHKeyValue>'''

    def __init__(self, xml):
        logging.debug('Generating new pub/priv key pair')
        self.dh = ec.generate_private_key(SECP521R1(), default_backend())
        self.peer_public_key = self.pubkey_from_xml(xml)
        logging.debug('Imported peer public key')

        self.shared_key = self.dh.exchange(ec.ECDH(), self.peer_public_key)
        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256.update(self.shared_key)
        self.derived_key = sha256.finalize()

        #logging.debug(f"Derived encryption key: {to_byte_array(self.derived_key)}")
        #logging.debug(f"Derived encryption key: {self.derived_key.hex()}")

    @property
    def public_key(self):
        ec_numbers = self.dh.public_key().public_numbers()

        pubkey_xml = ECDHE.pubkey_xml_tpl.replace("X_VALUE", str(ec_numbers.x))
        pubkey_xml = pubkey_xml.replace("Y_VALUE", str(ec_numbers.y))

        return pubkey_xml

    @staticmethod
    def pubkey_from_xml(xml):
        root = ET.fromstring(xml)

        x = int(root[1][0].attrib['Value'])
        y = int(root[1][1].attrib['Value'])
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

        #logging.debug(f"IV: {to_byte_array(iv)}")
        #logging.debug(f"HMAC: {to_byte_array(mac)}")
        #logging.debug(f"DATA: {to_byte_array(encrypted_data)}")

        return iv + encrypted_data + mac

    def decrypt(self, data):
        iv, ciphertext, data_hmac = data[:16], data[16:-32], data[-32:]

        if hmac.compare_digest(data_hmac, hmac.digest(self.derived_key, (iv + ciphertext), 'sha256')):

            aes = Cipher(algorithms.AES(self.derived_key), modes.CBC(iv), backend=default_backend())
            decryptor = aes.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()

            return unpadder.update(decrypted_data) + unpadder.finalize()

        #logging.error('HMAC not valid')
        raise CryptoException("HMAC not valid")

    """
    def encrypt_file(infile, aes_key, outfile):
        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256.update(aes_key.encode())
        derived_key = sha256.finalize()

        logging.debug(f"SHA256_KEY: {derived_key.hex()}")

        aes = Cipher(algorithms.AES(derived_key), modes.CBC(AES_IV), backend=default_backend())
        encryptor = aes.encryptor()

        padder = padding.PKCS7(128).padder()
        with open(infile, 'rb') as file_to_encrypt:
            with open(outfile, 'wb') as encrypted_file:
                padded_data = padder.update(file_to_encrypt.read()) + padder.finalize()
                encrypted_file.write(encryptor.update(padded_data) + encryptor.finalize())


    def decrypt(encrypted_data, aes_key):
        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256.update(aes_key.encode())
        derived_key = sha256.finalize()

        aes = Cipher(algorithms.AES(derived_key), modes.CBC(AES_IV), backend=default_backend())
        decryptor = aes.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()
    """


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
    # Sign our certificate with our private key
    ).sign(key, hashes.SHA256(), default_backend())

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    logging.info(f"Self-signed certificate written to {key_path} and {cert_path}")
