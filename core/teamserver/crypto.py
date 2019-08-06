import hmac
import logging
import datetime
import json
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

    def __init__(self, pubkey):
        logging.debug('Generating new pub/priv key pair')
        self.dh = ec.generate_private_key(SECP521R1(), default_backend())
        self.peer_public_key = self.pubkey_from_xml(pubkey)
        #self.peer_public_key = self.pubkey_from_json(pubkey)
        logging.debug('Imported peer public key')

        self.shared_key = self.dh.exchange(ec.ECDH(), self.peer_public_key)
        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256.update(self.shared_key)
        self.derived_key = sha256.finalize()

        logging.debug(f"Derived encryption key: {self.derived_key.hex()}")

    #@property
    #def public_key(self):
    #    ec_numbers = self.dh.public_key().public_numbers()
    #    return json.dumps({'x': ec_numbers.x, 'y': ec_numbers.y})

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

    @staticmethod
    def pubkey_from_json(json_pubkey):
        root = json.loads(json_pubkey.decode())

        x = int(root['x'], 16)
        y = int(root['y'], 16)

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

