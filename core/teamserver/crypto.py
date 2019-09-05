import hmac
import logging
import datetime
import json
import secrets
import defusedxml.ElementTree as ET
from binascii import unhexlify
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP521R1


class CryptoException(Exception):
    pass

def gen_stager_psk():
    ek = secrets.token_bytes(30)
    sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
    sha256.update(ek)
    return sha256.finalize().hex()


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

    def __init__(self, psk):
        self.psk = unhexlify(psk)
        self.dh = ec.generate_private_key(SECP521R1(), default_backend())
        self.derived_key = None

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

    @property
    def enc_public_key(self):
        return self.encrypt(self.public_key.encode(), self.psk)

    def generate_private_key(self):
        logging.debug('Generating new pub/priv key pair')
        self.dh = ec.generate_private_key(SECP521R1(), default_backend())

    def derive_shared_key(self, enc_pubkey):
        pubkey = self.decrypt(enc_pubkey, self.psk)
        peer_public_key = self.pubkey_from_xml(pubkey)
        #peer_public_key = self.pubkey_from_json(pubkey)
        logging.debug('Imported peer public key')

        shared_key = self.dh.exchange(ec.ECDH(), peer_public_key)
        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256.update(shared_key)
        self.derived_key = sha256.finalize()

        logging.debug(f"Derived encryption key: {self.derived_key.hex()}")

    def encrypt(self, data, key=None):
        iv = secrets.token_bytes(16)
        key = key if key is not None else self.derived_key

        aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = aes.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        mac = hmac.digest(key, (iv + encrypted_data), 'sha256')

        return iv + encrypted_data + mac

    def decrypt(self, data, key=None):
        iv, ciphertext, data_hmac = data[:16], data[16:-32], data[-32:]
        key = key if key is not None else self.derived_key

        if hmac.compare_digest(data_hmac, hmac.digest(key, (iv + ciphertext), 'sha256')):

            aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = aes.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()

            return unpadder.update(decrypted_data) + unpadder.finalize()

        raise CryptoException("HMAC not valid")
