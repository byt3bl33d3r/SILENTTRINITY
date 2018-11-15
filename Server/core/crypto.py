import xml.etree.ElementTree as ET
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP521R1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from secrets import token_bytes

pubkey_xml_tpl = '''<ECDHKeyValue xmlns="http://www.w3.org/2001/04/xmldsig-more#">
  <DomainParameters>
    <NamedCurve URN="urn:oid:1.3.132.0.35" />
  </DomainParameters>
  <PublicKey>
    <X Value="X_VALUE" xsi:type="PrimeFieldElemType" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" />
    <Y Value="Y_VALUE" xsi:type="PrimeFieldElemType" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" />
  </PublicKey>
</ECDHKeyValue>'''


class ECDHE:
    def __init__(self):
        self.diffieHellman = ec.generate_private_key(SECP521R1(), default_backend())
        self.public_key = self.diffieHellman.public_key()
        self.IV = token_bytes(16)

    def encrypt(self, public_key, secret):
        shared_key = self.diffieHellman.exchange(ec.ECDH(), public_key)

        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256.update(shared_key)
        derived_key = sha256.finalize()

        aes = Cipher(algorithms.AES(derived_key), modes.CBC(self.IV), backend=default_backend())
        encryptor = aes.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(secret) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, public_key, iv, secret):
        shared_key = self.diffieHellman.exchange(ec.ECDH(), public_key)

        sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256.update(shared_key)
        derived_key = sha256.finalize()

        aes = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        decryptor = aes.decryptor()
        decrypted_data = decryptor.update(secret) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()

    def import_public_key(self, public_key):
        root = ET.fromstring(public_key)

        x = int(root[1][0].attrib['Value'])
        y = int(root[1][1].attrib['Value'])
        return EllipticCurvePublicNumbers(x, y, SECP521R1()).public_key(backend=default_backend())

    def export_public_key(self):
        ec_numbers = self.public_key.public_numbers()

        pubkey_xml = pubkey_xml_tpl.replace("X_VALUE", str(ec_numbers.x))
        pubkey_xml = pubkey_xml.replace("Y_VALUE", str(ec_numbers.y))

        return pubkey_xml
