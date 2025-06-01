"""
High level cryptographic functions based on `.pyelliptic` OpenSSL bindings.

.. note::
  Upstream pyelliptic was upgraded from SHA1 to SHA256 for signing. We must
  `upgrade PyBitmessage gracefully. <https://github.com/Bitmessage/PyBitmessage/issues/953>`_
  `More discussion. <https://github.com/yann2192/pyelliptic/issues/32>`_
"""

import hashlib
import os
from binascii import hexlify

try:
    import pyelliptic
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from fallback import RIPEMD160Hash
    from pyelliptic import OpenSSL
    from pyelliptic import arithmetic as a
except ImportError:
    from pybitmessage import pyelliptic
    from pybitmessage.fallback import RIPEMD160Hash
    from pybitmessage.pyelliptic import OpenSSL
    from pybitmessage.pyelliptic import arithmetic as a


__all__ = [
    'decodeWalletImportFormat', 'deterministic_keys',
    'double_sha512', 'calculateInventoryHash', 'encodeWalletImportFormat',
    'encrypt', 'makeCryptor', 'pointMult', 'privToPub', 'randomBytes',
    'random_keys', 'sign', 'to_ripe', 'verify']


# WIF (uses arithmetic ):
def decodeWalletImportFormat(WIFstring):
    """
    Convert private key from base58 that's used in the config file to
    8-bit binary string.
    """
    fullString = a.changebase(WIFstring, 58, 256)
    privkey = fullString[:-4]
    if fullString[-4:] != \
       hashlib.sha256(hashlib.sha256(privkey).digest()).digest()[:4]:
        raise ValueError('Checksum failed')
    elif privkey[0:1] == b'\x80':  # checksum passed
        return privkey[1:]

    raise ValueError('No hex 80 prefix')


# An excellent way for us to store our keys
# is in Wallet Import Format. Let us convert now.
# https://en.bitcoin.it/wiki/Wallet_import_format
def encodeWalletImportFormat(privKey):
    """
    Convert private key from binary 8-bit string into base58check WIF string.
    """
    privKey = b'\x80' + privKey
    checksum = hashlib.sha256(hashlib.sha256(privKey).digest()).digest()[0:4]
    return a.changebase(privKey + checksum, 256, 58)


# Random

def randomBytes(n):
    """Get n random bytes"""
    try:
        return os.urandom(n)
    except NotImplementedError:
        return OpenSSL.rand(n)


# Hashes

def _bm160(data):
    """RIPEME160(SHA512(data)) -> bytes"""
    return RIPEMD160Hash(hashlib.sha512(data).digest()).digest()


def to_ripe(signing_key, encryption_key):
    """Convert two public keys to a ripe hash"""
    return _bm160(signing_key + encryption_key)


def double_sha512(data):
    """Binary double SHA512 digest"""
    return hashlib.sha512(hashlib.sha512(data).digest()).digest()


def calculateInventoryHash(data):
    """Calculate inventory hash from object data"""
    return double_sha512(data)[:32]


# Keys

def random_keys():
    """Return a pair of keys, private and public"""
    priv = randomBytes(32)
    pub = pointMult(priv)
    return priv, pub


def deterministic_keys(passphrase, nonce):
    """Generate keys from *passphrase* and *nonce* (encoded as varint)"""
    priv = hashlib.sha512(passphrase + nonce).digest()[:32]
    pub = pointMult(priv)
    return priv, pub


def hexToPubkey(pubkey):
    """Convert a pubkey from hex to binary"""
    pubkey_raw = a.changebase(pubkey[2:], 16, 256, minlen=64)
    pubkey_bin = b'\x02\xca\x00 ' + pubkey_raw[:32] + b'\x00 ' + pubkey_raw[32:]
    return pubkey_bin


def privToPub(privkey):
    """Converts hex private key into hex public key"""
    private_key = a.changebase(privkey, 16, 256, minlen=32)
    public_key = pointMult(private_key)
    return hexlify(public_key)


def pointMult(secret):
    """
    Does an EC point multiplication; turns a private key into a public key.

    Evidently, this type of error can occur very rarely:

    >>> File "highlevelcrypto.py", line 54, in pointMult
    >>>  group = OpenSSL.EC_KEY_get0_group(k)
    >>> WindowsError: exception: access violation reading 0x0000000000000008
    """
    while True:
        try:
            k = OpenSSL.EC_KEY_new_by_curve_name(
                OpenSSL.get_curve('secp256k1'))
            priv_key = OpenSSL.BN_bin2bn(secret, 32, None)
            group = OpenSSL.EC_KEY_get0_group(k)
            pub_key = OpenSSL.EC_POINT_new(group)

            OpenSSL.EC_POINT_mul(group, pub_key, priv_key, None, None, None)
            OpenSSL.EC_KEY_set_private_key(k, priv_key)
            OpenSSL.EC_KEY_set_public_key(k, pub_key)

            size = OpenSSL.i2o_ECPublicKey(k, None)
            mb = OpenSSL.create_string_buffer(size)
            OpenSSL.i2o_ECPublicKey(k, OpenSSL.byref(OpenSSL.pointer(mb)))

            return mb.raw

        except Exception:
            import traceback
            import time
            traceback.print_exc()
            time.sleep(0.2)
        finally:
            OpenSSL.EC_POINT_free(pub_key)
            OpenSSL.BN_free(priv_key)
            OpenSSL.EC_KEY_free(k)


# Encryption

#def makeCryptor(privkey, curve='secp256k1'):
#    """Return a private `.pyelliptic.ECC` instance"""
#    private_key = a.changebase(privkey, 16, 256, minlen=32)
#    public_key = pointMult(private_key)
#    cryptor = pyelliptic.ECC(
#        pubkey_x=public_key[1:-32], pubkey_y=public_key[-32:],
#        raw_privkey=private_key, curve=curve)
#    return cryptor

def makeCryptor(privkey, curve=ec.SECP256K1()):
    """Return a private ECC instance using pyca/cryptography"""
    # Convert the hex private key to bytes
    private_key_bytes = bytes.fromhex(privkey)

    # Create a private key object
    private_key = ec.derive_private_key(int.from_bytes(private_key_bytes, byteorder='big'), curve, default_backend())

    # Get the public key
    public_key = private_key.public_key()

    return private_key, public_key

#def makePubCryptor(pubkey):
#    """Return a public `.pyelliptic.ECC` instance"""
#    pubkey_bin = hexToPubkey(pubkey)
#    return pyelliptic.ECC(curve='secp256k1', pubkey=pubkey_bin)
#

def hexToPubkey(pubkey):
    """Convert a hex public key to bytes."""
    return bytes.fromhex(pubkey)

def hexToPrivkey(privkey):
    """Convert a hex private key to bytes."""
    return bytes.fromhex(privkey)

def makePubCryptor(pubkey):
    """Return a public ECC instance using pyca/cryptography"""
    pubkey_bin = hexToPubkey(pubkey)

    # Create a public key object from the bytes
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pubkey_bin)

    return public_key

#def encrypt(msg, hexPubkey):
#    """Encrypts message with hex public key"""
#    return pyelliptic.ECC(curve='secp256k1').encrypt(
#        msg, hexToPubkey(hexPubkey))


def encrypt(msg, hexPubkey):
    """Encrypts message with hex public key"""
    # Convert the message to bytes
    message_bytes = msg.encode('utf-8')

    # Load the public key
    pubkey_bin = hexToPubkey(hexPubkey)
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pubkey_bin)

    # Generate a symmetric key for encryption
    symmetric_key = os.urandom(32)  # Example: 256-bit key

    # Encrypt the message using a symmetric encryption algorithm (e.g., AES)
    # Here, we will use a simple example with AES-GCM (you can choose your preferred method)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # Create a random nonce
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message_bytes) + encryptor.finalize()

    # Encrypt the symmetric key with the public key
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        ec.ECIES(algorithm=hashes.SHA256(), padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    )

    return {
        'ciphertext': ciphertext,
        'nonce': nonce,
        'encrypted_symmetric_key': encrypted_symmetric_key,
    }

#def decrypt(msg, hexPrivkey):
#    """Decrypts message with hex private key"""
#    return makeCryptor(hexPrivkey).decrypt(msg)

def decrypt(encrypted_data, hexPrivkey):
    """Decrypts message with hex private key"""
    # Extract the encrypted symmetric key, ciphertext, and nonce
    encrypted_symmetric_key = encrypted_data['encrypted_symmetric_key']
    ciphertext = encrypted_data['ciphertext']
    nonce = encrypted_data['nonce']

    # Convert the hex private key to bytes
    private_key_bytes = hexToPrivkey(hexPrivkey)

    # Create a private key object
    private_key = ec.derive_private_key(int.from_bytes(private_key_bytes, byteorder='big'), ec.SECP256K1(), default_backend())

    # Decrypt the symmetric key using the private key
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        ec.ECIES(algorithm=hashes.SHA256(), padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    )

    # Decrypt the message using the symmetric key
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_message.decode('utf-8')

#def decryptFast(msg, cryptor):
#    """Decrypts message with an existing `.pyelliptic.ECC` object"""
#    return cryptor.decrypt(msg)

def decryptFast(encrypted_data, private_key):
    """Decrypts message with an existing `EllipticCurvePrivateKey` object"""
    # Extract the encrypted symmetric key, ciphertext, and nonce
    encrypted_symmetric_key = encrypted_data['encrypted_symmetric_key']
    ciphertext = encrypted_data['ciphertext']
    nonce = encrypted_data['nonce']

    # Decrypt the symmetric key using the private key
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        ec.ECIES(algorithm=hashes.SHA256(), padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    )

    # Decrypt the message using the symmetric key
    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_message.decode('utf-8')

# Signatures

def _choose_digest_alg(digestAlg):
    """Choose the appropriate digest algorithm based on the input."""
    if digestAlg.lower() == "sha1":
        return hashes.SHA1()
    elif digestAlg.lower() == "sha256":
        return hashes.SHA256()
    else:
        raise ValueError("Unsupported digest algorithm. Use 'sha1' or 'sha256'.")

def sign(msg, hexPrivkey, digestAlg="sha256"):
    """
    Signs with hex private key using SHA1 or SHA256 depending on
    *digestAlg* keyword.
    """
    # Create the cryptor (private key) using the new makeCryptor function
    private_key, _ = makeCryptor(hexPrivkey)

    # Choose the appropriate digest algorithm
    digest_algorithm = _choose_digest_alg(digestAlg)

    # Sign the message
    signature = private_key.sign(
        msg.encode('utf-8'),  # Convert message to bytes
        ec.ECDSA(digest_algorithm)
    )

    return signature


def verify(msg, sig, hexPubkey, digestAlg=None):
    """Verifies with hex public key using SHA1 or SHA256"""
    if digestAlg is None:
        # First, try verifying with SHA1
        sigVerifyPassed = verify(msg, sig, hexPubkey, "sha1")
        if sigVerifyPassed:
            return True
        # If SHA1 verification fails, try SHA256
        return verify(msg, sig, hexPubkey, "sha256")

    # Load the public key using the new makePubCryptor function
    public_key = makePubCryptor(hexPubkey)

    # Choose the appropriate digest algorithm
    digest_algorithm = _choose_digest_alg(digestAlg)

    try:
        # Verify the signature
        public_key.verify(
            sig,
            msg.encode('utf-8'),  # Convert message to bytes
            ec.ECDSA(digest_algorithm)
        )
        return True
    except Exception:
        return False