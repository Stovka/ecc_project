from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccPoint
from Crypto.Signature import DSS
from Crypto.Hash import keccak
from Crypto.Hash import SHA256

ECC_CURVE = "secp256r1"
KEY_LENGTH = 32  # 32 * 8 = 256b


def validate_password(password, public_point):
    """Calculates P = Hash(password) * G and compares P with PK."""
    # public_point in bytes first x then y
    curve = ECC._curves[ECC_CURVE]
    # Generator G
    G = EccPoint(curve.Gx, curve.Gy, ECC_CURVE)
    # Number d
    d = int_from_bytes(get_hash_from_string(password))
    # Point dG = user PK
    dG = G * d
    # Convert bytes to x,y int coordinates
    PKx, PKy = get_coordinates(public_point)
    if dG.x == PKx and dG.y == PKy:
        return True
    return False


def get_coordinates(bytes_cor):
    """Convert bytes to x, y integer coordinates."""
    Px = bytearray()
    Py = bytearray()
    # Split in half
    for i, b in enumerate(bytes_cor):
        if i < len(bytes_cor) / 2:
            Px.append(b)
        else:
            Py.append(b)
    # Bytes to int
    Px = int_from_bytes(Px)
    Py = int_from_bytes(Py)
    return Px, Py


def get_key_from_coordinates(bytes_cor):
    """Get key from bytes. Return bytes of KEY_LENGTH length."""
    key = bytearray()
    for i, b in enumerate(bytes_cor):
        if i < KEY_LENGTH:
            key.append(b)
        else:
            break
    return bytes(key)


def get_hash_from_string(msg):
    return keccak.new(data=string_to_bytes(msg), digest_bits=256).digest()


def get_hash(bytes):
    return keccak.new(data=bytes, digest_bits=256).digest()


def encrypt_aes_gcm(key, plaintext):
    """Encrypt plaintext with AES GCM. Accepts bytes or string. Returns ciphertext, nonce, mac in bytes."""
    if isinstance(plaintext, str):
        plaintext = string_to_bytes(plaintext)
    aesCipher = AES.new(key, AES.MODE_GCM)
    ciphertext, mac = aesCipher.encrypt_and_digest(plaintext)
    return (ciphertext, aesCipher.nonce, mac)


def decrypt_aes_gcm(key, nonce, mac, encrypted_data):
    """Decrypt ciphertext with AES GCM. Returns plaintext if success."""
    aesCipher = AES.new(key, AES.MODE_GCM, nonce)
    try:
        plaintext = aesCipher.decrypt_and_verify(encrypted_data, mac)
    except ValueError as err:
        #print(err)  # MAC error / other error
        return None
    return plaintext


def multiply_generator(bytes):
    """Multiply number in bytes with generator G. Returns point as bytes."""
    curve = ECC._curves[ECC_CURVE]
    G = EccPoint(curve.Gx, curve.Gy, ECC_CURVE)
    d = int_from_bytes(bytes)
    dG = G * d
    dG_bytes = bytearray(dG.x.to_bytes())
    dG_bytes += dG.y.to_bytes()
    return dG_bytes


def multiply_point(bytes, point_bytes):
    """Multiply number with arbitrary point. Everything in bytes."""
    d = int_from_bytes(bytes)
    Px, Py = get_coordinates(point_bytes)
    P = EccPoint(Px, Py)
    dP = P * d
    dP_bytes = bytearray(dP.x.to_bytes())
    dP_bytes += dP.y.to_bytes()
    return dP_bytes


def ecdsa_sign(sk, bytes_to_sign):
    """Sign bytes with sk. Returns signature bytes."""
    # Construct ECC key from sk
    curve = ECC._curves[ECC_CURVE]
    G = EccPoint(curve.Gx, curve.Gy, ECC_CURVE)
    d = int_from_bytes(sk)
    PK = G * d
    key = ECC.construct(curve=ECC_CURVE, d=d, point_x=PK.x, point_y=PK.y)

    # Hash input bytes
    hashed = SHA256.new(bytes_to_sign)
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(hashed)
    return signature


def ecdsa_verify(pk, signature, bytes_to_verify):
    """Verify signature with public key."""
    # Construct ECC key from pk
    PKx, PKy = get_coordinates(pk)
    key = ECC.construct(curve=ECC_CURVE, point_x=PKx, point_y=PKy)

    # Hash bytes to verify
    hashed = SHA256.new(bytes_to_verify)
    verifier = DSS.new(key, 'fips-186-3')
    try:
        verifier.verify(hashed, signature)
        return True
    except ValueError:
        return False


def random_bytes(length):
    return get_random_bytes(length)

def int_to_bytes(num):
    return num.to_bytes((num.bit_length() + 7) // 8, 'big')

def int_from_bytes(num_bytes):
    return int.from_bytes(num_bytes, byteorder="big", signed=False)

def bytes_to_hex_string(bytes):
    return bytes.hex()

def bytes_from_hex_string(hex_string):
    return bytes.fromhex(hex_string)

def string_to_bytes(string):
    return string.encode('utf-8')

def string_from_bytes(bytes):
    return bytes.decode("utf-8")
