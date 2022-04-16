from Crypto.Cipher import AES
from Crypto.Hash import keccak
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccPoint
from Crypto.Util import number
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

ecc_curve = "secp256r1"
nonce_length = 16
mac_length = 16
key_length = 32

def validate_password(password, public_point):
    # public_point in bytes first x then y
    curve = ECC._curves[ecc_curve]
    point_G = EccPoint(curve.Gx, curve.Gy, ecc_curve)
    d = int_from_bytes(get_hash_from_string(password))
    dG = point_G * d
    # Convert bytes to x,y int coordinates
    PKx, PKy = get_coordinates(public_point)
    if dG.x == PKx and dG.y == PKy:
        return True
    return False

def get_coordinates(bytes_cor):
    PKx = bytearray()
    PKy = bytearray()
    # Convert bytes to x,y int coordinates
    for i, b in enumerate(bytes_cor):
        if i < len(bytes_cor) / 2:
            PKx.append(b)
        else:
            PKy.append(b)
    PKx = int_from_bytes(PKx)
    PKy = int_from_bytes(PKy)
    return PKx, PKy

def get_key_from_coordinates(bytes_cor):
    key = bytearray()
    # Convert bytes to x !BYTES! coordinate
    for i, b in enumerate(bytes_cor):
        if i < key_length:
            key.append(b)
        else:
            break
    return bytes(key)

def derive_key(password):
    # Calculate hash of password
    key = password
    return key

def get_hash_from_string(msg):
    return keccak.new(data=string_to_bytes(msg), digest_bits=256).digest()

def get_hash(bytes):
    return keccak.new(data=bytes, digest_bits=256).digest()

def get_hash_512(bytes):
    return keccak.new(data=bytes, digest_bits=512).digest()

def encrypt_AES_GCM(key, plaintext):
    # key in bytes, returns bytes
    if isinstance(plaintext, str):
        plaintext = string_to_bytes(plaintext)
    aesCipher = AES.new(key, AES.MODE_GCM)
    ciphertext, mac = aesCipher.encrypt_and_digest(plaintext)
    return (ciphertext, aesCipher.nonce, mac)


def decrypt_AES_GCM(key, nonce, mac, encrypted_data):
    # Everything bytes, returns string
    aesCipher = AES.new(key, AES.MODE_GCM, nonce)
    try:
        plaintext = aesCipher.decrypt_and_verify(encrypted_data, mac)
    except ValueError as err:
        print(err)
        return None
    return plaintext

def multiply_generator(bytes):
    curve = ECC._curves[ecc_curve]
    point_G = EccPoint(curve.Gx, curve.Gy, ecc_curve)
    d = int_from_bytes(bytes)
    dG = point_G * d
    dG_bytes = bytearray(dG.x.to_bytes())
    dG_bytes += dG.y.to_bytes()
    return dG_bytes

def multiply_point(bytes, point_bytes):
    #curve = ECC._curves[ecc_curve]
    d = int_from_bytes(bytes)
    Px, Py = get_coordinates(point_bytes)
    P = EccPoint(Px, Py)
    dP = P * d
    dP_bytes = bytearray(dP.x.to_bytes())
    dP_bytes += dP.y.to_bytes()
    return dP_bytes

def ecdsa_sign(sk, bytes_to_sign):
    curve = ECC._curves[ecc_curve]
    point_G = EccPoint(curve.Gx, curve.Gy, ecc_curve)
    d = int_from_bytes(sk)
    PK = point_G * d
    key = ECC.construct(curve=ecc_curve, d=d, point_x=PK.x, point_y=PK.y)

    hashed = SHA256.new(bytes_to_sign)
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(hashed)
    return signature

def ecdsa_verify(pk, signature, bytes_to_verify):
    PKx, PKy = get_coordinates(pk)
    key = ECC.construct(curve=ecc_curve, point_x=PKx, point_y=PKy)

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