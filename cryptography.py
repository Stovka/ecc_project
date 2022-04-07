from Crypto.Cipher import AES
from Crypto.Hash import keccak
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccPoint

ecc_curve = "secp256r1"
nonce_length = 16
mac_length = 16
key_length = 32

def validate_password(password, public_point):
    # Udelat hash z hesla a porovnat s ulozenou hashi
    curve = ECC._curves[ecc_curve]
    point_G = EccPoint(curve.Gx, curve.Gy, ecc_curve)
    d = int.from_bytes(get_hash(password), byteorder="big", signed=False)
    dG = point_G * d
    if dG.x == public_point[0] and dG.y == public_point[1]:
        return True
    return False

def derive_key(password):
    # Calculate hash of password
    key = password
    return key

def get_hash(msg):
    return keccak.new(data=str.encode(msg), digest_bits=256).digest()

def encrypt_AES_GCM(key, plaintext):
    # key in bytes, returns bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    aesCipher = AES.new(key, AES.MODE_GCM)
    ciphertext, mac = aesCipher.encrypt_and_digest(plaintext)
    return (ciphertext, aesCipher.nonce, mac)


def decrypt_AES_GCM(key, nonce, mac, encrypted_data):
    # Everything bytes, returns string
    aesCipher = AES.new(key, AES.MODE_GCM, nonce)
    try:
        plaintext = aesCipher.decrypt_and_verify(encrypted_data, mac)
        plaintext = plaintext.decode("utf-8")
    except ValueError as err:
        print(err)
        return None
    return plaintext

def ecdh(alice_d, bob_d):
    # alice_d, bob_d in hex
    curve = ECC._curves[ecc_curve]
    point_G = EccPoint(curve.Gx, curve.Gy, ecc_curve)

    #alice_d = int(alice_d, 16)
    #bob_d = int(bob_d, 16)
    #d = int.from_bytes(get_hash(password), byteorder="big", signed=False)
    daG = point_G * alice_d
    dbG = point_G * bob_d

    shared1 = daG * bob_d
    shared2 = dbG * alice_d
    print(shared1.x)
    print(shared2.x)
    print(shared1.y)
    print(shared2.y)