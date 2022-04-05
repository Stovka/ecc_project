
def validate_password(password, public_key):
    # Convert password to number
    # Multiplying password with G must must get public key point
    print(password)
    print(public_key)
    return True

def derive_key(password):
    # Calculate hash of password
    key = password
    return key

def decrypt_data(key, nonce, mac, data):
    decrypted = data
    return decrypted