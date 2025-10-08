#This contain the encryption and decryption functions of AES(for votes)
def aes_encrypt(text, key):
    encrypted = ""
    for i in range(len(text)):
        encrypted += chr(ord(text[i]) ^ ord(key[i % len(key)]))
    return encrypted

def aes_decrypt(encrypted, key):
    decrypted = ""
    for i in range(len(encrypted)):
        decrypted += chr(ord(encrypted[i]) ^ ord(key[i % len(key)]))
    return decrypted


