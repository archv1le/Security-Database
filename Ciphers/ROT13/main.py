def rot13_encrypt(plain_text):
    encrypted_text = ""
    for char in plain_text:
        if char.isalpha():
            shift = 13 if char.islower() else 13
            encrypted_char = chr((ord(char) - ord('a' if char.islower() else 'A') + shift) % 26 + ord('a' if char.islower() else 'A'))
            encrypted_text += encrypted_char
        else:
            encrypted_text += char
    return encrypted_text

def rot13_decrypt(encrypted_text):
    return rot13_encrypt(encrypted_text)  # ROT13 is symmetric, so encryption and decryption are the same

original_text = "message"
encrypted_text = rot13_encrypt(original_text)
decrypted_text = rot13_decrypt(encrypted_text)

print("Original text: ", original_text)
print("Encrypted text: ", encrypted_text)
print("Decrypted text: ", decrypted_text)
