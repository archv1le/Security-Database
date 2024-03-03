def vigenere_encrypt(plain_text, key):
    plain_text = plain_text.upper()
    key = key.upper()
  
    encrypted_text = ""

    for i in range(len(plain_text)):
        char = plain_text[i]
        if char.isalpha():
            # Apply Vigenere encryption
            shift = ord(key[i % len(key)]) - ord('A')
            encrypted_char = chr((ord(char) + shift - ord('A')) % 26 + ord('A'))
            encrypted_text += encrypted_char
        else:
            # Preserve non-alphabetic characters
            encrypted_text += char

    return encrypted_text

def vigenere_decrypt(encrypted_text, key):
    encrypted_text = encrypted_text.upper()
    key = key.upper()

    decrypted_text = ""

    for i in range(len(encrypted_text)):
        char = encrypted_text[i]
        if char.isalpha():
            # Apply Vigenère decryption
            shift = ord(key[i % len(key)]) - ord('A')
            decrypted_char = chr((ord(char) - shift - ord('A')) % 26 + ord('A'))
            decrypted_text += decrypted_char
        else:
            # Preserve non-alphabetic characters
            decrypted_text += char

    return decrypted_text

plain_text = "some message"
key = "key"
encrypted_text = vigenere_encrypt(plain_text, key)
decrypted_text = vigenere_decrypt(encrypted_text, key)

print("Original text: ", plain_text)
print("Encrypted text: ", encrypted_text)
print("Decrypted text: ", decrypted_text)
