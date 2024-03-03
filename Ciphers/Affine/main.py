def mod_inverse(a, m):
    # Calculate the modular inverse of 'a' modulo 'm'
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def affine_encrypt(plaintext, a, b):
    encrypted_text = ""
    for char in plaintext:
        if char.isalpha():
            is_upper = char.isupper()

            # Apply the Affine Cipher transformation
            char_code = ord(char)
            encrypted_char = chr((a * (char_code - ord('A' if is_upper else 'a')) + b) % 26 + ord('A' if is_upper else 'a'))

            encrypted_text += encrypted_char
        else:
            # Keep non-alphabetic characters unchanged
            encrypted_text += char

    return encrypted_text

def affine_decrypt(ciphertext, a, b):
    # Calculate the modular inverse of 'a'
    a_inverse = mod_inverse(a, 26)
    
    decrypted_text = ""
    for char in ciphertext:
        if char.isalpha():
            # Determine whether the character is uppercase or lowercase
            is_upper = char.isupper()

            # Apply the Affine Cipher decryption
            char_code = ord(char)
            decrypted_char = chr((a_inverse * (char_code - ord('A' if is_upper else 'a') - b)) % 26 + ord('A' if is_upper else 'a'))

            decrypted_text += decrypted_char
        else:
            # Keep non-alphabetic characters unchanged
            decrypted_text += char

    return decrypted_text

plaintext = "message"
a = 5
b = 8

encrypted_text = affine_encrypt(plaintext, a, b)
decrypted_text = affine_decrypt(encrypted_text, a, b)

print("Text: ", plaintext)
print("Encrypted text: ", encrypted_text)
print("Decrypted text: ", decrypted_text)
