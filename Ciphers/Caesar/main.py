def caesar_encrypt(plaintext, shift):
    encrypted_text = ""
    for char in plaintext:
        if char.isalpha():
            is_upper = char.isupper()
            
            # Apply the Caesar Cipher shift
            char_code = ord(char)
            encrypted_char = chr((char_code - ord('A' if is_upper else 'a') + shift) % 26 + ord('A' if is_upper else 'a'))
            
            encrypted_text += encrypted_char
        else:
            # Keep non-alphabetic characters unchanged
            encrypted_text += char
    
    return encrypted_text

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

text = "message"
shift = 3

encrypted_text = caesar_encrypt(text, shift)
decrypted_text = caesar_decrypt(encrypted_text, shift)

print("Text: ", text)
print("Encrypted text: ", encrypted_text)
print("Decrypted text: ", decrypted_text)
