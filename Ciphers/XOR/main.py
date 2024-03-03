def xor_cipher(message, key):
    message_bytes = message.encode()
    key_bytes = key.encode()
    repeated_key = key_bytes * (len(message_bytes) // len(key_bytes)) + key_bytes[:len(message_bytes) % len(key_bytes)]
    encrypted_bytes = bytes([a ^ b for a, b in zip(message_bytes, repeated_key)])
    encrypted_message = encrypted_bytes.decode()

    return encrypted_message

message = "message"
key = "secret_key"
encrypted_message = xor_cipher(message, key)
print("Original message: ", message)
print("XOR-ed message: ", encrypted_message)
