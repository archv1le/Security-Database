#include <iostream>
#include <string>

std::string encryptDecrypt(const std::string& key, const std::string& input) {
    std::string message;

    /*
     * 1. Get ASCII values of input's character and key's character.
     * 2. Use XOR bitwise operator and then cast the result to character.
     * 3. Add encrypted character to result message.
    */
    for (int i = 0; i < input.length(); i++) {
        char character = input[i];
        char keyCharacter = key[i % key.length()];
        char encryptedCharacter = static_cast<char>(static_cast<int>(character) ^ static_cast<int>(keyCharacter));
        message += encryptedCharacter;
    }

    return message;
}

int main() {
    std::string input, key;

    std::cout << "Enter your message: ";
    std::cin >> input;

    std::cout << "Enter your key: ";
    std::cin >> key;

    std::string encryptedMessage = encryptDecrypt(key, input);
    std::string decryptedMessage = encryptDecrypt(key, encryptedMessage);

    std::cout << "Your message: " << input << std::endl;
    std::cout << "Encrypted message: " << encryptedMessage << std::endl;
    std::cout << "Decrypted message: " << decryptedMessage << std::endl;
}
