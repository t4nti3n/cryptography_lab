#include <iostream>
#include <fstream>
#include <string>
#include <locale>
#include <codecvt>
#include <C:/cryptopp/include/cryptopp/osrng.h>
#include <C:/cryptopp/include/cryptopp/rsa.h>
#include <C:/cryptopp/include/cryptopp/files.h>
#include <C:/cryptopp/include/cryptopp/hex.h>
#include <C:/cryptopp/include/cryptopp/base64.h>
#include <C:/cryptopp/include/cryptopp/cryptlib.h>
#include <C:/cryptopp/include/cryptopp/secblock.h>
#include <C:/cryptopp/include/cryptopp/pem.h>

class RSACrypto {
public:
    // Method to generate RSA key pairs
    static void GenerateKeys(int keySize, const std::string &privFilename, const std::string &pubFilename, const std::string &format) {
        CryptoPP::AutoSeededRandomPool rng;

        // Generate the private key
        CryptoPP::RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, keySize);

        // Generate the public key
        CryptoPP::RSA::PublicKey publicKey;
        publicKey.AssignFrom(privateKey);

        // Save the private key to a file
        if (format == "DER") {
            CryptoPP::FileSink privFile(privFilename.c_str());
            privateKey.DEREncode(privFile);
            privFile.MessageEnd();
        } else if (format == "PEM") {
            CryptoPP::FileSink privFile(privFilename.c_str());
            privateKey.Save(CryptoPP::PEM_Save(privFile));
            privFile.MessageEnd();
        }

        // Save the public key to a file
        if (format == "DER") {
            CryptoPP::FileSink pubFile(pubFilename.c_str());
            publicKey.DEREncode(pubFile);
            pubFile.MessageEnd();
        } else if (format == "PEM") {
            CryptoPP::FileSink pubFile(pubFilename.c_str());
            publicKey.Save(CryptoPP::PEM_Save(pubFile));
            pubFile.MessageEnd();
        }

        std::cout << "RSA key pair generated and saved to files:" << std::endl;
        std::cout << "Private Key: " << privFilename << std::endl;
        std::cout << "Public Key: " << pubFilename << std::endl;
    }

    // Method to encrypt plaintext with a public key file
    static std::string Encrypt(const std::string &plainText, const std::string &pubFilename) {
        CryptoPP::RSA::PublicKey publicKey;
        CryptoPP::FileSource pubFile(pubFilename.c_str(), true);
        publicKey.BERDecode(pubFile);

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
        std::string cipherText;

        CryptoPP::StringSource ss1(plainText, true,
            new CryptoPP::PK_EncryptorFilter(rng, encryptor,
                new CryptoPP::StringSink(cipherText)
            )
        );
        return cipherText;
    }

    // Method to decrypt ciphertext with a private key file
    static std::string Decrypt(const std::string &cipherText, const std::string &privFilename) {
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::FileSource privFile(privFilename.c_str(), true);
        privateKey.BERDecode(privFile);

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
        std::string recoveredText;

        CryptoPP::StringSource ss2(cipherText, true,
            new CryptoPP::PK_DecryptorFilter(rng, decryptor,
                new CryptoPP::StringSink(recoveredText)
            )
        );
        return recoveredText;
    }
};

// Helper function to read file content into a string
std::string ReadFile(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary);
    std::ostringstream oss;
    oss << file.rdbuf();
    return oss.str();
}

// Helper function to write string content to a file
void WriteFile(const std::string &filename, const std::string &content) {
    std::ofstream file(filename, std::ios::binary);
    file << content;
}

// Main function to handle separate key generation, encryption, and decryption commands
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <command> <args...>" << std::endl;
        std::cerr << "Commands: generate, encrypt, decrypt" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "generate") {
        // Generate RSA key pair: <program> generate <key_size> <private_key_file> <public_key_file> <format>
        if (argc != 6) {
            std::cerr << "Usage: " << argv[0] << " generate <key_size> <private_key_file> <public_key_file> <format>" << std::endl;
            return 1;
        }
        int keySize = std::stoi(argv[2]);
        std::string privFilename = argv[3];
        std::string pubFilename = argv[4];
        std::string format = argv[5];
        RSACrypto::GenerateKeys(keySize, privFilename, pubFilename, format);

    } else if (command == "encrypt") {
        // Encrypt text: <program> encrypt <plain_text> <public_key_file> <cipher_file> <format>
        if (argc != 6) {
            std::cerr << "Usage: " << argv[0] << " encrypt <plain_text> <public_key_file> <cipher_file> <format>" << std::endl;
            return 1;
        }
        std::string plainText = argv[2];
        std::string pubFilename = argv[3];
        std::string cipherFile = argv[4];
        std::string format = argv[5];
        std::string cipherText = RSACrypto::Encrypt(plainText, pubFilename);
        if (format == "base64") {
            CryptoPP::StringSource(cipherText, true, new CryptoPP::Base64Encoder(new CryptoPP::FileSink(cipherFile.c_str())));
        }
        else if (format == "hex") {
            CryptoPP::StringSource(cipherText, true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(cipherFile.c_str())));
        }
        else if (format == "bin") {
            CryptoPP::StringSource(cipherText, true, new CryptoPP::FileSink(cipherFile.c_str(), true));
        }
        else {
            std::cerr << "Invalid format: " << argv[5] << std::endl;
            return 1;
        }
        // Display the encrypted data as hexadecimal
        CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
        encoder.Put((const unsigned char*)cipherText.data(), cipherText.size());
        encoder.MessageEnd();
        std::cout << std::endl;

    } else if (command == "decrypt") {
        // Decrypt text: <program> decrypt <cipher_file> <private_key_file> <plain_text_file> <format>
        if (argc != 6) {
            std::cerr << "Usage: " << argv[0] << " decrypt <cipher_file> <private_key_file> <plain_text_file> <format>" << std::endl;
            return 1;
        }
        std::string cipherFile = argv[2];
        std::string privFilename = argv[3];
        std::string plainTextFile = argv[4];
        std::string format = argv[5];
        std::string cipherText;

        if (format == "base64") {
            CryptoPP::FileSource(cipherFile.c_str(), true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(cipherText)));
        }
        else if (format == "hex") {
            CryptoPP::FileSource(cipherFile.c_str(), true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(cipherText)));
        }
        else if (format == "bin") {
            CryptoPP::FileSource(cipherFile.c_str(), true, new CryptoPP::StringSink(cipherText));
        }
        else {
            std::cerr << "Invalid format: " << format << std::endl;
            return 1;
        }

        std::string plainText = RSACrypto::Decrypt(cipherText, privFilename);
        std::cout << "Decrypted text: " << plainText << std::endl;
        WriteFile(plainTextFile, plainText);
    
    } else {
        std::cerr << "Invalid command: " << command << std::endl;
        std::cerr << "Commands: generate, encrypt, decrypt" << std::endl;
        return 1;
    }

    return 0;
}