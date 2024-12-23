#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include <cstdlib>
#include <string>

#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif

extern "C" {
    DLL_EXPORT void handleErrors() {
        ERR_print_errors_fp(stderr);
        abort();
    }

    DLL_EXPORT bool signPdf(const char* privateKeyPath, const char* pdfPath, const char* signaturePath) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        BIO *keyData = BIO_new(BIO_s_file());
        if (!keyData || BIO_read_filename(keyData, privateKeyPath) <= 0) {
            std::cerr << "Error opening private key file." << std::endl;
            if (keyData) BIO_free(keyData);
            ERR_print_errors_fp(stderr);
            return false;
        }

        EVP_PKEY *privateKey = PEM_read_bio_PrivateKey(keyData, NULL, NULL, NULL);
        BIO_free(keyData);

        if (!privateKey) {
            std::cerr << "Error reading private key." << std::endl;
            ERR_print_errors_fp(stderr);
            return false;
        }

        std::ifstream pdfFile(pdfPath, std::ios::binary);
        if (!pdfFile.is_open()) {
            std::cerr << "Error opening PDF file." << std::endl;
            EVP_PKEY_free(privateKey);
            return false;
        }

        std::vector<unsigned char> pdfContents((std::istreambuf_iterator<char>(pdfFile)), std::istreambuf_iterator<char>());
        pdfFile.close();

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) {
            std::cerr << "Error creating signing context." << std::endl;
            EVP_PKEY_free(privateKey);
            return false;
        }

        if (EVP_SignInit(ctx, EVP_sha512()) <= 0) {
            std::cerr << "Error initializing signing context." << std::endl;
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(privateKey);
            return false;
        }

        if (EVP_SignUpdate(ctx, pdfContents.data(), pdfContents.size()) <= 0) {
            std::cerr << "Error updating signing context." << std::endl;
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(privateKey);
            return false;
        }

        unsigned int signatureLen = EVP_PKEY_size(privateKey);
        std::vector<unsigned char> signature(signatureLen);

        if (EVP_SignFinal(ctx, signature.data(), &signatureLen, privateKey) <= 0) {
            std::cerr << "Error finalizing signature." << std::endl;
            ERR_print_errors_fp(stderr);
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(privateKey);
            return false;
        }

        std::ofstream signatureFile(signaturePath, std::ios::binary);
        if (!signatureFile.is_open()) {
            std::cerr << "Error opening signature file." << std::endl;
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(privateKey);
            return false;
        }

        signatureFile.write(reinterpret_cast<const char*>(signature.data()), signatureLen);
        signatureFile.close();

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        EVP_cleanup();
        ERR_free_strings();

        return true;
    }

    DLL_EXPORT bool verifySignature(const char* publicKeyPath, const char* pdfPath, const char* signaturePath) {
        BIO *pubData = BIO_new(BIO_s_file());
        if (!pubData || BIO_read_filename(pubData, publicKeyPath) <= 0) {
            std::cerr << "Error opening public key file." << std::endl;
            if (pubData) BIO_free(pubData);
            return false;
        }
        EVP_PKEY *publicKey = PEM_read_bio_PUBKEY(pubData, NULL, NULL, NULL);
        BIO_free(pubData);

        if (!publicKey) {
            std::cerr << "Error loading public key." << std::endl;
            return false;
        }

        std::ifstream pdfFile(pdfPath, std::ios::binary);
        if (!pdfFile) {
            std::cerr << "Error opening PDF file." << std::endl;
            EVP_PKEY_free(publicKey);
            return false;
        }
        std::vector<unsigned char> pdfContents((std::istreambuf_iterator<char>(pdfFile)), std::istreambuf_iterator<char>());
        pdfFile.close();

        std::ifstream signatureFile(signaturePath, std::ios::binary);
        if (!signatureFile) {
            std::cerr << "Error opening signature file." << std::endl;
            EVP_PKEY_free(publicKey);
            return false;
        }
        std::vector<unsigned char> signature((std::istreambuf_iterator<char>(signatureFile)), std::istreambuf_iterator<char>());
        signatureFile.close();

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) {
            std::cerr << "Error creating digest context." << std::endl;
            EVP_PKEY_free(publicKey);
            return false;
        }
        if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha512(), NULL, publicKey) <= 0) {
            std::cerr << "Error initializing digest verification." << std::endl;
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(publicKey);
            return false;
        }

        if (EVP_DigestVerifyUpdate(ctx, pdfContents.data(), pdfContents.size()) <= 0) {
            std::cerr << "Error updating digest verification with PDF content." << std::endl;
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(publicKey);
            return false;
        }

        int result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
        if (result != 1) {
            std::cerr << "Signature verification failed." << std::endl;
        }

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(publicKey);

        return result == 1;
    }

    DLL_EXPORT void generateKey(const char* algorithm_choice, const char* key_param) {
        EVP_PKEY *keypair = nullptr;
        EVP_PKEY_CTX *ctx = nullptr;

        if (std::string(algorithm_choice) == "RSA") {
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
            if (!ctx) handleErrors();

            if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();

            int rsa_key_size = std::stoi(key_param);
            if (rsa_key_size < 2048) {
                std::cerr << "Error: RSA key size must be at least 2048 bits." << std::endl;
                EVP_PKEY_CTX_free(ctx);
                return;
            }
            if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, rsa_key_size) <= 0) handleErrors();

        } else if (std::string(algorithm_choice) == "ECC") {
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
            if (!ctx) handleErrors();

            if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();

            int curve_nid = OBJ_txt2nid(key_param);
            if (curve_nid == NID_undef) {
                std::cerr << "Error: Invalid ECC curve name." << std::endl;
                EVP_PKEY_CTX_free(ctx);
                return;
            }
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0) handleErrors();

        } else {
            std::cerr << "Invalid algorithm choice. Please enter 'RSA' or 'ECC'." << std::endl;
            return;
        }

        if (EVP_PKEY_keygen(ctx, &keypair) <= 0) handleErrors();

        BIO *private_bio = BIO_new_file("private_key.pem", "w");
        if (!private_bio) {
            std::cerr << "Error opening private key file for writing." << std::endl;
            handleErrors();
        }
        if (!PEM_write_bio_PrivateKey(private_bio, keypair, nullptr, nullptr, 0, nullptr, nullptr)) {
            std::cerr << "Error writing private key to file." << std::endl;
            handleErrors();
        }
        BIO_free_all(private_bio);

        BIO *public_bio = BIO_new_file("public_key.pem", "w");
        if (!public_bio) {
            std::cerr << "Error opening public key file for writing." << std::endl;
            handleErrors();
        }
        if (!PEM_write_bio_PUBKEY(public_bio, keypair)) {
            std::cerr << "Error writing public key to file." << std::endl;
            handleErrors();
        }
        BIO_free_all(public_bio);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(keypair);

        EVP_cleanup();
        ERR_free_strings();

        std::cout << "Keypair generated and saved successfully.\n";
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <operation> [parameters...]\n";
        std::cerr << "Operations:\n";
        std::cerr << "  generateKeypair <algorithm> <key_param> <private_key_file> <public_key_file>\n";
        std::cerr << "  signPdf <private_key_file> <pdf_file> <signature_file>\n";
        std::cerr << "  verifySignature <public_key_file> <pdf_file> <signature_file>\n";
        return 1;
    }
 
    std::string operation = argv[1];
    if (operation == "generateKeypair" && argc == 6) {
        generateKey(argv[2], argv[3]);
    } else if (operation == "signPdf" && argc == 5) {
        if (signPdf(argv[2], argv[3], argv[4])) {
            std::cout << "PDF signed successfully.\n";
        } else {
            std::cerr << "PDF signing failed.\n";
        }
    } else if (operation == "verifySignature" && argc == 5) {
        if (verifySignature(argv[2], argv[3], argv[4])) {
            std::cout << "Signature verified successfully.\n";
        } else {
            std::cerr << "Signature verification failed.\n";
        }
    } else {
        std::cerr << "Invalid operation or parameters.\n";
        return 1;
    }
 
    return 0;
}
