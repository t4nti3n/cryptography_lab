// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "C:/cryptopp/include/cryptopp/osrng.h" // generate random number
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
#include <ostream>
using std::cin;
using std::cout;
using std::cerr;
using std::endl;
using std::getline;
#include <iostream>
#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdlib>
#include <fcntl.h>
#include <io.h>
#include <locale>
#include <cctype>
#include <stdexcept>
/* Vietnamese*/ 
#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;
using CryptoPP::byte; // byte of cryptopp

#include "C:/cryptopp/include/cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "C:/cryptopp/include/cryptopp/hex.h" 

#include "C:/cryptopp/include/cryptopp/base64.h" 

#include "C:/cryptopp/include/cryptopp/filters.h" // string filters
 using CryptoPP::StreamTransformationFilter; // string transformation

#include "C:/cryptopp/include/cryptopp/files.h" // read and write to file

#include "C:/cryptopp/include/cryptopp/aes.h"
using CryptoPP::AES;

#include "C:/cryptopp/include/cryptopp/modes.h"
#include "C:/cryptopp/include/cryptopp/gcm.h"
#include "C:/cryptopp/include/cryptopp/eax.h"
using CryptoPP::CBC_Mode;

#include "C:/cryptopp/include/cryptopp/secblock.h" // cryptopp byte (distinguish with c++ byte)
using CryptoPP::SecByteBlock; 

// Convert unicode
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

// Function to convert wstring to string
string wstring_to_string(const wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
    return conv.to_bytes(wstr);
}

// Function to convert wstring to UTF-8 string (alternative)
string wstring_to_utf8(const wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
    return conv.to_bytes(wstr);
}

// Function to convert UTF-8 string to wstring
wstring utf8_to_wstring(const string& str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
    return conv.from_bytes(str);
}


using CryptoPP::HexEncoder;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

using namespace std;
void usage() {
    cout << "Usage: program.exe --plaintext <message> --mode <cbc>\n";
}

int main(int argc, char* argv[])
{
    string mode, plain;

    // Command-line options parsing
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "--mode" && i + 1 < argc) {
            mode = argv[++i];
        } else if (arg == "--plaintext" && i + 1 < argc) {
            plain = argv[++i];
        } else {
            usage();
            return 1;
        }
    }

    if (mode.empty() || plain.empty()) {
        usage();
        return 1;
    }

    // Set UTF-8 environment
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
    #endif

    // Generate random key and IV
    AutoSeededRandomPool prng;
    SecByteBlock key(32); // 32 bytes
    prng.GenerateBlock(key, key.size());
    cout << L"length of key: " << key.size() << endl << flush;

    CryptoPP::byte iv[AES::BLOCKSIZE];   // inital vector 8 bytes 
    prng.GenerateBlock(iv, sizeof(iv));  // generate iv

    // Pretty print key in hex format
    string encoded;
    encoded.clear();
    CryptoPP::StringSource(key, key.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    wcout << L"key(Hex): " << utf8_to_wstring(encoded) << endl << flush;

    // Pretty print iv in hex format
    encoded.clear();
    StringSource(iv, sizeof(iv), true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
    wcout << L"iv: " << utf8_to_wstring(encoded) << endl;

    // Print plain text
    wcout << L"plain text: " << utf8_to_wstring(plain) << endl;

    // Encrypt the plain text
    string cipher;
    if (mode == "cbc") {
        CBC_Mode< AES >::Encryption encrypt;
        encrypt.SetKeyWithIV(key, key.size(), iv);

        StringSource(plain, true, 
            new StreamTransformationFilter(encrypt,
                new StringSink(cipher)
            ) // StreamTransformationFilter      
        ); // StringSource
    } else if (mode == "ecb") {
        CryptoPP::ECB_Mode< AES >::Encryption encrypt;
        encrypt.SetKey(key, key.size());

        StringSource(plain, true, 
            new StreamTransformationFilter(encrypt,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    } else if (mode == "cfb") {
        CryptoPP::CFB_Mode< AES >::Encryption encrypt;
        encrypt.SetKeyWithIV(key, key.size(), iv);

        StringSource(plain, true, 
            new CryptoPP::StreamTransformationFilter(encrypt,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    } else if (mode == "ofb") {
        CryptoPP::OFB_Mode< AES >::Encryption encrypt;
        encrypt.SetKeyWithIV(key, key.size(), iv);

        StringSource(plain, true, 
            new CryptoPP::StreamTransformationFilter(encrypt,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    } else if (mode == "ctr") {
        CryptoPP::CTR_Mode< AES >::Encryption encrypt;
        encrypt.SetKeyWithIV(key, key.size(), iv);

        StringSource(plain, true, 
            new CryptoPP::StreamTransformationFilter(encrypt,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    } else if (mode == "gcm") {
        CryptoPP::GCM< AES >::Encryption encrypt;
        encrypt.SetKeyWithIV(key, key.size(), iv);

        StringSource(plain, true, 
            new CryptoPP::AuthenticatedEncryptionFilter(encrypt,
                new StringSink(cipher)
            ) // AuthenticatedEncryptionFilter
        ); // StringSource


    } else if (mode == "eax") {
        CryptoPP::EAX< AES >::Encryption encrypt;
        encrypt.SetKeyWithIV(key, key.size(), iv);

        StringSource(plain, true, 
            new CryptoPP::AuthenticatedEncryptionFilter(encrypt,
                new StringSink(cipher)
            ) // AuthenticatedEncryptionFilter
        ); // StringSource
    } else {
        cerr << "Invalid mode specified. Use one of 'cbc', 'ecb', 'cfb', 'ofb', 'ctr', 'gcm', 'ccm', 'xts', 'eax'.\n";
        return 1;
    }

    // Pretty print cipher text in Base64
    encoded.clear();
    StringSource(cipher, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded)
        ) // Base64Encoder
    ); // StringSource
    cout << "cipher text: " << encoded << endl;

    // Save cipher text to file
    StringSource(encoded, true, new FileSink("cipher.txt")); //base64 string 
    StringSource(cipher, true, new FileSink("bytecipher.bin", true)); //bytes file

    // Decrypt the cipher text
    string scipher, rcipher, recovered;
    FileSource("cipher.txt", true, new CryptoPP::StringSink(scipher));
    StringSource(scipher, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(rcipher)));

    CBC_Mode< AES >::Decryption decrypt;
    decrypt.SetKeyWithIV(key, key.size(), iv);

    StringSource (rcipher, true, 
        new StreamTransformationFilter(decrypt,
            new StringSink(recovered)
        ) // StreamTransformationFilter
    ); // StringSource

    wcout << L"recovered text: " << utf8_to_wstring(recovered) << endl;

    return 0;
}