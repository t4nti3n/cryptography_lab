// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
#include <locale>


#include "C:/cryptopp/include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "C:/cryptopp/include/cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "C:/cryptopp/include/cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "C:/cryptopp/include/cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "C:/cryptopp/include/cryptopp/aes.h"
using CryptoPP::AES;

#include <C:/cryptopp/include/cryptopp/modes.h>
#include "C:/cryptopp/include/cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
#include <C:/cryptopp/include/cryptopp/eax.h>
#include <C:/cryptopp/include/cryptopp/gcm.h>
#include <C:/cryptopp/include/cryptopp/xts.h>

//Header working with string and array filters
#include <C:/cryptopp/include/cryptopp/filters.h> 
using CryptoPP::ArraySink;

//header working with file
#include "C:/cryptopp/include/cryptopp/files.h" //********
using CryptoPP::FileSource; //********
using CryptoPP::FileSink; 	//********
using CryptoPP::ArraySource;


#include <C:/cryptopp/include/cryptopp/secblock.h>
#include "assert.h"
using namespace CryptoPP;

#include <windows.h>


void CBC_enMODE(string&, const byte*, const byte*);
void CCM_enMODE(string&, const byte*, const byte*);
void CFB_enMODE(string&, const byte*, const byte*);
void CTR_enMODE(string&, const byte*, const byte*); 
void ECB_enMODE(string&, const byte*, const byte*);
void GCM_enMODE(string&, const byte*, const byte*);
void OFB_enMODE(string&, const byte*, const byte*);
void XTS_enMODE(string&, const byte*, const byte*);

void CBC_deMODE(string&, const byte*, const byte*);
void CCM_deMODE(string&, const byte*, const byte*);
void CFB_deMODE(string&, const byte*, const byte*);
void CTR_deMODE(string&, const byte*, const byte*); 
void ECB_deMODE(string&, const byte*, const byte*);
void GCM_deMODE(string&, const byte*, const byte*);
void OFB_deMODE(string&, const byte*, const byte*);
void XTS_deMODE(string&, const byte*, const byte*);

string plain = "", cipher = "", encoded = "", recovered = "";

int main(int argc, char* argv[])
{
	#ifdef __linux__
    	std::locale::global(std::locale("C.utf8"));
	#endif

	#ifdef _WIN32
		// Set console code page to UTF-8 on Windows
		SetConsoleOutputCP(CP_UTF8);
		SetConsoleCP(CP_UTF8);
    #endif
	// prng.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);
	// CryptoPP::StringSource(key, AES::DEFAULT_KEYLENGTH, true, new FileSink("key.key", AES::DEFAULT_KEYLENGTH)); //********
	
	//input
	std::cout << "What mode would you like to use?\n";
	std::cout << " 1. CBC\n 2. CCM\n 3. CFB\n 4. CTR\n 5. ECB\n 6. GCM\n 7. OFB\n 8. XTS\n";
	char inputmode = '\0';
	std::cout << "Your option: "; std::cin >> inputmode; std::fflush(stdin);
	byte key[AES::DEFAULT_KEYLENGTH]; 
	byte iv[AES::BLOCKSIZE];

	std::cout << "What type would you like to use?\n";
	std::cout << " 1. Encryption\n 2. Decryption\n";
	char inputtype = '\0';
	std::cin >> inputtype;
	std::fflush(stdin);

	char inputkeyiv = '\0';
	std::cout << "Would you like to generate key from: \n";
	std::cout << " 1. Random\n 2. Type from your console Screen\n 3. Read from file\n";
	std::cout << "Your option: "; std::cin >> inputkeyiv;
	
	switch (inputkeyiv)
	{
		case '1':	
		{
			AutoSeededRandomPool prng;
			
			prng.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);
			prng.GenerateBlock(iv, AES::BLOCKSIZE);
			encoded.clear();
			StringSource(key, AES::DEFAULT_KEYLENGTH, true,
				new HexEncoder(
					new StringSink(encoded)
				) // HexEncoder
			); // StringSource
			std::cout << "\n\n------------------Your Key and IV------------------\n";
			cout << "key: " << encoded << endl;
			// Pretty print iv
			encoded.clear();
			StringSource(iv, AES::BLOCKSIZE, true,
				new HexEncoder(
					new StringSink(encoded)
				) // HexEncoder
			); // StringSource
			cout << "iv: " << encoded << endl;
			std::cout << "---------------------------------------------------\n\n";
			break;
		}
		case '2':
		{
			std::string stringkey = "";
			std::cout << "Type key: ";
			std::cin.ignore();  // Add this line to clear the newline character
			std::getline(std::cin, stringkey);
			StringSource(stringkey, true, new HexDecoder(new ArraySink(key, AES::DEFAULT_KEYLENGTH)));
			
			std::string stringiv = "";
			std::cout << "Type iv: ";
			std::getline(std::cin, stringiv);
			StringSource(stringiv, true, new HexDecoder(new ArraySink(iv, AES::BLOCKSIZE)));
			break;
		}
		case '3':
		{
			std::string fkey = "";
			std::string fiv = "";
			std::cout << "Input key file: ";
			std::cin.ignore();  // Add this line to clear the newline character
			std::getline(std::cin, fkey);
			FileSource(fkey.c_str(), true, new ArraySink(key, AES::DEFAULT_KEYLENGTH));

			std::cout << "Input iv file: ";
			std::getline(std::cin, fiv);
			FileSource(fiv.c_str(), true, new ArraySink(iv, AES::BLOCKSIZE));
			break;
		}
		default:
		{
			std::cout << "We will chose your key and iv randomly!!!\n";
			AutoSeededRandomPool prng;
			prng.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);
			prng.GenerateBlock(iv, AES::BLOCKSIZE);
			encoded.clear();
			StringSource(key, AES::DEFAULT_KEYLENGTH, true,
				new HexEncoder(
					new StringSink(encoded)
				) // HexEncoder
			); // StringSource
			std::cout << "\n\n-------------------Your Key and IV-------------------\n";
			cout << "key: " << encoded << endl;
			// Pretty print iv
			encoded.clear();
			StringSource(iv, AES::BLOCKSIZE, true,
				new HexEncoder(
					new StringSink(encoded)
				) // HexEncoder
			); // StringSource
			std::cout << "iv: " << encoded << endl;
			std::cout << "-----------------------------------------------------\n\n";
			break;
		}
	}
	switch (inputtype)
	{
		case '1':
		{
			
			char inputplain = '\0';
			std::cout << "Would you like to type plaintext from: \n";
			std::cout << "1. Input from screen\n";
			std::cout << "2. Input from file\n";
			std::cout << "Your option: "; std::cin >> inputplain; std::fflush(stdin);

			switch (inputplain)
			{
				case '1':
				{
					if (inputmode == '8')
					{
						std::fflush(stdin);
						std::cout << "Caution!!! Plaintext in this mode required at least 16 characters\n";
						std::cout << "Type your plaintext: ";
						std::getline(std::cin, plain);
						std::fflush(stdin);
						while(plain.size() < 16)
						{
							std::cout << "Plain text isn't long enough, please type at leats 16 characters: ";
							std::getline(std::cin, plain);
							std::fflush(stdin);	
						}
					}
					else
					{
						std::fflush(stdin);
						std::cout << "Type your plaintext: ";
						std::getline(std::cin, plain);
						std::fflush(stdin);	
					}
					break;
				}
				case '2':
				{
					std::fflush(stdin);
					std::cout << "Type your input file name: ";
					std::string fileName;
					std::getline(std::cin, fileName);
					std::fflush(stdin);
					std::ifstream inputFile(fileName);
					FileSource(inputFile, true, new StringSink(plain));
					break;
				}
				default:
				{
					if (inputmode == '8')
					{
						std::fflush(stdin);
						std::cout << "Caution!!! Plaintext in this mode required at least 16 characters\n";
						std::cout << "Type your plaintext: ";
						std::getline(std::cin, plain);
						std::fflush(stdin);
						while(plain.size() < 16)
						{
							std::cout << "Plain text isn't long enough, please type at leats 16 characters: ";
							std::getline(std::cin, plain);
							std::fflush(stdin);	
						}
					}
					else
					{
						std::fflush(stdin);
						std::cout << "Type your plaintext: ";
						std::getline(std::cin, plain);
						std::fflush(stdin);	
					}
					break;
				}
			}
			
			//output
			std::cout << "\n\n------------------------Result------------------------\n";
			switch (inputmode)
			{
				case '1':
				{
					CBC_enMODE(plain, key, iv);
					break;
				}
					
				case '2':
				{
					CCM_enMODE(plain, key, iv);
					break;
				}
				case '3':
				{
					CFB_enMODE(plain, key, iv);
					break;
				}
				case '4':
				{
					CTR_enMODE(plain, key, iv);
					break;
				}
				case '5':
				{
					ECB_enMODE(plain, key, iv);
					break;
				}
				case '6':
				{
					GCM_enMODE(plain, key, iv);
					break;
				}
				case '7':
				{
					OFB_enMODE(plain, key, iv);
					break;
				}
				case '8':
				{
					XTS_enMODE(plain, key, iv);
					break;
				}
				default:
				{
					std::cout << "We have chosen CBC mode for you!!!\n";
					plain = "Hello There!";
					CBC_enMODE(plain, key, iv);
					break;
				}
			}
			std::cout << "------------------------------------------------------\n";
			break;
		}	
			
		case '2':
		{
			char inputcipher = '\0';
			std::cout << "Would you like to type plaintext from: \n";
			std::cout << "1. Input from screen\n";
			std::cout << "2. Input from file\n";
			std::cout << "Your option: "; std::cin >> inputcipher; std::fflush(stdin);
			
			
			switch (inputcipher)
			{
				case '1':
				{
					std::fflush(stdin);
					std::cout << "Type your ciphertext: ";
					std::getline(std::cin, cipher);
					std::fflush(stdin);	
					break;
				}
				case '2':
				{
					std::fflush(stdin);
					std::cout << "Type your input file name: ";
					std::string fileName;
					std::getline(std::cin, fileName);
					std::fflush(stdin);
					std::ifstream inputFile(fileName);
					FileSource(inputFile, true, new StringSink(cipher));
					break;
				}
				default:
				{
					std::cout << "Invalid choice!!!";
					break;
				}
			}
			
			//output
			
			std::cout << "\n\n------------------------Result------------------------\n";
			switch (inputmode)
			{
				case '1':
				{
					CBC_deMODE(cipher, key, iv);
					break;
				}
					
				case '2':
				{
					CCM_deMODE(cipher, key, iv);
					break;
				}
				case '3':
				{
					CFB_deMODE(cipher, key, iv);
					break;
				}
				case '4':
				{
					CTR_deMODE(cipher, key, iv);
					break;
				}
				case '5':
				{
					ECB_deMODE(cipher, key, iv);
					break;
				}
				case '6':
				{
					GCM_deMODE(cipher, key, iv);
					break;
				}
				case '7':
				{
					OFB_deMODE(cipher, key, iv);
					break;
				}
				case '8':
				{
					XTS_deMODE(cipher, key, iv);
					break;
				}
				default:
				{
					std::cout << "Invalid choice!!!";
					break;
				}
			}
			std::cout << "------------------------------------------------------\n";
			break;
		}
		default:
		{
			std::cout << "Invalid choice!!!";
			break;
		}
			
	}
	return 0;	
}
void CBC_enMODE(string& plain, const byte* key, const byte* iv)
{
	CBC_Mode< AES >::Encryption e;
	e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	// CFB mode must not use padding. Specifying
	//  a scheme will result in an exception
	StringSource(plain, true, 
		new StreamTransformationFilter(e,
			new StringSink(cipher)
		) // StreamTransformationFilter      
	); // StringSource

	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;

	CBC_Mode< AES >::Decryption d;
	d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(cipher, true, 
		new StreamTransformationFilter(d,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource
	cout << "recovered text: " << recovered << endl;
	return;
}

void CCM_enMODE(string& plain, const byte* key, const byte* iv)
{
	const int TAG_SIZE = 8;
	CCM< AES, TAG_SIZE >::Encryption e;
	e.SetKeyWithIV( key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);
	e.SpecifyDataLengths( 0, plain.size(), 0 );
	StringSource ss1( plain, true,
		new CryptoPP::AuthenticatedEncryptionFilter( e,
			new StringSink( cipher )
		) // AuthenticatedEncryptionFilter
	); // StringSource
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;
	CCM< AES, TAG_SIZE >::Decryption d;
	d.SetKeyWithIV( key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);
	d.SpecifyDataLengths( 0, cipher.size()-TAG_SIZE, 0 );
	CryptoPP::AuthenticatedDecryptionFilter df( d,
		new StringSink( recovered )
	); // AuthenticatedDecryptionFilter
	// The StringSource dtor will be called immediately
	//  after construction below. This will cause the
	//  destruction of objects it owns. To stop the
	//  behavior so we can get the decoding result from
	//  the DecryptionFilter, we must use a redirector
	//  or manually Put(...) into the filter without
	//  using a StringSource.
	StringSource ss2( cipher, true,
		new CryptoPP::Redirector( df )
	); // StringSource
	// If the object does not throw, here's the only
	//  opportunity to check the data's integrity
	if( true == df.GetLastResult() ) {
		cout << "recovered text: " << recovered << endl;
	}
	return;
}

void CFB_enMODE(string& plain, const byte* key, const byte* iv)
{
	cout << "plain text: " << plain << endl;
	CFB_Mode< AES >::Encryption e;
	e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	// CFB mode must not use padding. Specifying
	//  a scheme will result in an exception
	StringSource(plain, true, 
		new StreamTransformationFilter(e,
			new StringSink(cipher)
		) // StreamTransformationFilter      
	); // StringSource


	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;
	CFB_Mode< AES >::Decryption d;
	d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(cipher, true, 
		new StreamTransformationFilter(d,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource
	cout << "recovered text: " << recovered << endl;
	return;
}

void CTR_enMODE(string& plain, const byte* key, const byte* iv)
{
	CTR_Mode< AES >::Encryption e;
	e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	// The StreamTransformationFilter adds padding
	//  as required. ECB and CBC Mode must be padded
	//  to the block size of the cipher.
	StringSource(plain, true, 
		new StreamTransformationFilter(e,
			new StringSink(cipher)
		) // StreamTransformationFilter      
	); // StringSource
	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;
	CTR_Mode< AES >::Decryption d;
	d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(cipher, true, 
		new StreamTransformationFilter(d,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource
	cout << "recovered text: " << recovered << endl;
	return;
}

void ECB_enMODE(string& plain, const byte* key, const byte* iv)
{
	cout << "plain text: " << plain << endl;

	ECB_Mode< AES >::Encryption e;
	e.SetKey(key, AES::DEFAULT_KEYLENGTH);
	// The StreamTransformationFilter adds padding
	//  as required. ECB and CBC Mode must be padded
	//  to the block size of the cipher.
	StringSource(plain, true, 
		new StreamTransformationFilter(e,
			new StringSink(cipher)
		) // StreamTransformationFilter      
	); // StringSource

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;

	ECB_Mode< AES >::Decryption d;
	d.SetKey(key, AES::DEFAULT_KEYLENGTH);
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(cipher, true, 
		new StreamTransformationFilter(d,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource
	cout << "recovered text: " << recovered << endl;
	return;
}

void GCM_enMODE(string& plain, const byte* key, const byte* iv)
{
	const int TAG_SIZE = 12;

	cout << "plain text: " << plain << endl;
    GCM< AES >::Encryption e;
    e.SetKeyWithIV( key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE );

    StringSource ss1( plain, true,
        new CryptoPP::AuthenticatedEncryptionFilter( e,
            new StringSink( cipher ), false, TAG_SIZE
        ) // AuthenticatedEncryptionFilter
    ); // StringSource


	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;
	GCM< AES >::Decryption d;
    d.SetKeyWithIV( key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE );

    CryptoPP::AuthenticatedDecryptionFilter df( d,
        new StringSink(recovered ), CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
        TAG_SIZE
    ); // AuthenticatedDecryptionFilter

    // The StringSource dtor will be called immediately
    //  after construction below. This will cause the
    //  destruction of objects it owns. To stop the
    //  behavior so we can get the decoding result from
    //  the DecryptionFilter, we must use a redirector
    //  or manually Put(...) into the filter without
    //  using a StringSource.
    StringSource ss2( cipher, true,
        new CryptoPP::Redirector( df /*, PASS_EVERYTHING */ )
    ); // StringSource

    // If the object does not throw, here's the only
    //  opportunity to check the data's integrity
    if( true == df.GetLastResult() ) {
        cout << "recovered text: " << recovered << endl;
    }
    return;
}

void OFB_enMODE(string& plain, const byte* key, const byte* iv)
{

	OFB_Mode< AES >::Encryption e;
	e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	// OFB mode must not use padding. Specifying
	//  a scheme will result in an exception
	StringSource(plain, true, 
		new StreamTransformationFilter(e,
			new StringSink(cipher)
		) // StreamTransformationFilter      
	); // StringSource
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;
	OFB_Mode< AES >::Decryption d;
	d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(cipher, true, 
		new StreamTransformationFilter(d,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource
	cout << "recovered text: " << recovered << endl;
	return;
}

void XTS_enMODE(string& plain, const byte* key, const byte* iv)
{
	XTS_Mode< AES >::Encryption e;
	e.SetKeyWithIV(key, 32, iv);
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(plain, true, 
		new StreamTransformationFilter(e,
			new StringSink(cipher)
		) // StreamTransformationFilter
	); // StringSource

	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;	
	XTS_Mode< AES >::Decryption d;
	d.SetKeyWithIV(key, 32, iv);
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(cipher, true, 
		new StreamTransformationFilter(d,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource
	cout << "recovered text: " << recovered << endl;
	return;
}	

void CBC_deMODE(string& cipher, const byte* key, const byte* iv)
{
	CBC_Mode< AES >::Decryption d;
	d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(cipher, true, 
		new StreamTransformationFilter(d,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource
	cout << "recovered text: " << recovered << endl;
	return;
}

void CCM_deMODE(string& cipher, const byte* key, const byte* iv)
{	
	const int TAG_SIZE = 8;
	CCM< AES, TAG_SIZE >::Decryption d;
	d.SetKeyWithIV( key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);
	d.SpecifyDataLengths( 0, cipher.size()-TAG_SIZE, 0 );
	CryptoPP::AuthenticatedDecryptionFilter df( d,
		new StringSink( recovered )
	); // AuthenticatedDecryptionFilter
	// The StringSource dtor will be called immediately
	//  after construction below. This will cause the
	//  destruction of objects it owns. To stop the
	//  behavior so we can get the decoding result from
	//  the DecryptionFilter, we must use a redirector
	//  or manually Put(...) into the filter without
	//  using a StringSource.
	StringSource ss2( cipher, true,
		new CryptoPP::Redirector( df )
	); // StringSource
	// If the object does not throw, here's the only
	//  opportunity to check the data's integrity
	if( true == df.GetLastResult() ) {
		cout << "recovered text: " << recovered << endl;
	}
	return;
}

void CFB_deMODE(string& cipher, const byte* key, const byte* iv)
{
	CFB_Mode< AES >::Decryption d;
	d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(cipher, true, 
		new StreamTransformationFilter(d,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource
	cout << "recovered text: " << recovered << endl;
	return;
}

void CTR_deMODE(string& cipher, const byte* key, const byte* iv)
{
	CTR_Mode< AES >::Decryption d;
	d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(cipher, true, 
		new StreamTransformationFilter(d,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource
	cout << "recovered text: " << recovered << endl;
	return;
}

void ECB_deMODE(string& cipher, const byte* key, const byte* iv)
{
	ECB_Mode< AES >::Decryption d;
	d.SetKey(key, AES::DEFAULT_KEYLENGTH);
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(cipher, true, 
		new StreamTransformationFilter(d,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource
	cout << "recovered text: " << recovered << endl;
	return;
}

void GCM_deMODE(string& cipher, const byte* key, const byte* iv)
{
	const int TAG_SIZE = 12;
	GCM< AES >::Decryption d;
    d.SetKeyWithIV( key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE );

    CryptoPP::AuthenticatedDecryptionFilter df( d,
        new StringSink(recovered ), CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
        TAG_SIZE
    ); // AuthenticatedDecryptionFilter

    // The StringSource dtor will be called immediately
    //  after construction below. This will cause the
    //  destruction of objects it owns. To stop the
    //  behavior so we can get the decoding result from
    //  the DecryptionFilter, we must use a redirector
    //  or manually Put(...) into the filter without
    //  using a StringSource.
    StringSource ss2( cipher, true,
        new CryptoPP::Redirector( df /*, PASS_EVERYTHING */ )
    ); // StringSource

    // If the object does not throw, here's the only
    //  opportunity to check the data's integrity
    if( true == df.GetLastResult() ) {
        cout << "recovered text: " << recovered << endl;
    }
	return;
}

void OFB_deMODE(string& cipher, const byte* key, const byte* iv)
{
	OFB_Mode< AES >::Decryption d;
	d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(cipher, true, 
		new StreamTransformationFilter(d,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource
	cout << "recovered text: " << recovered << endl;
	return;
}

void XTS_deMODE(string& cipher, const byte* key, const byte* iv)
{
	XTS_Mode< AES >::Decryption d;
	d.SetKeyWithIV(key, 32, iv);
	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(cipher, true, 
		new StreamTransformationFilter(d,
			new StringSink(recovered)
		) // StreamTransformationFilter
	); // StringSource
	cout << "recovered text: " << recovered << endl;
	return;
}