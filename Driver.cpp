// lib cryptopp needed
// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.so -lcryptopp -lpthread -shared -fpermissive -fPIC -Wall -Wextra
	
#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "serpent.h"
using CryptoPP::Serpent;

#include "modes.h"
using CryptoPP::CBC_Mode;

#include "secblock.h"
using CryptoPP::SecByteBlock;
using CryptoPP::byte;

extern "C"{
    char* decrypt (char* encrypted, int e_size, char* key_char)
    {
        string recovered, key_encoded;
        CryptoPP::byte iv[Serpent::BLOCKSIZE] = { 0 };

        /*********************************\
        \*********************************/

        string key_str(key_char);
        // Pretty print key
        SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(&key_str[0]), key_str.size());
        StringSource ss1(key, key.size(), true,
            new HexEncoder(
                new StringSink(key_encoded)
            ) // HexEncoder
        ); // StringSource

        unsigned char encrypted_array[e_size];
        memcpy(encrypted_array, encrypted, e_size);

        /*********************************\
        \*********************************/

        try
        {
            CBC_Mode< Serpent >::Decryption d;
            d.SetKeyWithIV(key, key.size(), iv);

            // The StreamTransformationFilter removes
            //  padding as required.
            StringSource ss5(encrypted_array, e_size, true,
                new StreamTransformationFilter(d,
                    new StringSink(recovered), StreamTransformationFilter::NO_PADDING
                ) // StreamTransformationFilter
            ); // StringSource
        }
        catch(const CryptoPP::Exception& e)
        {
            cerr << e.what() << endl;
            exit(1);
        }

        /*********************************\
        \*********************************/

        char * decrypted;
        decrypted = new char[recovered.length() + 1];
        strcpy(decrypted, recovered.c_str());
        decrypted[recovered.length() + 1] = '\0';

        return strdup(decrypted);
    }

    void freeme(char *ptr)
    {
        free(ptr);
    }
}

