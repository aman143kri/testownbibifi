#ifndef FILESYSTEM_APP_KEYENCRYPTER_H
#define FILESYSTEM_APP_KEYENCRYPTER_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include "EnvVars.h"
#include "CipherFile.h"

using namespace std;
using namespace EnvVars::rootFolder;

class CipherKey
{
public:
    // Function for managing AES key generation and encryption
    int aesKeyManager(string username, vector<string> filePath)
    {
        // Define the size of the AES key in bits
        const int aesKeySize = 256;

        // Buffer to store the generated AES key
        unsigned char aesKey[aesKeySize / 8];

        // Generate random bytes to create the AES key
        if (!RAND_bytes(aesKey, aesKeySize / 8))
        {
            cout << "AES Key Generation Error" << endl;
            return 1;
        }

        // Read the public RSA key from file
        RSA *keyPublic = nullptr;
        string publicKeyName = filePath[0] + "/" + username + PUB_KEY_EXT;
        char *publicKeyFile = new char[publicKeyName.length() + 1];
        strcpy(publicKeyFile, publicKeyName.c_str());
        FILE *publicKeyFilePointer = fopen(publicKeyFile, "r");

        if (!publicKeyFilePointer)
        {
            cout << "Could not open public key file" << endl;
            return 1;
        }

        keyPublic = PEM_read_RSAPublicKey(publicKeyFilePointer, nullptr, nullptr, nullptr);
        fclose(publicKeyFilePointer);

        if (!keyPublic)
        {
            cout << "Could not load public key" << endl;
            return 1;
        }

        // Calculate the size of the RSA encrypted key
        const int rsaEncryptedSize = RSA_size(keyPublic);

        // Buffer to store the RSA encrypted AES key
        unsigned char keyEncrypted[rsaEncryptedSize];

        // Encrypt the AES key using RSA public key
        int keySizeEncrypted = RSA_public_encrypt(aesKeySize / 8, aesKey, keyEncrypted, keyPublic, RSA_PKCS1_OAEP_PADDING);
        if (keySizeEncrypted == -1)
        {
            cout << "AES Key Encryption Error" << endl;
            RSA_free(keyPublic);
            return 1;
        }

        // Create the file path for storing the encrypted AES key
        string fileBinName = filePath[0] + "/" + username + AES_KEY_EXT;

        // Convert string to char array
        char *keyEncrypted_file = new char[fileBinName.length() + 1];
        strcpy(keyEncrypted_file, fileBinName.c_str());

        // Open the file to store the encrypted AES key
        ofstream keyEncrypted_stream(keyEncrypted_file, ios::out | ios::binary);

        if (!keyEncrypted_stream.is_open())
        {
            cout << "Could not open Encrypted Key File" << endl;
            RSA_free(keyPublic);
            return 1;
        }

        // Write the encrypted AES key to the file
        keyEncrypted_stream.write((const char *)keyEncrypted, keySizeEncrypted);
        keyEncrypted_stream.close();

        // Free the allocated memory and return success
        RSA_free(keyPublic);
        return 0;
    }
 // Function for decrypting the AES key
    unsigned char *aesKeyDescryption(vector<string> filePath, string username)
    {
        // Read the private RSA key from file
        RSA *keyPrivate = nullptr;
        string keyPrivate_path = filePath[1] + "/" + username + PVT_KEY_EXT;
        char *keyPrivate_file = new char[keyPrivate_path.length() + 1];
        strcpy(keyPrivate_file, keyPrivate_path.c_str());
        FILE *keyPrivate_fp = fopen(keyPrivate_file, "r");

        if (!keyPrivate_fp)
        {
            cout << "Could not open Private Key File" << endl;
            return nullptr;
        }

        keyPrivate = PEM_read_RSAPrivateKey(keyPrivate_fp, nullptr, nullptr, nullptr);
        fclose(keyPrivate_fp);

        if (!keyPrivate)
        {
            cout << "\nKey file is invalid\n"
                 << endl;
            return nullptr;
        }

        // Create the file path for the encrypted AES key
        string aes_keyPrivate_path = filePath[0] + "/" + username + AES_KEY_EXT;

        // Convert string to char array
        char *keyEncrypted_file = new char[aes_keyPrivate_path.length() + 1];
        strcpy(keyEncrypted_file, aes_keyPrivate_path.c_str());

        // Open the file to read the encrypted AES key
        ifstream keyEncrypted_stream(keyEncrypted_file, ios::in | ios::binary);
        if (!keyEncrypted_stream.is_open())
        {
            cout << "\nKey file is invalid\n"
                 << endl;
            RSA_free(keyPrivate);
            return nullptr;
        }

        // Calculate the size of the RSA encrypted key
        const int rsaEncryptedSize = RSA_size(keyPrivate);

        // Buffer to store the RSA encrypted AES key
        unsigned char keyEncrypted[rsaEncryptedSize];

        // Read the encrypted AES key from file
        keyEncrypted_stream.read((char *)keyEncrypted, rsaEncryptedSize);
        keyEncrypted_stream.close();

        // Define the size of the AES key in bits
        const int aesKeySize = 256;

        // Buffer to store the decrypted AES key
        unsigned char *aesKey = new unsigned char[aesKeySize / 8];

        // Decrypt the AES key using RSA private key
        int keySizeDecrypted = RSA_private_decrypt(rsaEncryptedSize, keyEncrypted, aesKey, keyPrivate, RSA_PKCS1_OAEP_PADDING);

        if (keySizeDecrypted == -1)
        {
            cout << "\nKey file is invalid\n"
                 << endl;
            RSA_free(keyPrivate);
            delete[] aesKey;
            return nullptr;
        }

        // Free the allocated memory and return the decrypted AES key
        RSA_free(keyPrivate);
        return aesKey;
    }
};

#endif // FILESYSTEM_APP_KEYENCRYPTER_H
