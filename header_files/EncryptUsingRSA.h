#ifndef FILESYSTEM_APP_RSAENCRYPTION_H
#define FILESYSTEM_APP_RSAENCRYPTION_H

#include <iostream>
#include <vector>
#include <sstream>
#include <filesystem>
#include <termios.h>
#include <unistd.h>
#include <curses.h>
#include <cstdlib>
#include <cstring>
#include <cstdlib>
#include <dirent.h>
#include <map>
#include <cstdlib>
#include <fstream>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "AccessManager.h"
#include "Miscellaneous.h"
#include "EnvVars.h"
#include "CipherFile.h"
#include "AddNewUser.h"
#include "GenerateRandom.h"

using namespace std;
using namespace Utilities;
using namespace EnvVars::rootFolder;

class EncryptUsingRSA
{

private:
    CipherFile mCipherFile; // Instance of CipherFile for additional functionality

public:
    // Function for RSA encryption of a text and writing the result to a file
    int RSAEncrypter(const string &vanillaText, const string &publicKeyFile, const string &encryptedFileOutput)
    {
        // Open the public key file for reading
        FILE *publicKey = fopen(publicKeyFile.c_str(), "rb");
        if (!publicKey)
        {
            cout << "Couldnt open public key file." << endl;
            return 1;
        }

        // Read the RSA public key
        RSA *rsa = PEM_read_RSAPublicKey(publicKey, NULL, NULL, NULL);
        fclose(publicKey);

        if (!rsa)
        {
            cout << "Couldnt read public key file." << endl;
            return 1;
        }

        // Calculate the maximum length of data that can be encrypted
        int dataLenMax = RSA_size(rsa) - 42;

        // Check if the input text is too long for RSA encryption
        if (vanillaText.length() > dataLenMax)
        {
            cout << "RSA cannot encrypt text, too long." << endl;
            RSA_free(rsa);
            return 1;
        }

        // Buffer to store the encrypted data
        vector<unsigned char> encryptedData(RSA_size(rsa));

        // Perform RSA encryption
        int encryptedDataLen = RSA_public_encrypt(vanillaText.length(), (unsigned char *)vanillaText.c_str(), &encryptedData[0], rsa, RSA_PKCS1_OAEP_PADDING);

        if (encryptedDataLen == -1)
        {
            cout << "Couldnt encrypt text." << endl;
            RSA_free(rsa);
            return 1;
        }

        // Write the encrypted data to the output file
        ofstream otptFile(encryptedFileOutput, ios::out | ios::binary);
        if (!otptFile)
        {
            cout << "Could not open output file." << endl;
            RSA_free(rsa);
            return 1;
        }

        otptFile.write((char *)&encryptedData[0], encryptedDataLen);
        otptFile.close();

        // Free resources and return success
        RSA_free(rsa);
        return 0;
    }

 // Function for RSA decryption of a file and returning the decrypted content as a string
    string RSADecrypter(const string &encryptedFile, const string &privateKeyFile, bool checkAdmin, const string &privateKeyName_for_admin, vector<string> filePath)
    {
        // Open the private key file for reading
        FILE *privateKey = fopen(privateKeyFile.c_str(), "rb");
        if (!privateKey)
        {
            cout << "Could not open private key file." << endl;
            return "";
        }

        // Read the RSA private key
        RSA *rsa = PEM_read_RSAPrivateKey(privateKey, NULL, NULL, NULL);
        fclose(privateKey);

        if (!rsa)
        {
            cout << "Could not read private key file." << endl;
            return "";
        }

        // Open the encrypted data file for reading
        ifstream encryptedDataFile(encryptedFile, ios::in | ios::binary);

        // Check if the file is not found and admin check is enabled
        if (!encryptedDataFile && checkAdmin)
        {
            RSA_free(rsa);
            // Fetch decrypted data using the admin's private key
            string key_name = mCipherFile.dynamicFetchDecryptedData(privateKeyName_for_admin, "", filePath);
            return decryptedFilePrinter(key_name, encryptedFile);
        }
        // Check if the file is not found
        else if (!encryptedDataFile)
        {
            cout << "Could not open decrypted file." << endl;
            RSA_free(rsa);
            return "";
        }

        // Read the encrypted data from file
        vector<unsigned char> encryptedData((istreambuf_iterator<char>(encryptedDataFile)), istreambuf_iterator<char>());
        encryptedDataFile.close();

        // Buffer to store the decrypted data
        vector<unsigned char> decryptedData(RSA_size(rsa));

        // Perform RSA decryption
        int decryptedDataLen = RSA_private_decrypt(encryptedData.size(), &encryptedData[0], &decryptedData[0], rsa, RSA_PKCS1_OAEP_PADDING);

        // Check if decryption fails and admin check is enabled
        if (decryptedDataLen == -1 && checkAdmin)
        {
            RSA_free(rsa);
            // Fetch decrypted data using the admin's private key
            string key_name = mCipherFile.dynamicFetchDecryptedData(privateKeyName_for_admin, "", filePath);
            return decryptedFilePrinter(key_name, encryptedFile);
        }
        // Check if decryption fails
        if (decryptedDataLen == -1)
        {
            cout << "Could not decrypt file." << endl;
            RSA_free(rsa);
            return "";
        }

        // Free resources and return the decrypted content as a string
        RSA_free(rsa);
        return string((char *)&decryptedData[0], decryptedDataLen);
    }

    // Function to print the content of a decrypted file
    void decryptedContentPrinter(const string &encryptedFile, const string &privateKeyFile, bool checkAdmin, const string &privateKeyName_for_admin, vector<string> filePath)
    {
        // Retrieve the decrypted content
        string fileContent = RSADecrypter(encryptedFile, privateKeyFile, checkAdmin, privateKeyName_for_admin, filePath);

        // Print the decrypted content to the console
        cout.write((char *)fileContent.data(), fileContent.size());
        cout << endl;
    }

    // Function to read the content of a file into a string
    string fileReader(string pathFile)
    {
        ifstream file(pathFile);
        stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    // Function to print the content of a decrypted file using a given private key
    string decryptedFilePrinter(string keyPrivate_str, string pathFile)
    {
        // Initialize OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        // Convert the private key string to a C string
        const char *keyPrivate_cstr = keyPrivate_str.c_str();

        // Create a BIO for reading the private key
        BIO *bio = BIO_new_mem_buf((void *)keyPrivate_cstr, -1);
        RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        // Open the encrypted data file for reading
        ifstream encryptedDataFile(pathFile, ios::in | ios::binary);
        if (!encryptedDataFile)
        {
            cout << "decryptedFilePrinter - Could not open decrypted file." << endl;
            RSA_free(rsa);
            return "";
        }

        // Read the encrypted data from file
        vector<unsigned char> encryptedData((istreambuf_iterator<char>(encryptedDataFile)), istreambuf_iterator<char>());
        encryptedDataFile.close();

        // Buffer to store the decrypted data
        vector<unsigned char> decryptedData(RSA_size(rsa));

        // Perform RSA decryption
        int decryptedDataLen = RSA_private_decrypt(encryptedData.size(), &encryptedData[0], &decryptedData[0], rsa, RSA_PKCS1_OAEP_PADDING);

        if (decryptedDataLen == -1)
        {
            cout << "Error decrypting data." << endl;
            RSA_free(rsa);
            return "";
        }

        // Free resources and return the decrypted content as a string
        RSA_free(rsa);
        return string((char *)&decryptedData[0], decryptedDataLen);
    }
};

#endif // FILESYSTEM_APP_RSAENCRYPTION_H
