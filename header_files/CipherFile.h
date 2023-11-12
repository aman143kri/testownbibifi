#ifndef FILESYSTEM_APP_FILEENCRYPTOR_H
#define FILESYSTEM_APP_FILEENCRYPTOR_H

// Include necessary libraries and headers
#include <iostream>
#include <string>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <vector>
#include "CipherKey.h"

// Using the standard namespace
using namespace std;

// Class definition for File Encryption using AES
class CipherFile
{
private:
    // Static key for encryption/decryption
    static unsigned char key[16];
    // Instance of CipherKey class for dynamic key handling
    CipherKey mCipherKey;

public:
    // Function for dynamically encrypting file content
    void dynamicFileEncryption(string fileName, string contents, vector<string> filePath, string username)
    {
        // Initializing AES key
        AES_KEY aesKey;
        AES_set_encrypt_key(mCipherKey.aesKeyDescryption(filePath, ADMIN), 128, &aesKey);

        // Convert input string to vector of unsigned characters
        vector<unsigned char> inputBuffer(contents.begin(), contents.end());

        // Padding the input to multiples of 16 bytes
        int padding = 16 - (inputBuffer.size() % 16);
        for (int i = 0; i < padding; i++)
        {
            inputBuffer.push_back('\0');
        }

        // Output buffer for encrypted data
        vector<unsigned char> outputBuffer;
        for (int i = 0; i < inputBuffer.size(); i += 16)
        {
            unsigned char inBlock[16], outBlock[16];
            // Copy 16 bytes of input data to inBlock
            for (int j = 0; j < 16; j++)
            {
                inBlock[j] = inputBuffer[i + j];
            }
            // Encrypt inBlock and store the result in outBlock
            AES_encrypt(inBlock, outBlock, &aesKey);
            // Append encrypted block to the output buffer
            for (int j = 0; j < 16; j++)
            {
                outputBuffer.push_back(outBlock[j]);
            }
        }
 // Write the encrypted data to the output file
        ofstream outFile(fileName, ios::out | ios::binary);
        if (!outFile.is_open())
        {
            cout << "Error: Unable to create file " << fileName << endl;
            return;
        }
        outFile.write((char *)outputBuffer.data(), outputBuffer.size());
        outFile.close();
    }

    // Static function for encrypting file content using a predefined key
    static void FileEncrypter(string fileName, string contents)
    {
        AES_KEY aesKey;
        AES_set_encrypt_key(key, 128, &aesKey);

        vector<unsigned char> inputBuffer(contents.begin(), contents.end());
        int padding = 16 - (inputBuffer.size() % 16);
        for (int i = 0; i < padding; i++)
        {
            inputBuffer.push_back('\0');
        }
        vector<unsigned char> outputBuffer;
        for (int i = 0; i < inputBuffer.size(); i += 16)
        {
            unsigned char inBlock[16], outBlock[16];
            for (int j = 0; j < 16; j++)
            {
                inBlock[j] = inputBuffer[i + j];
            }
            AES_encrypt(inBlock, outBlock, &aesKey);
            for (int j = 0; j < 16; j++)
            {
                outputBuffer.push_back(outBlock[j]);
            }
        }
        ofstream outFile(fileName, ios::out | ios::binary);
        if (!outFile.is_open())
        {
            cout << "Error: Unable to create file " << fileName << endl;
            return;
        }
        outFile.write((char *)outputBuffer.data(), outputBuffer.size());
        outFile.close();
    }

    // Static function for decrypting file content using a predefined key
    static vector<unsigned char> FileDecrypter(string fileName, string realFileName = "")
    {
        AES_KEY aesKey;
        AES_set_decrypt_key(key, 128, &aesKey);
        vector<unsigned char> outputBuffer;
        ifstream in_file(fileName, ios::in | ios::binary);
        if (!in_file.is_open())
        {
            cout << realFileName << " doesn't exist." << endl;
            return outputBuffer;
        }
        vector<unsigned char> inputBuffer(istreambuf_iterator<char>(in_file), {});
        in_file.close();
        for (int i = 0; i < inputBuffer.size(); i += 16)
        {
            unsigned char inBlock[16], outBlock[16];
            for (int j = 0; j < 16; j++)
            {
                inBlock[j] = inputBuffer[i + j];
            }
            AES_decrypt(inBlock, outBlock, &aesKey);
            for (int j = 0; j < 16; j++)
            {
                outputBuffer.push_back(outBlock[j]);
            }
        }
        int padding = 0;
        for (int i = outputBuffer.size() - 1; i >= 0; i--)
        {
            if (outputBuffer[i] == '\0')
            {
                padding++;
            }
            else
            {
                break;
            }
        }
        outputBuffer.resize(outputBuffer.size() - padding);
        return outputBuffer;
    }
 // Function for dynamically decrypting file content
    vector<unsigned char> dynamicFileDecrypter(string fileName, string realFileName, vector<string> filePath)
    {
        AES_KEY aesKey;
        AES_set_decrypt_key(mCipherKey.aesKeyDescryption(filePath, ADMIN), 128, &aesKey);
        vector<unsigned char> outputBuffer;
        ifstream in_file(fileName, ios::in | ios::binary);
        if (!in_file.is_open())
        {
            cout << realFileName << " doesn't exist." << endl;
            return outputBuffer;
        }
        vector<unsigned char> inputBuffer(istreambuf_iterator<char>(in_file), {});
        in_file.close();
        for (int i = 0; i < inputBuffer.size(); i += 16)
        {
            unsigned char inBlock[16], outBlock[16];
            for (int j = 0; j < 16; j++)
            {
                inBlock[j] = inputBuffer[i + j];
            }
            AES_decrypt(inBlock, outBlock, &aesKey);
            for (int j = 0; j < 16; j++)
            {
                outputBuffer.push_back(outBlock[j]);
            }
        }
        int padding = 0;
        for (int i = outputBuffer.size() - 1; i >= 0; i--)
        {
            if (outputBuffer[i] == '\0')
            {
                padding++;
            }
            else
            {
                break;
            }
        }
        outputBuffer.resize(outputBuffer.size() - padding);
        return outputBuffer;
    }

    // Static function to print decrypted data to the console
    static void printDecryptedData(string fileName, string realFileName)
    {
        vector<unsigned char> outputBuffer = FileDecrypter(fileName, realFileName);
        cout.write((char *)outputBuffer.data(), outputBuffer.size());
        cout << endl;
    }

    // Function for dynamically printing decrypted data to the console
    void dynamicPrintDecryptedData(string fileName, string realFileName, vector<string> filePath)
    {
        // Decrypting file using dynamically generated AES key
        vector<unsigned char> outputBuffer = dynamicFileDecrypter(fileName, realFileName, filePath);

        // Printing the decrypted data to the console
        cout.write((char *)outputBuffer.data(), outputBuffer.size());
        cout << endl;
    }

    // Function for dynamically fetching decrypted data as a string
    string dynamicFetchDecryptedData(string fileName, string realFileName, vector<string> filePath)
    {
        // Decrypting file using dynamically generated AES key
        vector<unsigned char> outputBuffer = dynamicFileDecrypter(fileName, realFileName, filePath);

        // Converting the decrypted data to a string
        return string((char *)outputBuffer.data(), outputBuffer.size());
    }

    // Static function to fetch decrypted data as a string
    static string fetchDecryptedData(string fileName)
    {
        // Decrypting file using predefined AES key
        vector<unsigned char> outputBuffer = FileDecrypter(fileName);

        // Converting the decrypted data to a string
        return string((char *)outputBuffer.data(), outputBuffer.size());
    }
};

// Initializing the static key for encryption/decryption
unsigned char CipherFile::key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

#endif // FILESYSTEM_APP_FILEENCRYPTOR_H
