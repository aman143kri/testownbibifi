#ifndef FILESYSTEM_APP_CREATEUSER_H
#define FILESYSTEM_APP_CREATEUSER_H

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "Miscellaneous.h"
#include "EncryptUsingRSA.h"
#include "CipherKey.h"
#include "CipherFile.h"

using namespace Utilities;
using namespace EnvVars::rootFolder;

class AddNewUser
{

private:
    EncryptUsingRSA mEncryptUsingRSA;
    CipherKey mCipherKey;
    CipherFile mCipherFile;

public:
    // Function to generate an RSA key pair for a new user
    // newUser: Username of the new user
    // filePath: Paths for public and private key storage
    // username: Username for user-specific operations (optional)
    bool KeyGenerator(string newUser, vector<string> filePath, string username = "")
    {
        int result = 0;
        int keyBits = 4096;

        RSA *r = NULL;
        BIGNUM *bne = NULL;
        BIO *publicBP = NULL, *privateBP = NULL, *privateBP_share_admin = NULL;
        unsigned long e = RSA_F4;
        string publicKeyName = filePath[0] + "/" + newUser + "_public.pem";
        string privateKeyName = filePath[1] + "/" + newUser + "_private.pem";

        // Create a big number with a specific exponent (RSA_F4)
        bne = BN_new();
        result = BN_set_word(bne, e);
        if (result != 1)
        {
            goto cleanup; // Handle errors and cleanup
        }

        // Generate an RSA key pair
        r = RSA_new();
        result = RSA_generate_key_ex(r, keyBits, bne, NULL);
        if (result != 1)
        {
            goto cleanup; // Handle errors and cleanup
        }

        // Save the public key to a file
        publicBP = BIO_new_file(publicKeyName.c_str(), "w+");
        result = PEM_write_bio_RSAPublicKey(publicBP, r);
        if (result != 1)
        {
            goto cleanup; // Handle errors and cleanup
        }

        // Save the private key to a file
        privateBP = BIO_new_file(privateKeyName.c_str(), "w+");
        result = PEM_write_bio_RSAPrivateKey(privateBP, r, NULL, NULL, 0, NULL, NULL);



 if (newUser != ADMIN)
        {
            // If the new user is not the admin, generate a private key file for admin
            // and encrypt it using AES, then store it in a designated path.

            // Create a BIO for in-memory private key storage
            BIO *bio = BIO_new(BIO_s_mem());
            PEM_write_bio_RSAPrivateKey(bio, r, NULL, NULL, 0, NULL, NULL);

            char *buffer;
            long length = BIO_get_mem_data(bio, &buffer);

            string keyPrivate_string(buffer, length);

            // Get file paths and directories
            vector<string> filePath = Miscellaneous::fetchPubPvtKeyPath();

            // Get root directory path
            string rootPath = Miscellaneous::fetchDirRoot(Miscellaneous::fetchPwdPath(), FS);
            string privateKeyName_for_admin = filePath[0] + "/" +
                                              GenerateRandom::fetchValueMeta(rootPath, PVT) + "/" +
                                              newUser + "_private.pem";
            string admin_publicKeyName = filePath[0] + "/" + ADMIN + "_public.pem";
            string aesKey_path = filePath[0] + "/" + ADMIN + AES_KEY_EXT;

            // Encrypt the admin's private key and store it
            mCipherFile.dynamicFileEncryption(privateKeyName_for_admin, keyPrivate_string, filePath, username);
            BIO_free(bio); // Cleanup memory BIO
        }

    cleanup:
        // Clean up resources
        BIO_free_all(publicBP);
        BIO_free_all(privateBP);
        BIO_free_all(privateBP_share_admin);
        RSA_free(r);
        BN_free(bne);

        return (result == 1);
    }
};

#endif // FILESYSTEM_APP_CREATEUSER_H
