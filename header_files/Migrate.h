#ifndef FILESYSTEM_APP_SHAREFILE_H
#define FILESYSTEM_APP_SHAREFILE_H

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
#include "AccessManager.h"
#include "Miscellaneous.h"
#include "EnvVars.h"
#include "CipherFile.h"
#include "AddNewUser.h"
#include "GenerateRandom.h"
#include "EncryptUsingRSA.h"

using namespace std;
using namespace Utilities;
using namespace EnvVars::rootFolder;

class Migrate
{
    EncryptUsingRSA mEncryptUsingRSA;

public:
    // Function to share a file between users using RSA encryption
    void FileShare(string filename, string usernameShare, string realFileName, string shareUsernameActual, string username)
    {
        // Fetching the root path and constructing the destination share path
        string pwd = Miscellaneous::fetchPwdPath() + "/" + FS;
        string rootPath = Miscellaneous::fetchDirRoot(pwd, FS);
        string destinationSharePath;

        // Determine if the share is for the admin or a regular user
        if (shareUsernameActual == ADMIN)
        {
            destinationSharePath = rootPath + "/" + GenerateRandom::fetchValueMeta(rootPath, SHARED);
        }
        else
        {
            destinationSharePath = rootPath + "/" + usernameShare + "/" + GenerateRandom::fetchValueMeta(rootPath, SHARED);
        }

        // Creating a unique file destination name for the shared file
        string fileDestinationName = Miscellaneous::makingDirFile(username + "-" + realFileName);
        destinationSharePath = destinationSharePath + "/" + fileDestinationName;

        // Fetching the file paths for public and private keys
        vector<string> filePath = Miscellaneous::fetchPubPvtKeyPath();

        // Constructing the paths for the private key of the sharing user and the public key of the receiving user
        string keyPvtPath = filePath[1] + "/" + username + PVT_KEY_EXT;
        string keyPubPath = filePath[0] + "/" + shareUsernameActual + PUB_KEY_EXT;

        // Decrypting the content of the file using the private key of the sharing user
        string contents = mEncryptUsingRSA.RSADecrypter(filename, keyPvtPath, false, "", filePath);

        // Encrypting the content using the public key of the receiving user and saving it to the destination share path
        mEncryptUsingRSA.RSAEncrypter(contents, keyPubPath, destinationSharePath);
    }
};

#endif // FILESYSTEM_APP_SHAREFILE_H
