#ifndef FILESYSTEM_APP_AUTH_H
#define FILESYSTEM_APP_AUTH_H
#include <iostream>
#include <sys/stat.h>
#include <sys/types.h>
#include <filesystem>
#include <termios.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>
#include <string>
#include <regex>
#include <algorithm>
#include "Miscellaneous.h"
#include "EnvVars.h"
#include "AddNewUser.h"
#include "GenerateRandom.h"
#include "CipherKey.h"

using namespace Utilities;
using namespace EnvVars::rootFolder;
using namespace std;

class AccessManager
{

private:
    AddNewUser mAddNewUser;
    GenerateRandom mRandom;
    CipherKey mCipherKey;

public:
    //
    int AdminCreation(bool checkAdmin)
    {
        int codeStatus = DirectoryCreation();
        if (codeStatus == 201)
        {
            AdminUserCreation();
        }
        if (codeStatus == 201 || codeStatus == 200)
            chdir(FS.c_str());
        return codeStatus;
    }
    //
int FileSystemChecking(bool checkAdmin)
    {
        int pointerStatus = stat(FS.c_str(), &info);
        if (pointerStatus == 0 && S_ISDIR(info.st_mode))
            return 200;
        else
            return 404;
    }
    //
    int DirectoryCreation()
    {
        int pointerStatus = stat(FS.c_str(), &info);
        if (pointerStatus == 0 && S_ISDIR(info.st_mode))
            return 200;

        string personal_random_dir = GenerateRandom::randomStringGenerator();
        string shared_random_dir = GenerateRandom::randomStringGenerator();
        string users_key_random_dir = GenerateRandom::randomStringGenerator();
        string admin = GenerateRandom::randomStringGenerator();
        string private_k = GenerateRandom::randomStringGenerator();

        map<string, string> keyFolderValues = {
            {USER_DIR, personal_random_dir},
            {SHARED, shared_random_dir},
            {USERS_KEY, users_key_random_dir},
            {ADMIN, admin},
            {PVT, private_k}};

        string localChildFolder = FS + "/" + personal_random_dir;
        string localSharedFolder = FS + "/" + shared_random_dir;
        string child_folder_users = FS + "/" + users_key_random_dir;
        string child_folder_users_private = child_folder_users + "/" + private_k;

        int s1 = mkdir(FS.c_str(), 0777);
        int s2 = mkdir(localChildFolder.c_str(), 0777);
        int s3 = mkdir(localSharedFolder.c_str(), 0777);
        int s4 = mkdir(child_folder_users.c_str(), 0777);
        int s5 = mkdir(child_folder_users_private.c_str(), 0777);

        if (s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0)
        {
            string rootPath = Miscellaneous::fetchDirRoot(Miscellaneous::fetchPwdPath(), FS) + "/" + FS;
            mRandom.metaFileCreation(rootPath, keyFolderValues);
            map<string, string> kp = mRandom.fetchFromMeta(rootPath);
            return 201;
        }
        else
            return 500;
    }

    //
    void AdminUserCreation()
    {
        string pwd = Miscellaneous::fetchPwdPath() + "/" + FS;
        string rootPath = Miscellaneous::fetchDirRoot(pwd, FS);
        vector<string> filePath = Miscellaneous::fetchPubPvtKeyPath(rootPath);
        mAddNewUser.KeyGenerator(ADMIN, filePath);
        mCipherKey.aesKeyManager(ADMIN, filePath);
    }

    //
    string fetchCurrUser(string input)
    {
        string currUser = "";
        int pos = input.find(PVT_KEY_EXT);
        if (pos != string::npos)
        {                                    // check if "_private.pem" exists in the input string
            currUser = input.substr(0, pos); // extract the characters before "_private.pem"
        }
        if (currUser.empty())
        {
            cout << "\nWrong key format. The key format should be in the <username>_private.pem format." << endl;
            return "";
        }
        return currUser;
    }
unsigned char *SignIn(string currUser)
    {
        string pwd = Miscellaneous::fetchPwdPath();
        string rootPath = Miscellaneous::fetchDirRoot(pwd, FS);
        string users_path = rootPath + "/" + GenerateRandom::fetchValueMeta(rootPath, USERS_KEY);
        vector<string> filesAll = Miscellaneous::fetchFromDir(users_path);
        string publicKeyName = Miscellaneous::wherePubKey(filesAll, currUser);

        vector<string> filePath = Miscellaneous::fetchPubPvtKeyPath(rootPath);
        unsigned char *key = mCipherKey.aesKeyDescryption(filePath, currUser);
        return key;
    }

    void ifNotAdmin(bool checkAdmin, string currUser)
    {
        if (!checkAdmin)
        {
            string rootPath = Miscellaneous::fetchDirRoot(Miscellaneous::fetchPwdPath(), FS);
            string randomised_currUser = GenerateRandom::fetchValueMeta(rootPath, currUser);
            chdir(randomised_currUser.c_str());
        }
    }
};

#endif // FILESYSTEM_APP_AUTH_H
