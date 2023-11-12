#ifndef FILESYSTEM_APP_APPCONSTANTS_H
#define FILESYSTEM_APP_APPCONSTANTS_H

#include <string>

using namespace std;

namespace EnvVars
{

    namespace rootFolder
    {
        const string USER_DIR = "personal";
        const string META_FILE = "_meta_.txt";
        const string FS = "filesystem";
        const string USERS_KEY = "users_key";
        const string ADMIN = "admin";
        const string PUB_KEY_EXT = "_public.pem";
        const string PVT_KEY_EXT = "_private.pem";
        const string AES_KEY_EXT = "-encrypted_key.bin";
        const string SHARED = "shared";
        const string USER = "____user____";
        const string PVT = "private";
    }

    namespace CMDConstants
    {

        const std::string EXIT = "exit";
        const std::string ADDUSER = "adduser";
        const std::string MKFILE = "mkfile";
        const std::string MKDIR = "mkdir";
        const std::string SHARE = "share";
        const std::string CAT = "cat";
        const std::string LS = "ls";
        const std::string CD = "cd";
        const std::string PWD = "pwd";
        const std::string CP = "cp";
        const std::string HELP = "help";

        enum Command
        {
            CMD_EXIT,
            CMD_ADDUSER,
            CMD_MKFILE,
            CMD_MKDIR,
            CMD_SHARE,
            CMD_CAT,
            CMD_LS,
            CMD_CD,
            CMD_PWD,
            CMD_INVALID,
            CMD_HELP
        };
    }
}

#endif // FILESYSTEM_APP_APPCONSTANTS_H
