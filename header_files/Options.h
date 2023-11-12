#ifndef FILESYSTEM_APP_MENU_H
#define FILESYSTEM_APP_MENU_H

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
#include "Migrate.h"
#include "CipherKey.h"

using namespace std;
using namespace Utilities;
using namespace EnvVars::rootFolder;

class Options
{
private:
    // Class members
    string username = "";
    string current_directoryName = "";
    CipherFile enc;
    AddNewUser mAddNewUser;
    EncryptUsingRSA mEncryptUsingRSA;
    Migrate mMigrate;
    CipherKey mCipherKey;
    bool checkAdmin;
    CipherFile mCipherFile;

public:
    // Constructor
    Options(string user, bool admin)
    {
        username = user;
        checkAdmin = admin;
    }

    // Display the command prompt and handle user input
    int displayCmd()
    {
        displayOptions();

        while (true)
        {
            string ip;
            showPwd();

            if (current_directoryName == FS)
                cout << "/ $ ";
            else
                cout << current_directoryName + " $ ";

            getline(cin, ip);
            if (ip.empty())
                continue;
            ip = Miscellaneous::trim(ip);
            ip = Miscellaneous::oneSpaceOnly(ip);
            if (ip.empty())
                continue;

            vector<string> lexeme = Miscellaneous::split(ip, ' ');

            Command currentCmd = Miscellaneous::fetchCmd(lexeme, ip);

            if (currentCmd == CMD_EXIT)
            {
                break;
            }

            switch (currentCmd)
            {
            case CMD_ADDUSER:
            {
                if (checkAdmin)
                {
                    // Handle adduser command
                    string newUser = lexeme[1];
                    string rootPath = Miscellaneous::fetchDirRoot(showPwd(), FS);
                    vector<string> filePath = Miscellaneous::fetchPubPvtKeyPath(rootPath);
                    int status = makeNewUser(rootPath, newUser);
                    if (status == 201)
                    {
                        mAddNewUser.KeyGenerator(newUser, filePath, username);
                        mCipherKey.aesKeyManager(newUser, filePath);
                    }
                }
                else
                {
                    cout << "Operation not permitted, please contact admin" << endl;
                }
                break;
            }

            case CMD_MKFILE:
            {
                if (Miscellaneous::withPers(relativeCurrPath()))
                {
                    // Handle mkfile command
                    string rootPath = Miscellaneous::fetchDirRoot(showPwd(), FS);
                    string _username = Miscellaneous::fetchFilePathUsername(Miscellaneous::fetchPwdPath());
                    string tgtUsername = GenerateRandom::fetchKeyMeta(rootPath, _username);
                    bool checkAdmin_inside_users_dir = GenerateRandom::fetchValueMeta(rootPath, USER + tgtUsername).empty() && checkAdmin;
                    mkfileCMD(lexeme[1], Miscellaneous::vectorStr(lexeme, 2, " "));
                }
                break;
            }

            case CMD_MKDIR:
            {
                if (Miscellaneous::withPers(relativeCurrPath()))
                {
                    // Handle mkdir command
                    string rootPath = Miscellaneous::fetchDirRoot(showPwd(), FS);
                    string _username = Miscellaneous::fetchFilePathUsername(Miscellaneous::fetchPwdPath());
                    string valueFilename = Miscellaneous::makingDirFile(lexeme[1]);
                    bool isPresent = Miscellaneous::doesDirExist(valueFilename);
                    if (!isPresent)
                        mkdir(valueFilename.c_str(), 0777);
                    else
                        cout << "Directory already exists" << endl;
                }
                break;
            }

            case CMD_SHARE:
            {
                // Handle share command
                shareOptions(lexeme[1], lexeme[2]);
                break;
            }

            case CMD_CAT:
            {
                // Handle cat command
                string rootPath = Miscellaneous::fetchDirRoot(showPwd(), FS);
                string fileNameTranslated = GenerateRandom::fetchValueMeta(rootPath, lexeme[1]);
                if (Miscellaneous::typeFileIs(fileNameTranslated))
                {
                    catCmd(fileNameTranslated, lexeme[1]);
                }
                break;
            }

            case CMD_LS:
            {
                // Handle ls command
                lsCmd();
                break;
            }

            case CMD_CD:
            {
                // Handle cd command
                cdCmd(lexeme[1]);
                break;
            }

            case CMD_PWD:
            {
                // Handle pwd command
                cout << relativeCurrPath() << endl;
                break;
            }

            case CMD_HELP:
            {
                // Display available options
                displayOptions();
                break;
            }

            default:
                cout << "\nInvalid Command\n"
                     << endl;
                break;
            }
        }
        return 0;
    }

    // Share file options
    void shareOptions(string fileName, string userTo)
    {
        if (username == userTo)
        {
            cout << "You cannot share a file with yourself" << endl;
            return;
        }

        bool adminReceiver = ADMIN == userTo;
        bool fileIsPresent = isFileInCWD(fileName);
        if (!fileIsPresent)
            return;
        bool isUser = adminReceiver || doesUserThere(userTo);
        bool isPresent = fileIsPresent && isUser;

        if (isPresent)
        {
            string rootPath = Miscellaneous::fetchDirRoot(showPwd(), FS);
            string filename = GenerateRandom::fetchValueMeta(rootPath, fileName);
            string usernameShare = GenerateRandom::fetchValueMeta(rootPath, userTo);
            mMigrate.FileShare(filename, usernameShare, fileName, userTo, username);
            string fileName_with_key_value = fileName + " " + GenerateRandom::fetchValueMeta(rootPath, fileName);
            GenerateRandom::changeShareStat(rootPath, fileName_with_key_value, userTo);
        }
    }

    // Get the relative current path
    string relativeCurrPath()
    {
        string pathPwd = showPwd();
        string rootDirectory = Miscellaneous::fetchDirRoot(Miscellaneous::fetchPwdPath(), FS);
        string pathTranslated = GenerateRandom::getTranslatedPathRev(rootDirectory, pathPwd);
        return printCurrWorkDir(pathTranslated);
    }

    // Check if the user exists
    bool doesUserThere(string usernameShare = "")
    {
        string pwd = Miscellaneous::fetchPwdPath() + "/" + FS;
        string rootPath = Miscellaneous::fetchDirRoot(pwd, FS);
        DIR *dir;
        struct dirent *entry;
        bool usernameIsPresent = false;
        dir = opendir(rootPath.c_str());
        if (!dir)
        {
            cout << "Directory could not be opened" << endl;
        }
        while ((entry = readdir(dir)) != NULL)
        {
            string nameDRandom = string(entry->d_name);
            string value;
            bool presentDot = nameDRandom == "." || nameDRandom == "..";
            if (!presentDot)
                value = GenerateRandom::fetchKeyMeta(rootPath, nameDRandom);
            else
                value = nameDRandom;

            if (entry->d_type == DT_DIR && !value.empty() && usernameShare == value)
            {
                usernameIsPresent = true;
            }
        }
        closedir(dir);
        if (!usernameIsPresent && !checkAdmin)
        {
            cout << "User " << usernameShare << " doesn't exist" << endl;
        }
        return usernameIsPresent;
    }

    // Check if the file is present in the current working directory
    bool isFileInCWD(string filename = "", string usernameShare = "")
    {
        string pwd = Miscellaneous::fetchPwdPath() + "/" + FS;
        string rootPath = Miscellaneous::fetchDirRoot(pwd, FS);
        DIR *dir;
        struct dirent *entry;
        bool filePresent = false;
        dir = opendir(".");
        if (!dir)
        {
            cout << "Error: Could not open directory" << endl;
        }
        while ((entry = readdir(dir)) != NULL)
        {
            string nameDRandom = string(entry->d_name);
            string value;
            bool presentDot = nameDRandom == "." || nameDRandom == "..";
            if (!presentDot)
                value = GenerateRandom::fetchKeyMeta(rootPath, nameDRandom);
            else
                value = nameDRandom;

            if (entry->d_type == DT_REG && !value.empty() && filename == value)
            {
                filePresent = true;
            }
        }
        closedir(dir);

        if (!filePresent)
        {
            cout << "File " << filename << " doesn't exist" << endl;
        }
        return filePresent;
    }

    // Share the file with another user
    void FileShare(string filename, string usernameShare)
    {
        string pwd = Miscellaneous::fetchPwdPath() + "/" + FS;
        string rootPath = Miscellaneous::fetchDirRoot(pwd, FS);
        string destinationSharePath = rootPath + "/" + usernameShare + "/" + GenerateRandom::fetchValueMeta(rootPath, SHARED);
        string cmd = CP + " " + filename + " " + destinationSharePath;
        int exit_code = system(cmd.c_str());
        if (exit_code == 0)
        {
            cout << "File shared successfully." << endl;
        }
        else
        {
            cout << "Failed to share the file." << endl;
        }
    }

    // Print the current working directory
    string printCurrWorkDir(string pathPwd)
    {
        if (pathPwd.empty())
            return "";
        vector<string> pathPwd_parts = Miscellaneous::split(pathPwd, '/');
        int index;
        if (checkAdmin)
        {
            index = Miscellaneous::getIdxVector(pathPwd_parts, FS);
        }
        else
        {
            index = Miscellaneous::getIdxVector(pathPwd_parts, username);
        }
        string abs_pathPwd = Miscellaneous::vectorStr(pathPwd_parts, index + 1, "/");
        return "/" + abs_pathPwd;
    }

    // Create a new user
    int makeNewUser(string rootDirectory_path, string username)
    {
        Miscellaneous::makingDirFile(USER + username);
        string nameRandom = Miscellaneous::makingDirFile(username);
        string folderPathUser = rootDirectory_path + "/" + nameRandom;
        int pointerStatus = stat(folderPathUser.c_str(), &info);
        if (pointerStatus == 0 && S_ISDIR(info.st_mode))
        {
            cout << "User " << username << " already exists" << endl;
            return 200;
        }
        int _status = mkdir(folderPathUser.c_str(), 0777);
        if (_status == 0)
        {
            string localChildFolder = folderPathUser + "/" + GenerateRandom::fetchValueMeta(rootDirectory_path, USER_DIR);
            string localSharedFolder = folderPathUser + "/" + GenerateRandom::fetchValueMeta(rootDirectory_path, SHARED);
            mkdir(localChildFolder.c_str(), 0777);
            mkdir(localSharedFolder.c_str(), 0777);
            return 201;
        }
        else
            return 500;
    }

    // Handle mkfile command
    void mkfileCMD(string filename, string content)
    {
        string pwd = Miscellaneous::fetchPwdPath() + "/" + FS;
        string rootPath = Miscellaneous::fetchDirRoot(pwd, FS);
        bool isShared = GenerateRandom::shareChecking(rootPath, filename);

        string valueFilename = Miscellaneous::makingDirFile(filename);
        string keyPublic_path = Miscellaneous::fetchPubKeys() + "/" + username + PUB_KEY_EXT;
        mEncryptUsingRSA.RSAEncrypter(content, keyPublic_path, valueFilename);

        if (isShared)
        {
            vector<string> users = GenerateRandom::fetchUsernameShare(rootPath, filename);
            for (const auto &user : users)
            {
                shareOptions(filename, user);
            }
        }
    }

    // Print the current working directory path
    string showPwd()
    {
        string cwd = Miscellaneous::fetchPwdPath();
        vector<string> lexeme = Miscellaneous::split(cwd, '/');

        string pwd = cwd + "/" + FS;
        string rootPath = Miscellaneous::fetchDirRoot(pwd, FS);

        current_directoryName = GenerateRandom::fetchKeyMeta(rootPath, lexeme[lexeme.size() - 1]);
        return cwd;
    }

    // Display the contents of a file
    void catCmd(string fileName, string realFileName)
    {
        string pwd = Miscellaneous::fetchPwdPath() + "/" + FS;
        string rootPath = Miscellaneous::fetchDirRoot(pwd, FS);
        vector<string> filePath = Miscellaneous::fetchPubPvtKeyPath(rootPath);
        string keyPrivate_path = filePath[1] + "/" + username + PVT_KEY_EXT;

        string tgtUsername;
        string privateKeyName_for_admin;
        if (checkAdmin)
        {
            string _username = Miscellaneous::fetchFilePathUsername(Miscellaneous::fetchPwdPath());
            tgtUsername = GenerateRandom::fetchKeyMeta(rootPath, _username);
            privateKeyName_for_admin = filePath[0] + "/" +
                                       GenerateRandom::fetchValueMeta(rootPath, PVT) + "/" +
                                       tgtUsername + PVT_KEY_EXT;
        }
        mEncryptUsingRSA.decryptedContentPrinter(fileName, keyPrivate_path, checkAdmin, privateKeyName_for_admin, filePath);
    }

    // Display available options
    void displayOptions()
    {
        cout << "\n";
        cout << "Welcome/Bienvenue User: " + username << endl;
        cout << "\n";
        cout << "Options:" << endl;
        cout << "Choose: " << endl;
        cout << "\n";
        cout << "cd <directory>" << endl;
        cout << "pwd" << endl;
        cout << "cat <filename>" << endl;
        cout << "mkdir <directory_name>" << endl;
        cout << "ls" << endl;
        cout << "mkfile <filename> <contents>" << endl;
        cout << "share <filename> <username>" << endl;
        cout << "help" << endl;
        cout << "exit" << endl;
        if (checkAdmin)
        {
            cout << "adduser <username>" << endl;
        }
        cout << "\n";
    }

    // Display the contents of the current directory
    void lsCmd()
    {
        string pwd = Miscellaneous::fetchPwdPath() + "/" + FS;
        string rootPath = Miscellaneous::fetchDirRoot(pwd, FS);
        DIR *dir;
        struct dirent *entry;
        dir = opendir(".");
        if (!dir)
        {
            cout << "Unable to open directory" << endl;
        }
        while ((entry = readdir(dir)) != NULL)
        {
            string nameDRandom = string(entry->d_name);
            string value;

            bool presentDot = nameDRandom == "." || nameDRandom == "..";
            if (!presentDot)
                value = GenerateRandom::fetchKeyMeta(rootPath, nameDRandom);
            else
                value = nameDRandom;

            if (value == USERS_KEY)
                continue;

            if (entry->d_type == DT_REG && !value.empty())
            {
                cout << "f -> " << value << endl;
            }
            else if (entry->d_type == DT_DIR && !value.empty())
            {
                cout << "d -> " << value << endl;
            }
        }
        closedir(dir);
    }

    // Change the current directory
    void cdCmd(string token)
    {
        string pathTranslated;
        string rootDirectory = Miscellaneous::fetchDirRoot(Miscellaneous::fetchPwdPath(), FS);
        pathTranslated = GenerateRandom::getTranslatedPath(rootDirectory, token);

        string f_path = newPathFetch(pathTranslated, token);
        vector<string> _f_path_parts = Miscellaneous::split(f_path, '/');
        string randomised_username = GenerateRandom::fetchValueMeta(rootDirectory, username);
        bool contains_rootDirectory = Miscellaneous::isRootDirInPath(_f_path_parts, checkAdmin, randomised_username);
        if (f_path.empty() || !contains_rootDirectory)
        {
            return;
        }
        chdir(pathTranslated.c_str());
    }

    // Fetch the new path
    string newPathFetch(string pathFile, string typed_pathFile)
    {
        try
        {
            if (!filesystem::exists(pathFile) || !filesystem::is_directory(pathFile))
            {
                cout << "Error: " << typed_pathFile << " This is not a valid directory." << endl;
                cout << "Ensure that you have entered the correct directory." << endl;
                return "";
            }

            string command = "cd " + pathFile + " && pwd";
            string futurePath = "";

            FILE *pipe = popen(command.c_str(), "r");
            if (!pipe)
            {
                cout << "Error" << typed_pathFile << endl;
                return "";
            }

            char buffer[128];
            while (fgets(buffer, sizeof(buffer), pipe) != NULL)
            {
                futurePath += buffer;
            }

            pclose(pipe);
            // remove trailing newline
            futurePath.erase(futurePath.find_last_not_of("\n") + 1);
            return futurePath;
        }
        catch (const filesystem::filesystem_error &ex)
        {
            cout << "Error: " << ex.what() << endl;
            return "";
        }
    };
};

#endif // FILESYSTEM_APP_MENU_H
