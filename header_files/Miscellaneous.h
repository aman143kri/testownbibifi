#ifndef FILESYSTEM_APP_UTILS_H
#define FILESYSTEM_APP_UTILS_H

#include <vector>
#include <sstream>
#include <map>
#include <filesystem>
#include <dirent.h>
#include "EnvVars.h"
#include "GenerateRandom.h"
#include <sys/stat.h>

using namespace std;
using namespace EnvVars::CMDConstants;
using namespace EnvVars::rootFolder;
using namespace filesystem;

struct stat info;

namespace Utilities
{

    class Miscellaneous
    {
    public:
        // Function to fetch the command based on the provided lexeme and IP address
        static Command fetchCmd(vector<string> lexeme, string ip)
        {
            // Define conditions for each command and check if they match the input lexeme
            // Returns the corresponding command if a single match is found
            map<Command, bool> values = {
                {CMD_EXIT, !lexeme.empty() && lexeme[0] == EXIT},
                {CMD_ADDUSER, lexeme.size() == 2 && lexeme[0] == ADDUSER && ipValidation(lexeme[1])},
                {CMD_MKFILE, lexeme.size() > 1 && lexeme[0] == MKFILE && ipValidation(lexeme[1])},
                {CMD_MKDIR, lexeme.size() == 2 && lexeme[0] == MKDIR && ipValidation(lexeme[1])},
                {CMD_SHARE, lexeme.size() == 3 && lexeme[0] == SHARE},
                {CMD_CAT, lexeme.size() == 2 && lexeme[0] == CAT},
                {CMD_LS, (lexeme.size() == 2 && lexeme[0] == LS) || ip == LS},
                {CMD_CD, lexeme.size() == 2 && lexeme[0] == CD},
                {CMD_PWD, ip == PWD},
                {CMD_HELP, ip == HELP}};
            return CmdFind(values);
        };

        // Function to validate IP addresses
        static bool ipValidation(string ip)
        {
            // Check for invalid IP addresses or path traversal attempts
            if (ip == "." || ip == ".." || ip.size() > 0 && (ip[0] == '.' || ip[0] == '/' || (ip.size() > 1 && ip.substr(0, 2) == "..")) || ip.find('/') != std::string::npos)
            {
                return false;
            }
            return true;
        }

        // Function to split a string into a vector of substrings based on a delimiter
        static vector<string> split(string str, char delimiter)
        {
            // Trim leading and trailing whitespaces from the input string
            string s = trim(str);
            vector<string> chars;
            istringstream iss(s);
            string character;

            // Split the string using the specified delimiter
            while (getline(iss, character, delimiter))
            {
                chars.push_back(character);
            }

            return chars;
        };

        // Function to replace consecutive whitespaces with a single space
        static string oneSpaceOnly(string str)
        {
            regex pattern("\\s+");
            return regex_replace(str, pattern, " ");
        }

        // Function to check if the root directory is present in the path
        static bool isRootDirInPath(vector<string> ipArray, bool checkAdmin, string username)
        {
            bool isFilesystemIn = false;

            for (int i = 0; i < ipArray.size(); i++)
            {
                if (checkAdmin && ipArray[i] == FS)
                {
                    isFilesystemIn = true;
                    break;
                }
                else if (!checkAdmin && ipArray[i] == username)
                {
                    isFilesystemIn = true;
                    break;
                }
            }
            return isFilesystemIn;
        }

        // Function to fetch the paths for public and private keys
    static vector<string> fetchPubPvtKeyPath()
        {
            string pwd = Miscellaneous::fetchPwdPath() + "/" + FS;
            string rootPath = Miscellaneous::fetchDirRoot(pwd, FS);
            vector<string> filePath = Miscellaneous::fetchPubPvtKeyPath(rootPath);
            return filePath;
        }

        // Function to create a unique directory or file name based on the provided name
        static string makingDirFile(string name)
        {
            string pwd = Miscellaneous::fetchPwdPath() + "/" + FS;
            string rootPath = Miscellaneous::fetchDirRoot(pwd, FS);

            // Generate a unique filename value
            string valueFilename = GenerateRandom::fetchValueMeta(rootPath, name);

            // If the filename value is empty, create a new entry in the metadata file
            if (valueFilename.empty())
            {
                map<string, string> keyFolderValues = {{name, GenerateRandom::randomStringGenerator()}};
                GenerateRandom::metaFileCreation(rootPath, keyFolderValues);
                valueFilename = GenerateRandom::fetchValueMeta(rootPath, name);
            }
            return valueFilename;
        }

        // Function to check if the given path corresponds to a file
        static bool typeFileIs(string ip)
        {
            struct stat fileInfo;
            if (stat(ip.c_str(), &fileInfo) < 0)
            {
                cout << "Stat was not able to perform." << endl;
                return false;
            }
            if (S_ISREG(fileInfo.st_mode))
            {
                return true;
            }
            cout << "\n Name not a file.\n";
            return false;
        }

        // Function to find a command based on a map of command-value pairs
        static Command CmdFind(const map<Command, bool> &values)
        {
            // Find the command that matches the conditions in the map
            Command result;
            int actualCnt = 0;
            for (const auto &[command, value] : values)
            {
                if (value)
                {
                    actualCnt++;
                    result = command;
                }
            }
            return (actualCnt == 1) ? result : CMD_INVALID;
        }

        // Function to trim leading and trailing whitespaces from a string
        static string trim(string str)
        {
            while (!str.empty() && isspace(str.front()))
            {
                str.erase(0, 1);
            }

            while (!str.empty() && isspace(str.back()))
            {
                str.pop_back();
            }

            return str;
        }

        // Function to concatenate vector elements into a string, starting from a specified index
        static string vectorStr(vector<string> lexeme, int indexStarts = 0, string addSep = " ")
        {
            ostringstream result;
            for (vector<string>::iterator it = lexeme.begin() + indexStarts; it != lexeme.end(); it++)
            {
                if (it != lexeme.begin() + indexStarts)
                {
                    result << addSep;
                }
                result << *it;
            }
            return result.str();
        };

        // Function to retrieve the root directory path based on the provided directory name and path
        static string onlyRoot(string directoryName, string path)
        {
            vector<string> diffParts = Miscellaneous::split(path, '/');
            auto it = find(diffParts.begin(), diffParts.end(), directoryName);
            if (it != diffParts.end())
            {
                diffParts.erase(it + 1, diffParts.end());
            }
            string pathFinal = Miscellaneous::vectorStr(diffParts, 0, "/");
            return pathFinal;
        }
        // Function to fetch the root directory path based on the directory name and path
        static string fetchDirRoot(string pathPwd, string directoryName)
        {
            string rootDirectory_path = Miscellaneous::onlyRoot(directoryName, pathPwd);
            return rootDirectory_path;
        }

        // Function to fetch paths for public and private keys
        static vector<string> fetchPubPvtKeyPath(string rootPath)
        {
            vector<string> filePath;

            vector<string> content = split(rootPath, '/');
            content.pop_back();

            string keyPrivate_path = vectorStr(content, 0, "/");
            string keyPublic_path = rootPath + "/" + GenerateRandom::fetchValueMeta(rootPath, USERS_KEY);

            filePath.push_back(keyPublic_path);
            filePath.push_back(keyPrivate_path);
            return filePath;
        }

        // Function to fetch files from a directory
        static vector<string> fetchFromDir(string path)
        {
            vector<string> currFile;
            DIR *dir;
            struct dirent *entry;
            dir = opendir(path.c_str());
            if (!dir)
            {
                cout << "Unable to open directory" << endl;
            }
            while ((entry = readdir(dir)) != NULL)
            {
                if (entry->d_type == DT_REG)
                {
                    currFile.push_back(entry->d_name);
                }
            }
            closedir(dir);
            return currFile;
        }

        // Function to fetch the username from a file path
        static string fetchFilePathUsername(string path)
        {
            string username = "";
            size_t pos = path.find("/" + FS + "/");
            if (pos != string::npos)
            {
                username = path.substr(pos + 12, path.find("/", pos + 12) - pos - 12);
            }
            return username;
        }

        // Function to check if a directory exists
        static bool doesDirExist(string directoryName)
        {
            int pointerStatus = stat(directoryName.c_str(), &info);
            if (pointerStatus == 0 && S_ISDIR(info.st_mode))
                return true;
            else
                return false;
        };

        // Function to get the index of an item in a vector
        static int getIdxVector(vector<string> path, string nameOfItem)
        {
            auto it = find(path.begin(), path.end(), nameOfItem);
            if (it != path.end())
                return it - path.begin();
            else
                return -1;
        }

        // Function to fetch the path of public keys
        static string fetchPubKeys()
        {
            string pwd = Miscellaneous::fetchPwdPath() + "/" + FS;
            string rootPath = Miscellaneous::fetchDirRoot(pwd, FS);
            vector<string> filePath = Miscellaneous::fetchPubPvtKeyPath(rootPath);
            return filePath[0];
        }

        // Function to fetch the current working directory path
        static string fetchPwdPath()
        {
            char currentWorkDir[1024];
            if (getcwd(currentWorkDir, sizeof(currentWorkDir)) == NULL)
            {
                cout << "Unable to get current directory" << endl;
            }
            return currentWorkDir;
        }

        // Function to check if a path contains the "/user" prefix
        static bool withPers(const string &str)
        {
            bool isPersonalFound = str.compare(0, 9, "/" + USER_DIR) == 0;
            if (!isPersonalFound)
            {
                cout << "\nForbidden\n"
                     << endl;
            }
            return isPersonalFound;
        }

        // Function to fetch the public key file name for a given username
        static string wherePubKey(vector<string> filesAll, string username)
        {
            string keyPublic = "";
            for (const string &k : filesAll)
            {
                vector<string> kp = Miscellaneous::split(k, '_');
                if (kp[0] == username)
                {
                    keyPublic = k;
                    break;
                }
            }
            return keyPublic;
        }
    };
}

#endif // FILESYSTEM_APP_UTILS_H
