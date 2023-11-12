#ifndef FILESYSTEM_APP_RANDOMIZER_H
#define FILESYSTEM_APP_RANDOMIZER_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include "Miscellaneous.h"
#include "CipherFile.h"

using namespace EnvVars::rootFolder;
using namespace std;

class GenerateRandom
{

public:
    // Function to generate a random string of a given length
    static string randomStringGenerator(int length = 30)
    {
        // Characters that can be used in the random string
        string possibleChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        string result = "";
        static bool initialized = false;

        // Initialize random seed only once
        if (!initialized)
        {
            srand(time(nullptr));
            initialized = true;
        }

        // Generate the random string
        for (int i = 0; i < length; i++)
        {
            int randomIndex = rand() % possibleChars.length();
            result += possibleChars[randomIndex];
        }
        return result;
    }

    // Function to create or update a metadata file with key-value pairs
    static void metaFileCreation(string rootPath, map<string, string> keyFolderValues)
    {
        ofstream myfile;

        // Decrypt existing metadata file content
        string dataDecrypted = metaFileDecrypter(rootPath);

        stringstream ss;
        ss << dataDecrypted;

        // Add new key-value pairs to the metadata content
        for (const auto &pair : keyFolderValues)
        {
            ss << pair.first << " " << pair.second << "\n";
        }
        string content = ss.str();

        // Encrypt and save the metadata file
        CipherFile::FileEncrypter(rootPath + "/" + META_FILE, content);
    }

    // Function to decrypt the content of the metadata file
    static string metaFileDecrypter(string rootPath)
    {
        ifstream file(rootPath + "/" + META_FILE);

        if (!file.is_open())
        {
            return "";
        }

        // Read the content of the file
        string content((istreambuf_iterator<char>(file)), (istreambuf_iterator<char>()));
        file.close();

        // Decrypt the content and return
        return CipherFile::fetchDecryptedData(rootPath + "/" + META_FILE);
    }

    // Function to fetch key-value pairs from the metadata file
    static map<string, string> fetchFromMeta(string rootDirectory)
    {
        // Path to the metadata file
        string filePathMeta = rootDirectory + "/" + META_FILE;

        // Decrypt metadata file content
        string dataDecrypted = metaFileDecrypter(rootDirectory);
        stringstream ss(dataDecrypted);

        // Parse key-value pairs
        map<string, string> pairsKeyValue;
        string line;
        while (getline(ss, line))
        {
            size_t pos = line.find(' ');
            if (pos != string::npos)
            {
                string _key = line.substr(0, pos);
                string value = line.substr(pos + 1);
                pairsKeyValue[_key] = value;
            }
        }
        return pairsKeyValue;
    }
   // Function to fetch the list of users with whom a file is shared
    static vector<string> fetchUsernameShare(string rootDirectory, string fileNameParent)
    {
        map<string, string> pairsKeyValue = fetchFromMeta(rootDirectory);
        auto it = pairsKeyValue.find(fileNameParent);

        // If the file is not found, return an empty vector
        if (it == pairsKeyValue.end())
        {
            return {};
        }

        string input = it->second;

        // Extract shared usernames from metadata
        size_t start = input.find(SHARED) + SHARED.length() + 1;
        size_t end = input.length();

        vector<string> users;
        string values = input.substr(start, end - start);

        istringstream iss(values);
        string value;
        while (iss >> value)
        {
            users.push_back(value);
        }
        return users;
    }

    // Function to fetch the value associated with a key from the metadata file
    static string fetchValueMeta(string rootDirectory, string key)
    {
        map<string, string> pairsKeyValue = fetchFromMeta(rootDirectory);
        auto it = pairsKeyValue.find(key);

        // If the key is not found, return an empty string
        if (it == pairsKeyValue.end())
        {
            return "";
        }

        // Extract the value and handle spaces
        if (it->second.find(' '))
        {
            string val = split(it->second, ' ')[0];
            return val;
        }
        return it->second;
    }

    // Function to split a string based on a delimiter
    static vector<string> split(string s, char delimiter)
    {
        vector<string> chars;
        istringstream iss(s);
        string character;

        while (getline(iss, character, delimiter))
        {
            chars.push_back(character);
        }

        return chars;
    };

    // Function to translate a file path in reverse based on metadata
    static string getTranslatedPathRev(string rootDirectory, string input)
    {
        map<string, string> pairsKeyValue = fetchFromMeta(rootDirectory);
        vector<string> Directories;
        istringstream iss(input);
        string dir;

        // Split the input path into directories
        while (getline(iss, dir, '/'))
        {
            Directories.push_back(dir);
        }

        // Translate directory names based on metadata
        for (int i = 0; i < Directories.size(); i++)
        {
            for (auto const &[key, value] : pairsKeyValue)
            {
                if (Directories[i] == value)
                {
                    Directories[i] = key;
                    break;
                }
            }
        }

        // Reconstruct and return the translated path
        string output;
        for (int i = 0; i < Directories.size(); i++)
        {
            output += Directories[i];
            if (i != Directories.size() - 1)
            {
                output += "/";
            }
        }
        return output;
    }
static string fetchKeyMeta(string rootDirectory, string value)
    {
        map<string, string> pairsKeyValue = fetchFromMeta(rootDirectory);

        // Iterate through key-value pairs to find a match
        for (auto it = pairsKeyValue.begin(); it != pairsKeyValue.end(); ++it)
        {
            string currValue = it->second;
            if (it->second.find(' '))
            {
                currValue = split(it->second, ' ')[0];
            }

            // Return the key when a match is found
            if (currValue == value)
            {
                return it->first;
            }
        }
        return "";
    }

    // Function to translate a file path based on metadata
    static string getTranslatedPath(string rootDirectory, string input)
    {
        map<string, string> pairsKeyValue = fetchFromMeta(rootDirectory);
        vector<string> tokens;
        istringstream iss(input);
        string token;

        // Split the input path into tokens
        while (getline(iss, token, '/'))
        {
            tokens.push_back(token);
        }
        // Translate tokens based on metadata
        for (int i = 0; i < tokens.size(); i++)
        {
            // Check if the token has a corresponding translation in metadata
            if (pairsKeyValue.count(tokens[i]) > 0)
            {
                tokens[i] = pairsKeyValue[tokens[i]];
            }
        }

        // Reconstruct and return the translated path
        string output = "";
        for (int i = 0; i < tokens.size(); i++)
        {
            if (i > 0)
            {
                output += "/";
            }
            output += tokens[i];
        }
        return output;
    }

    // Function to check if a file is shared based on metadata
    static bool shareChecking(string rootDirectory, string fileNameParent)
    {
        map<string, string> pairsKeyValue = fetchFromMeta(rootDirectory);
        auto it = pairsKeyValue.find(fileNameParent);

        // If the file is not found, return false
        if (it == pairsKeyValue.end())
        {
            return false;
        }

        string val = it->second;

        // Check if the file is marked as shared in metadata
        if (val.find(SHARED) != string::npos)
            return true;

        return false;
    }

    // Function to change the shared status of a file in metadata
    static void changeShareStat(string rootDirectory, string fileNameParent, string usernameOfShared)
    {
        string filePathMeta = rootDirectory + "/" + META_FILE;
        string dataDecrypted = metaFileDecrypter(rootDirectory);
        size_t pos = dataDecrypted.find(fileNameParent);

        // If the file is found in metadata
        if (pos != string::npos)
        {
            size_t endPos = dataDecrypted.find('\n', pos);
            string line = dataDecrypted.substr(pos, endPos - pos);

            // Check if the user is already in the shared list
            if (line.find(usernameOfShared) != string::npos)
                return;

            // Update the shared status in metadata
            if (line.find(SHARED) != string::npos)
                line = line + " " + usernameOfShared + "\n";
            else
                line = line + " " + SHARED + " " + usernameOfShared + "\n";

            // Replace the old metadata with the updated version
            dataDecrypted.replace(pos, endPos - pos + 1, line);

            // Encrypt and save the updated metadata file
            CipherFile::FileEncrypter(rootDirectory + "/" + META_FILE, dataDecrypted);
        }
    }
};

#endif // FILESYSTEM_APP_RANDOMIZER_H
