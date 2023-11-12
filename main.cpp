#include "header_files/AccessManager.h"
#include "header_files/Options.h"
#include "header_files/EnvVars.h"
#include <iostream>
#include <string>

using namespace EnvVars::rootFolder;
using namespace std;

int main(int argc, char* argv[]) {

    if(argc != 2) {
        cout << "\nPlease provide the keyfile for authentication purposes.\n" << endl;
        return 0;
    }

    AccessManager auth;
    CipherKey mCipherKey;

    string username = auth.fetchCurrUser(argv[1]);
    if(username.empty()) return 0;

    bool checkAdmin = username == ADMIN;

    int status = auth.FileSystemChecking(checkAdmin);
    if(status == 404 && !checkAdmin) {
        cout << "\nIt appears that you are a new user on this application. To get started, you will need to create an administrator account first.\n" << endl;
        return 0;
    }

    int create_admin_status = auth.AdminCreation(checkAdmin);

    unsigned char* SignIn_status;
    if(create_admin_status == 201) {
        SignIn_status = mCipherKey.aesKeyDescryption(Miscellaneous::fetchPubPvtKeyPath(),username);
    }

    if (create_admin_status != 201) {
        SignIn_status = auth.SignIn(username);
    }

    if (SignIn_status == nullptr) return 0;

    auth.ifNotAdmin(checkAdmin, username);
    Options menu(username, checkAdmin);
    menu.displayCmd();
    return 0;
}
