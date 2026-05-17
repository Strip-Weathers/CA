#include "crypto_manager.hpp"

#include <iostream>
#include <string>
using namespace std;
int main(int argc, char* argv[]){
    if (argc < 2){
        cout << "Usage: crypto_tool genkey\n";
        return 1;
    }

    string command = argv[1];

    if (command == "genkey"){
        if (CryptoManager::generateRSAKeyPair()){
            cout << "Keys generated successfully\n";
        }
        else{
            cout << "Key generation failed\n";
        }
    }

    else if (command == "sign"){
        if (argc < 3){
            cout << "Usage: exe sign <file>\n";
            return 1;
        }

        if (CryptoManager::signFile(argv[2])){
            cout << "File signed successfully\n";
        }
        else{
            cout << "Signing failed\n";
        }
    }

    else if (command == "verify"){
        if (argc < 3){
            cout << "Usage: exe verify <file>\n";
            return 1;
        }

        if (CryptoManager::verifyFile(argv[2])){
            cout << "VALID SIGNATURE\n";
        }
        else{
            cout << "INVALID SIGNATURE\n";
        }
    }

    return 0;
}