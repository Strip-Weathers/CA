#include "crypto_manager.hpp"

#include <iostream>
#include <string>

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: crypto_tool genkey\n";
        return 1;
    }

    std::string command = argv[1];

    if (command == "genkey")
    {
        if (CryptoManager::generateRSAKeyPair())
        {
            std::cout << "Keys generated successfully\n";
        }
        else
        {
            std::cout << "Key generation failed\n";
        }
    }

    return 0;
}