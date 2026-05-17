#pragma once
#include <string>

class CryptoManager {
public:

    static bool generateRSAKeyPair();

    static bool signFile(const std::string& filePath);

    static bool verifyFile(const std::string& filePath);

    bool encryptFileAES(
        const std::string& inputPath,
        const std::string& outputPath
    );

    bool decryptFileAES(
        const std::string& inputPath,
        const std::string& outputPath
    );
};