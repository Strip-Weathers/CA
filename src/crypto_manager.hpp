#pragma once
#include <string>

class CryptoManager {
public:

    static bool generateRSAKeyPair();

    bool signFile(
        const std::string& filePath,
        const std::string& privateKeyPath,
        const std::string& signaturePath
    );

    bool verifyFile(
        const std::string& filePath,
        const std::string& publicKeyPath,
        const std::string& signaturePath
    );

    bool encryptFileAES(
        const std::string& inputPath,
        const std::string& outputPath
    );

    bool decryptFileAES(
        const std::string& inputPath,
        const std::string& outputPath
    );
};