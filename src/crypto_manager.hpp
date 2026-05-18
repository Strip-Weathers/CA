#pragma once

#include <string>
#include <vector>

class CryptoManager {
public:

    static bool generateRSAKeyPair(const std::string& privateKeyPath, const std::string& publicKeyPath);

    static bool generateCAKeyPair();

    static bool signPublicKey(const std::string& userPublicKeyPath, const std::string& outputCertPath);

    static bool verifyCertificate(const std::string& userPublicKeyPath, const std::string& certPath, const std::string& caPublicKeyPath);

    static bool signFile(const std::string& filePath, const std::string& privateKeyPath, const std::string& signaturePath);

    static bool verifyFile(const std::string& filePath, const std::string& publicKeyPath, const std::string& signaturePath);

    static bool encryptFileAES(const std::string& filePath, const std::string& encryptedPath, const std::string& aesKeyPath);

    static bool decryptFileAES(const std::string& encryptedPath, const std::string& aesKeyPath, const std::string& outputPath);

    static bool encryptAESKey(const std::string& aesKeyPath, const std::string& receiverPublicKeyPath, const std::string& encryptedKeyPath);

    static bool decryptAESKey(const std::string& encryptedKeyPath, const std::string& receiverPrivateKeyPath, const std::string& outputKeyPath);

    static bool sendMessage(const std::string& senderName, const std::string& receiverName, const std::string& messagePath);

    static bool receiveMessage(const std::string& receiverName);

    static bool gatewaySend(const std::string& filePath);

    static std::vector<unsigned char> readFile(const std::string& path);
    static bool writeFile(const std::string& path, const std::vector<unsigned char>& data);
};

