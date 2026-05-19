#include "crypto_manager.hpp"
#include <iostream>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fstream>
#include <vector>
#include <openssl/rand.h>
using namespace std;

string user1, user2;

bool CryptoManager::load_users(const std::string& user_1, const std::string& user_2){
user1 = user_1;
user2 = user_2;
return 1;
}

bool CryptoManager::generateRSAKeyPair(
    const std::string& privateKeyPath,
    const std::string& publicKeyPath
){
    cout << "\n[KEYGEN] Generating RSA key pair...\n";

    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (!ctx){
        cerr << "[ERROR] CTX creation failed\n";
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0){
        cerr << "[ERROR] keygen_init failed\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0){
        cerr << "[ERROR] keygen_bits failed\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY* pkey = nullptr;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0){
        cerr << "[ERROR] key generation failed\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    filesystem::path privPath(privateKeyPath);

    if (!privPath.parent_path().empty()){
        filesystem::create_directories(
            privPath.parent_path()
        );
    }

    filesystem::path pubPath(publicKeyPath);

    if (!pubPath.parent_path().empty()){
        filesystem::create_directories(
            pubPath.parent_path()
        );
    }

    FILE* private_file =
        fopen(privateKeyPath.c_str(), "wb");

    if (!private_file){
        cerr << "[ERROR] Cannot open private key file\n";

        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);

        return false;
    }

    PEM_write_PrivateKey(
        private_file,
        pkey,
        nullptr,
        nullptr,
        0,
        nullptr,
        nullptr
    );

    fclose(private_file);

    FILE* public_file =
        fopen(publicKeyPath.c_str(), "wb");

    if (!public_file){
        cerr << "[ERROR] Cannot open public key file\n";

        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);

        return false;
    }

    PEM_write_PUBKEY(public_file, pkey);

    fclose(public_file);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    cout << "[OK] RSA key pair generated\n";
    cout << "[INFO] Private key -> "
         << privateKeyPath << endl;

    cout << "[INFO] Public key  -> "
         << publicKeyPath << endl;

    return true;
}

bool CryptoManager::signFile(
    const std::string& filePath,
    const std::string& privateKeyPath,
    const std::string& signaturePath
){
    cout << "\n[SIGN] Signing file...\n";

    vector<unsigned char> fileData = readFile(filePath);

    if (fileData.empty()){
        cerr << "[ERROR] File is empty or missing\n";
        return false;
    }

    FILE* fp = fopen(privateKeyPath.c_str(), "rb");

    if (!fp){
        cerr << "[ERROR] Cannot open private key file\n";
        return false;
    }

    EVP_PKEY* privateKey =
        PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);

    fclose(fp);

    if (!privateKey){
        cerr << "[ERROR] Cannot load private key\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx){
        cerr << "[ERROR] Cannot create EVP_MD_CTX\n";
        EVP_PKEY_free(privateKey);
        return false;
    }

    if (EVP_DigestSignInit(
            ctx,
            nullptr,
            EVP_sha256(),
            nullptr,
            privateKey
        ) != 1)
    {
        cerr << "[ERROR] EVP_DigestSignInit failed\n";
        ERR_print_errors_fp(stderr);

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);

        return false;
    }

    if (EVP_DigestSignUpdate(
            ctx,
            fileData.data(),
            fileData.size()
        ) != 1)
    {
        cerr << "[ERROR] EVP_DigestSignUpdate failed\n";
        ERR_print_errors_fp(stderr);

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);

        return false;
    }

    size_t sigLen = 0;

    if (EVP_DigestSignFinal(
            ctx,
            nullptr,
            &sigLen
        ) != 1)
    {
        cerr << "[ERROR] Cannot determine signature size\n";
        ERR_print_errors_fp(stderr);

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);

        return false;
    }

    vector<unsigned char> signature(sigLen);

    if (EVP_DigestSignFinal(
            ctx,
            signature.data(),
            &sigLen
        ) != 1)
    {
        cerr << "[ERROR] Signing failed\n";
        ERR_print_errors_fp(stderr);

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);

        return false;
    }

    signature.resize(sigLen);

    if (!writeFile(signaturePath, signature)){
        cerr << "[ERROR] Cannot save signature file\n";

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);

        return false;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(privateKey);

    cout << "[OK] File signed successfully\n";
    cout << "[INFO] Signature -> " << signaturePath << "\n";

    return true;
}

bool CryptoManager::encryptFileAES(
    const std::string& filePath,
    const std::string& encryptedPath,
    const std::string& aesKeyPath
){
    cout << "\n[AES] Encrypting file...\n";

    vector<unsigned char> plaintext = readFile(filePath);
    if (plaintext.empty()){
        cout << "[ERROR] Input file empty or missing\n";
        return false;
    }

    vector<unsigned char> key(32);
    vector<unsigned char> iv(12);
    vector<unsigned char> tag(16);

    if (RAND_bytes(key.data(), key.size()) != 1 ||
        RAND_bytes(iv.data(), iv.size()) != 1){
        cout << "[ERROR] RAND_bytes failed\n";
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx){
        cout << "[ERROR] EVP_CIPHER_CTX_new failed\n";
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1){
        cout << "[ERROR] EncryptInit failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1){
        cout << "[ERROR] IV length set failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1){
        cout << "[ERROR] Key/IV init failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    vector<unsigned char> ciphertext(plaintext.size());
    int len = 0;
    int totalLen = 0;

    if (EVP_EncryptUpdate(
            ctx,
            ciphertext.data(),
            &len,
            plaintext.data(),
            plaintext.size()
        ) != 1){
        cout << "[ERROR] EncryptUpdate failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    totalLen = len;

    if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext.data() + totalLen,
            &len
        ) != 1){
        cout << "[ERROR] EncryptFinal failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    totalLen += len;
    ciphertext.resize(totalLen);

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1){
        cout << "[ERROR] GET_TAG failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    vector<unsigned char> output;
    output.reserve(iv.size() + tag.size() + ciphertext.size());

    output.insert(output.end(), iv.begin(), iv.end());
    output.insert(output.end(), tag.begin(), tag.end());
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());

    if (!writeFile(encryptedPath, output)){
        cout << "[ERROR] Cannot write encrypted file\n";
        return false;
    }

    if (!writeFile(aesKeyPath, key)){
        cout << "[ERROR] Cannot save AES key\n";
        return false;
    }

    cout << "[OK] File encrypted successfully\n";
    cout << "[INFO] Encrypted file -> " << encryptedPath << "\n";
    cout << "[INFO] AES key -> " << aesKeyPath << "\n";

    return true;
}


bool CryptoManager::decryptFileAES(
    const std::string& encryptedPath,
    const std::string& aesKeyPath,
    const std::string& outputPath
){
    cout << "\n[AES] Decrypting file...\n";

    vector<unsigned char> encrypted = readFile(encryptedPath);

    if (encrypted.size() < 12 + 16){
        cout << "[ERROR] File too small / corrupted\n";
        return false;
    }

    vector<unsigned char> iv(encrypted.begin(), encrypted.begin() + 12);
    vector<unsigned char> tag(encrypted.begin() + 12, encrypted.begin() + 28);
    vector<unsigned char> ciphertext(encrypted.begin() + 28, encrypted.end());

    vector<unsigned char> key = readFile(aesKeyPath);

    if (key.size() != 32){
        cout << "[ERROR] Invalid AES key size\n";
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx){
        cout << "[ERROR] EVP_CIPHER_CTX_new failed\n";
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1){
        cout << "[ERROR] DecryptInit failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1){
        cout << "[ERROR] IV length set failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1){
        cout << "[ERROR] Key/IV init failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    vector<unsigned char> plaintext(ciphertext.size());

    int len = 0;
    int totalLen = 0;

    if (EVP_DecryptUpdate(
            ctx,
            plaintext.data(),
            &len,
            ciphertext.data(),
            ciphertext.size()
        ) != 1){
        cout << "[ERROR] DecryptUpdate failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    totalLen = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1){
        cout << "[ERROR] SET_TAG failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int finalOk = EVP_DecryptFinal_ex(ctx, plaintext.data() + totalLen, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (finalOk <= 0){
        cout << "[ERROR] GCM AUTH FAILED (tampered data or wrong key)\n";
        return false;
    }

    totalLen += len;
    plaintext.resize(totalLen);

    if (!writeFile(outputPath, plaintext)){
        cout << "[ERROR] Cannot write output file\n";
        return false;
    }

    cout << "[OK] File decrypted successfully\n";
    cout << "[INFO] Output -> " << outputPath << "\n";

    return true;
}

#include <chrono>
#include <ctime>

string getTimestamp(){
    auto now = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now);
    return string(ctime(&t));
}

bool CryptoManager::signPublicKey(
    const std::string& userPublicKeyPath,
    const std::string& outputCertPath
){
    cout << "\n========== CA ==========\n";
    cout << "[CA] Signing user public key...\n";

    FILE* caFile = fopen("ca/private/ca_private.pem", "rb");
    if (!caFile){
        cerr << "[ERROR] Cannot open CA private key\n";
        return false;
    }

    EVP_PKEY* caKey = PEM_read_PrivateKey(caFile, nullptr, nullptr, nullptr);
    fclose(caFile);

    if (!caKey){
        cerr << "[ERROR] Cannot read CA private key\n";
        return false;
    }

    vector<unsigned char> pubKey = readFile(userPublicKeyPath);

    if (pubKey.empty()){
        cerr << "[ERROR] User public key is empty or missing\n";
        EVP_PKEY_free(caKey);
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx){
        cerr << "[ERROR] Cannot create digest context\n";
        EVP_PKEY_free(caKey);
        return false;
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, caKey) <= 0){
        cerr << "[ERROR] DigestSignInit failed\n";
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(caKey);
        return false;
    }

    if (EVP_DigestSignUpdate(ctx, pubKey.data(), pubKey.size()) <= 0){
        cerr << "[ERROR] DigestSignUpdate failed\n";
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(caKey);
        return false;
    }

    size_t sigLen = 0;

    if (EVP_DigestSignFinal(ctx, nullptr, &sigLen) <= 0){
        cerr << "[ERROR] Cannot determine signature size\n";
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(caKey);
        return false;
    }

    vector<unsigned char> signature(sigLen);

    if (EVP_DigestSignFinal(ctx, signature.data(), &sigLen) <= 0){
        cerr << "[ERROR] Certificate signing failed\n";
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(caKey);
        return false;
    }

    signature.resize(sigLen);


    if (!writeFile(outputCertPath, signature)){
        cerr << "[ERROR] Cannot save certificate\n";
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(caKey);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(caKey);

    cout << "[OK] Certificate generated successfully\n";
    cout << "[INFO] User public key -> " << userPublicKeyPath << "\n";
    cout << "[INFO] Certificate -> " << outputCertPath << "\n";

    return true;
}
#include <filesystem>
bool CryptoManager::sendMessage(
    const std::string& senderName,
    const std::string& receiverName,
    const std::string& messagePath
){
    cout << "\n========== SENDER ==========\n";

    string encryptedPath =
        user1 + "/message.bin";

    string aesKeyPath =
        user1 + "/" + senderName + "_aes.key";

    string encryptedKeyPath =
        user1 + "/" + senderName + "_to_" +
        receiverName + ".key.enc";

    string certPath =
        user2 + "/inbox/" + senderName + ".cert";

    string receiverPubKey =
        user2 + "/" + receiverName + "_public.pem";

    string senderPrivKey =
        user1 + "/" + senderName + "_private.pem";

    if (!encryptFileAES(
            messagePath,
            encryptedPath,
            aesKeyPath
        )){
        return false;
    }

    if (!encryptAESKey(
            aesKeyPath,
            receiverPubKey,
            encryptedKeyPath
        )){
        return false;
    }

    cout << "\n[OK] Message package created\n";

    cout << "[INFO] Encrypted file  -> "
         << encryptedPath << endl;

    cout << "[INFO] Encrypted AES key -> "
         << encryptedKeyPath << endl;

    string senderPubKey =
        user1 + "/" + senderName + "_public.pem";

    filesystem::create_directories("inbox");

    cout << "[FORWARDED] Message forwarded ( " << user1 << " -> " << user2 << " )\n";

    try
    {
        filesystem::copy_file(
            user1 + "/" + senderName + ".cert",
            certPath,
            filesystem::copy_options::overwrite_existing
        );

        std::cout << "File copied\n";
    }
    catch (const filesystem::filesystem_error& e)
    {
        std::cerr << e.what() << '\n';
    }
    try
    {
        filesystem::copy_file(
            encryptedPath,
            user2 + "/inbox/message.bin",
            filesystem::copy_options::overwrite_existing
        );

        std::cout << "File copied\n";
    }
    catch (const filesystem::filesystem_error& e)
    {
        std::cerr << e.what() << '\n';
    }
    try
    {
        filesystem::copy_file(
            encryptedKeyPath,
            user2 + "/inbox/" + senderName + "_to_" + receiverName + ".key.enc",
            filesystem::copy_options::overwrite_existing
        );

        std::cout << "File copied\n";
    }
    catch (const filesystem::filesystem_error& e)
    {
        std::cerr << e.what() << '\n';
    }
        try
    {
        filesystem::copy_file(
            user1 + "/signature.sig",
            user2 + "/inbox/signature.sig",
            filesystem::copy_options::overwrite_existing
        );

        std::cout << "Signature sent\n";
    }
    catch (const filesystem::filesystem_error& e)
    {
        std::cerr << e.what() << '\n';
    }

            try
    {
        filesystem::copy_file(
            senderPubKey,
            user2 + "/inbox/" + senderName + "_public.pem",
            filesystem::copy_options::overwrite_existing
        );

        std::cout << "Signature sent\n";
    }
    catch (const filesystem::filesystem_error& e)
    {
        std::cerr << e.what() << '\n';
    }
        
    cout << "[INFO] Sender Cert -> "
         << certPath << endl;

    return true;
}

bool CryptoManager::verifyCertificate(
    const std::string& userPublicKeyPath,
    const std::string& certPath,
    const std::string& caPublicKeyPath
){
    cout << "\n[CA VERIFY] Verifying certificate...\n";

    vector<unsigned char> userPubKey =
        readFile(userPublicKeyPath);

    if (userPubKey.empty()){
        cerr << "[ERROR] User public key missing\n";
        return false;
    }

    vector<unsigned char> certSignature =
        readFile(certPath);

    if (certSignature.empty()){
        cerr << "[ERROR] Certificate missing\n";
        return false;
    }
    FILE* fp = fopen(caPublicKeyPath.c_str(), "rb");

    if (!fp){
        cerr << "[ERROR] Cannot open CA public key\n";
        return false;
    }

    EVP_PKEY* caPublicKey =
        PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);

    fclose(fp);

    if (!caPublicKey){
        cerr << "[ERROR] Cannot load CA public key\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx){
        cerr << "[ERROR] EVP_MD_CTX_new failed\n";
        EVP_PKEY_free(caPublicKey);
        return false;
    }

    bool valid = false;

    if (EVP_DigestVerifyInit(
            ctx,
            nullptr,
            EVP_sha256(),
            nullptr,
            caPublicKey
        ) != 1)
    {
        cerr << "[ERROR] DigestVerifyInit failed\n";
        ERR_print_errors_fp(stderr);
    }

    else if (EVP_DigestVerifyUpdate(
                ctx,
                userPubKey.data(),
                userPubKey.size()
            ) != 1)
    {
        cerr << "[ERROR] DigestVerifyUpdate failed\n";
        ERR_print_errors_fp(stderr);
    }

    else
    {
        int result = EVP_DigestVerifyFinal(
            ctx,
            certSignature.data(),
            certSignature.size()
        );

        if (result == 1)
        {
            valid = true;
        }
        else if (result == 0)
        {
            cerr << "[ERROR] INVALID CERTIFICATE\n";
        }
        else
        {
            cerr << "[ERROR] Certificate verification failed\n";
            ERR_print_errors_fp(stderr);
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(caPublicKey);

    if (valid){
        cout << "[OK] Certificate is VALID\n";
    }

    return valid;
}

bool CryptoManager::receiveMessage(
    const std::string& receiverName
){
    cout << "\n========== RECEIVER ==========\n";

    string senderName = user1;

    string encryptedPath =
        user2 + "/inbox/message.bin";

    string encryptedKeyPath =
        user2 + "/inbox/" + senderName +
        "_to_" + receiverName + ".key.enc";

    string signaturePath =
        user2 + "/inbox/signature.sig";

    string senderPubKey =
        user1 + "/" + senderName + "_public.pem";

    string receiverPrivKey =
        user2 + "/" + receiverName + "_private.pem";

    string decryptedAES =
        user2 + "/inbox/decrypted_aes.key";

    string outputPath =
        user2 + "/inbox/message.txt";


    if (!decryptAESKey(
            encryptedKeyPath,
            receiverPrivKey,
            decryptedAES
        )){
        return false;
    }

    if (!decryptFileAES(
            encryptedPath,
            decryptedAES,
            outputPath
        )){
        return false;
    }

    cout << "\n[OK] Message decrypted successfully\n";

    cout << "[INFO] Output -> "
         << outputPath << endl;


    bool valid = verifyFile(
        outputPath,
        senderPubKey,
        signaturePath
    );

    if (!valid){
        cout << "[ERROR] INVALID SIGNATURE\n";
        return false;
    }
    cout << "[OK] Signature valid\n";

    bool valid2 = verifyCertificate(
    user2 + "/inbox/" + user1 + "_public.pem",
    user2 + "/inbox/" + user1 + ".cert",
    "ca/certs/ca_public.pem"
    );
    if (!valid2){
        cout << "[ERROR] INVALID SENDER CERT\n";
        return false;
    }
    cout << "[OK] Sender cert valid\n";
    return true;
}

bool CryptoManager::decryptAESKey(
    const std::string& encryptedKeyPath,
    const std::string& receiverPrivateKeyPath,
    const std::string& outputKeyPath
){
    cout << "\n[HYBRID] Decrypting AES key...\n";

    vector<unsigned char> encryptedKey =
        readFile(encryptedKeyPath);

    if (encryptedKey.empty()){
        cerr << "[ERROR] Encrypted key file is empty\n";
        return false;
    }

    FILE* fp = fopen(receiverPrivateKeyPath.c_str(), "rb");

    if (!fp){
        cerr << "[ERROR] Cannot open private key\n";
        return false;
    }

    EVP_PKEY* privKey =
        PEM_read_PrivateKey(
            fp,
            nullptr,
            nullptr,
            nullptr
        );

    fclose(fp);

    if (!privKey){
        cerr << "[ERROR] Failed to load private key\n";
        return false;
    }

    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new(privKey, nullptr);

    if (!ctx){
        cerr << "[ERROR] EVP_PKEY_CTX_new failed\n";

        EVP_PKEY_free(privKey);
        return false;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0){
        cerr << "[ERROR] decrypt_init failed\n";

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);

        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(
            ctx,
            RSA_PKCS1_OAEP_PADDING
        ) <= 0){

        cerr << "[ERROR] padding setup failed\n";

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);

        return false;
    }

    size_t outLen = 0;

    if (EVP_PKEY_decrypt(
            ctx,
            nullptr,
            &outLen,
            encryptedKey.data(),
            encryptedKey.size()
        ) <= 0){

        cerr << "[ERROR] decrypt size failed\n";

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);

        return false;
    }

    vector<unsigned char> aesKey(outLen);

    if (EVP_PKEY_decrypt(
            ctx,
            aesKey.data(),
            &outLen,
            encryptedKey.data(),
            encryptedKey.size()
        ) <= 0){

        cerr << "[ERROR] AES key decryption failed\n";

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);

        return false;
    }

    aesKey.resize(outLen);

    if (!writeFile(outputKeyPath, aesKey)){
        cerr << "[ERROR] Cannot write AES key\n";

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);

        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privKey);

    cout << "[OK] AES key decrypted -> "
         << outputKeyPath << endl;

    return true;
}

bool CryptoManager::encryptAESKey(
    const std::string& aesKeyPath,
    const std::string& receiverPublicKeyPath,
    const std::string& encryptedKeyPath
){
    cout << "\n[HYBRID] Encrypting AES key...\n";

    vector<unsigned char> aesKey = readFile(aesKeyPath);

    if (aesKey.empty()){
        cerr << "[ERROR] AES key is empty or missing\n";
        return false;
    }

    FILE* fp = fopen(receiverPublicKeyPath.c_str(), "rb");
    if (!fp){
        cerr << "[ERROR] Cannot open receiver public key\n";
        return false;
    }

    EVP_PKEY* pubKey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!pubKey){
        cerr << "[ERROR] Failed to load receiver public key\n";
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubKey, nullptr);
    if (!ctx){
        cerr << "[ERROR] EVP_PKEY_CTX_new failed\n";
        EVP_PKEY_free(pubKey);
        return false;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0){
        cerr << "[ERROR] encrypt_init failed\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0){
        cerr << "[ERROR] OAEP padding setup failed\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return false;
    }

    size_t outLen = 0;

    if (EVP_PKEY_encrypt(
            ctx,
            nullptr,
            &outLen,
            aesKey.data(),
            aesKey.size()
        ) <= 0)
    {
        cerr << "[ERROR] Failed to calculate encrypted size\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return false;
    }

    vector<unsigned char> encryptedKey(outLen);

    if (EVP_PKEY_encrypt(
            ctx,
            encryptedKey.data(),
            &outLen,
            aesKey.data(),
            aesKey.size()
        ) <= 0)
    {
        cerr << "[ERROR] AES key encryption failed\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return false;
    }

    encryptedKey.resize(outLen);

    if (!writeFile(encryptedKeyPath, encryptedKey)){
        cerr << "[ERROR] Cannot write encrypted AES key\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return false;
    }

    cout << "[OK] AES key encrypted -> " << encryptedKeyPath << "\n";

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubKey);

    return true;
}

bool CryptoManager::verifyFile(
    const std::string& filePath,
    const std::string& publicKeyPath,
    const std::string& signaturePath
){
    cout << "\n[VERIFY] Verifying digital signature...\n";

    vector<unsigned char> fileData = readFile(filePath);

    if (fileData.empty()){
        cerr << "[ERROR] File is empty or missing\n";
        return false;
    }

    vector<unsigned char> signature = readFile(signaturePath);

    if (signature.empty()){
        cerr << "[ERROR] Signature file is empty or missing\n";
        return false;
    }

    FILE* fp = fopen(publicKeyPath.c_str(), "rb");

    if (!fp){
        cerr << "[ERROR] Cannot open public key file\n";
        return false;
    }

    EVP_PKEY* publicKey =
        PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);

    fclose(fp);

    if (!publicKey){
        cerr << "[ERROR] Cannot load public key\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx){
        cerr << "[ERROR] Cannot create EVP_MD_CTX\n";
        EVP_PKEY_free(publicKey);
        return false;
    }

    bool valid = false;

    if (EVP_DigestVerifyInit(
            ctx,
            nullptr,
            EVP_sha256(),
            nullptr,
            publicKey
        ) != 1)
    {
        cerr << "[ERROR] EVP_DigestVerifyInit failed\n";
        ERR_print_errors_fp(stderr);
    }

    else if (EVP_DigestVerifyUpdate(
                ctx,
                fileData.data(),
                fileData.size()
            ) != 1)
    {
        cerr << "[ERROR] EVP_DigestVerifyUpdate failed\n";
        ERR_print_errors_fp(stderr);
    }

    else
    {
        int result = EVP_DigestVerifyFinal(
            ctx,
            signature.data(),
            signature.size()
        );

        if (result == 1)
        {
            valid = true;
        }
        else if (result == 0)
        {
            valid = false;
            cerr << "[ERROR] INVALID SIGNATURE\n";
        }
        else
        {
            cerr << "[ERROR] Verification process failed\n";
            ERR_print_errors_fp(stderr);
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(publicKey);

    if (valid){
        cout << "[OK] Signature is VALID\n";
    }

    return valid;
}

bool CryptoManager::generateCAKeyPair(){

    cout << "\n========== CA ==========\n";
    cout << "[CA] Generating CA RSA-4096 key pair...\n";

    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (!ctx){
        cerr << "[ERROR] CTX creation failed\n";
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0){
        cerr << "[ERROR] keygen_init failed\n";

        ERR_print_errors_fp(stderr);

        EVP_PKEY_CTX_free(ctx);

        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0){
        cerr << "[ERROR] keygen_bits failed\n";

        ERR_print_errors_fp(stderr);

        EVP_PKEY_CTX_free(ctx);

        return false;
    }

    EVP_PKEY* pkey = nullptr;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0){
        cerr << "[ERROR] key generation failed\n";

        ERR_print_errors_fp(stderr);

        EVP_PKEY_CTX_free(ctx);

        return false;
    }

    filesystem::create_directories("ca");
    filesystem::create_directories("ca/private");
    filesystem::create_directories("ca/certs");

    FILE* private_file =
        fopen("ca/private/ca_private.pem", "wb");

    if (!private_file){
        cerr << "[ERROR] Opening CA private key failed\n";

        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);

        return false;
    }

    PEM_write_PrivateKey(
        private_file,
        pkey,
        nullptr,
        nullptr,
        0,
        nullptr,
        nullptr
    );

    fclose(private_file);

    FILE* public_file =
        fopen("ca/certs/ca_public.pem", "wb");

    if (!public_file){
        cerr << "[ERROR] Opening CA public key failed\n";

        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);

        return false;
    }

    PEM_write_PUBKEY(public_file, pkey);

    fclose(public_file);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    cout << "\n[OK] CA keys generated successfully\n";

    cout << "[INFO] Private key -> "
         << "ca/private/ca_private.pem\n";

    cout << "[INFO] Public key  -> "
         << "ca/certs/ca_public.pem\n";

    return true;
}

vector<unsigned char> CryptoManager::readFile(const string& path){
    ifstream file(path, ios::binary);
    if (!file) return {};

    return vector<unsigned char>(
        (istreambuf_iterator<char>(file)),
        istreambuf_iterator<char>()
    );
}

bool CryptoManager::writeFile(const string& path, const vector<unsigned char>& data){
    ofstream file(path, ios::binary);
    if (!file) return false;

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}
