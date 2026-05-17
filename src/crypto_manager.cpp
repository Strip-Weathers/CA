#include "crypto_manager.hpp"
#include <iostream>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fstream>
#include <vector>
using namespace std;


bool CryptoManager::generateRSAKeyPair(){
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx){
        cerr << "CTX creation failed\n";
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0){
        cerr << "keygen_init failed\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0){
        cerr << "keygen_bits failed\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY* pkey = nullptr;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0){
        cerr << "keygen failed\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    cout << "Key generation OK\n";

    std::filesystem::create_directories("keys");

    FILE* private_file = fopen("keys/private.pem", "wb");
    if (!private_file){
        cerr << "Opening private.pem failed\n";
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    PEM_write_PrivateKey(private_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(private_file);

    FILE* public_file = fopen("keys/public.pem", "wb");
    if (!public_file){
        cerr << "Opening public.pem failed\n";
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    PEM_write_PUBKEY(public_file, pkey);
    fclose(public_file);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return true;
}

vector<unsigned char> readFile(const string& path){
    ifstream file(path, ios::binary);

    return vector<unsigned char>(istreambuf_iterator<char>(file),{});
}

bool writeFile(const string& path, const vector<unsigned char>& data){
    ofstream file(path, ios::binary);

    if (!file) return false;

    file.write(reinterpret_cast<const char*>(data.data()), data.size());

    return true;
}

bool CryptoManager::signFile(const string& filePath)
{
    FILE* fp = fopen("keys/private.pem", "rb");
    if (!fp) return false;

    EVP_PKEY* privateKey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);

    fclose(fp);

    vector<unsigned char> fileData = readFile(filePath);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privateKey);

    EVP_DigestSignUpdate(ctx, fileData.data(), fileData.size());

    size_t sigLen = 0;

    EVP_DigestSignFinal(ctx, nullptr, &sigLen);

    vector<unsigned char> signature(sigLen);

    EVP_DigestSignFinal(ctx, signature.data(), &sigLen);

    writeFile("signature.sig", signature);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(privateKey);

    return true;
}

bool CryptoManager::verifyFile(const string& filePath)
{
    FILE* fp = fopen("keys/public.pem", "rb");
    if (!fp) return false;

    EVP_PKEY* publicKey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    vector<unsigned char> fileData = readFile(filePath);
    vector<unsigned char> signature = readFile("signature.sig");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, publicKey);

    EVP_DigestVerifyUpdate(ctx, fileData.data(), fileData.size());

    int result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(publicKey);

    if(result == 1) return true;
    else return false;
}