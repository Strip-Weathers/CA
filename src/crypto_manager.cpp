#include "crypto_manager.hpp"
#include <iostream>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
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