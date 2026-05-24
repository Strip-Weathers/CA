#include "crypto_manager.hpp"
#include <iostream>
#include <string>
#include <filesystem>
using namespace std;
std::string user_1, user_2;
void waitStep() {
    cout << "\n>>> next <<<";
    string cmd;
    cin >> cmd;
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        cout << "Usage: exe demo\n";
        return 1;
    }

    string mode = argv[1];
    if (mode == "demo") {

        waitStep();

        cout << "\n[1] CA and TSA KEYGEN\n";
        CryptoManager::generateCAKeyPair();
        CryptoManager::generateTSAKeyPair();
        waitStep();

        cout << "\n PODAJ IMIE SENDERA\n";
        cin >> user_1;
        cout << "\n PODAJ IMIE RECEIVERA\n";
        cin >> user_2;
        CryptoManager::load_users(user_1, user_2);
        cout << "\n[2] USER KEYGEN\n";
        filesystem::create_directories(user_1);
        filesystem::create_directories(user_2);
        filesystem::create_directories("ca");
        filesystem::create_directories("build");
        filesystem::create_directories(user_2 + "/inbox");

        CryptoManager::generateRSAKeyPair(
            user_1 + "/" + user_1 + "_private.pem",
            user_1 + "/" + user_1 + "_public.pem"
        );
        CryptoManager::generateRSAKeyPair(
            user_2 + "/" + user_2 + "_private.pem",
            user_2 + "/" + user_2 + "_public.pem"
        );
        waitStep();


        cout << "\n[3] CA SIGN CERT (REQUEST)\n";
        int git = 1;
        auto requestCert = [&](const std::string& user){

            cout << "\n========== CA REQUEST ==========\n";
            cout << "[CA] Incoming certificate request from: " << user << "\n";
            cout << "[CA] Public key: " << user << "_public.pem\n";

            cout << "[CA] Approve certificate for " << user << "? (y/n): ";

            std::string decision;
            cin >> decision;

            if (decision != "y"){
                cout << "[CA] Request REJECTED for " << user << "\n";
                git = 0;
                return;
            }

            cout << "[CA] Signing certificate for " << user << "...\n";

            bool ok = CryptoManager::signPublicKey(
                user + "/" + user + "_public.pem",
                user + "/" + user + ".cert"
            );

            if (!ok){
                cout << "[CA] Signing FAILED for " << user << "\n";
                return;
            }

            cout << "[CA] Certificate ISSUED for " << user << "\n";
        };
        requestCert(user_1);
        if (!git) {
            std::filesystem::remove_all(user_1);
            std::filesystem::remove_all(user_2);
            std::filesystem::remove_all("inbox");
            std::filesystem::remove_all("data");
            std::filesystem::remove_all("tsa");
            std::filesystem::remove_all("ca");
            return 1;}
        requestCert(user_2);
        if (!git) {
            std::filesystem::remove_all(user_1);
            std::filesystem::remove_all(user_2);
            std::filesystem::remove_all("inbox");
            std::filesystem::remove_all("data");
            std::filesystem::remove_all("tsa");
            std::filesystem::remove_all("ca");
            return 1;}
        waitStep();

        cout << "\n[4] SIGN FILE\n";
        CryptoManager::signFile(
            user_1 + "/" + "message.txt",
            user_1 + "/" + user_1 + "_private.pem",
            user_1 + "/" + "signature.sig"
        );
        waitStep();
        cout << "\n[5] GEN TIMESTAMP\n";
        cout << "Request timestamp creation...\n";
        cout << "[TSA] Creating timestamp...\n";
        cout << "Timestamp received...\n";
        CryptoManager::createTimestamp(
            user_1 + "/message.txt",
            "tsa/private.pem",
            user_1 + "/timestamp.bin"
          );
        waitStep();

        cout << "\n[6] SEND MESSAGE\n";
        CryptoManager::sendMessage(
            user_1,
            user_2,
            user_1 + "/" + "message.txt"
        );
        waitStep();

        cout << "\n[7] RECEIVE MESSAGE\n";
        CryptoManager::receiveMessage(user_2);

        cout << "\n========== END DEMO ==========\n";
        waitStep();
        std::filesystem::remove_all(user_1);
        std::filesystem::remove_all(user_2);
        std::filesystem::remove_all("inbox");
        std::filesystem::remove_all("data");
        std::filesystem::remove_all("tsa");
        std::filesystem::remove_all("ca");
        return 0;
    }
    if (mode == "tsa"){
            cout << "\n=== TSA DEMO ===\n";

            string file = "message.txt";

            cout << "[1] Creating timestamp...\n";
            CryptoManager::createTimestamp(
                file,
                "tsa/private.pem",
                "timestamp.bin"
            );

            cout << "[2] Verifying timestamp...\n";
            bool ok = CryptoManager::verifyTimestamp(
                file,
                "timestamp.bin",
                "tsa/public.pem"
            );

            cout << (ok ? "[OK] VALID\n" : "[FAIL]\n");

            return 0;
    }

    if (mode == "tsa_init") {
    CryptoManager::generateTSAKeyPair();
    return 0;
    }

    if (mode == "verify") {
        string file = "message.txt";
        bool ok = CryptoManager::verifyTimestamp(
            file,
            "timestamp.bin",
            "tsa/public.pem"
        );
        cout << (ok ? "[OK] VALID\n" : "[FAIL]\n");

        return 0;
    }

    cout << "Unknown mode\n";
    return 1;
}