#include "crypto_manager.hpp"
#include <iostream>
#include <string>

using namespace std;

void waitStep() {
    cout << "\n>>> wpisz 'next' aby kontynuować: ";
    string cmd;
    cin >> cmd;
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        cout << "Usage: exe demo|send|receive\n";
        return 1;
    }

    string mode = argv[1];

    // ================= DEMO FLOW =================
    if (mode == "demo") {

        cout << "\n========== PKI DEMO FLOW ==========\n";

        waitStep();

        // =================================================
        // 1. CA
        // =================================================
        cout << "\n[1] CA KEYGEN\n";
        CryptoManager::generateCAKeyPair();
        waitStep();

        // =================================================
        // 2. USER KEYS (SPÓJNE NAZWY)
        // =================================================
        cout << "\n[2] USER KEYGEN\n";
        CryptoManager::generateRSAKeyPair(
            "keys/alice_private.pem",
            "keys/alice_public.pem"
        );

        CryptoManager::generateRSAKeyPair(
            "keys/bob_private.pem",
            "keys/bob_public.pem"
        );
        waitStep();

        // =================================================
        // 3. CERT
        // =================================================
        cout << "\n[3] CA SIGN CERT\n";
        CryptoManager::signPublicKey(
            "keys/alice_public.pem",
            "keys/alice.cert"
        );
        CryptoManager::signPublicKey(
            "keys/bob_public.pem",
            "keys/bob.cert"
        );
        waitStep();

        // =================================================
        // 4. VERIFY CERT
        // =================================================
        cout << "\n[4] VERIFY CERT\n";
        CryptoManager::verifyCertificate(
            "keys/alice_public.pem",
            "keys/alice.cert",
            "ca/certs/ca_public.pem"
        );
        waitStep();

        // =================================================
        // 5. SIGN FILE
        // =================================================
        cout << "\n[5] SIGN FILE\n";
        CryptoManager::signFile(
            "message.txt",
            "keys/alice_private.pem",
            "signature.sig"
        );
        waitStep();

        // =================================================
        // 6. VERIFY FILE
        // =================================================
        cout << "\n[6] VERIFY FILE\n";
        CryptoManager::verifyFile(
            "message.txt",
            "keys/alice_public.pem",
            "signature.sig"
        );
        waitStep();

        // =================================================
        // 7. SEND MESSAGE (HYBRID)
        // =================================================
        cout << "\n[7] SEND MESSAGE\n";
        CryptoManager::sendMessage(
            "alice",
            "bob",
            "message.txt"
        );
        waitStep();

        // =================================================
        // 8. GATEWAY (opcjonalnie ale logiczne)
        // =================================================
        cout << "\n[8] GATEWAY CHECK\n";
        CryptoManager::gatewaySend("outbox/alice_to_bob.bin");
        waitStep();

        // =================================================
        // 9. RECEIVE MESSAGE
        // =================================================
        cout << "\n[9] RECEIVE MESSAGE\n";
        CryptoManager::receiveMessage("bob");

        cout << "\n========== END DEMO ==========\n";
        return 0;
    }

    // ================= SEND =================
    if (mode == "send") {

        if (argc < 3) {
            cout << "Usage: exe send <file>\n";
            return 1;
        }

        CryptoManager::sendMessage(
            "alice",
            "bob",
            argv[2]
        );

        return 0;
    }

    // ================= RECEIVE =================
    if (mode == "receive") {

        CryptoManager::receiveMessage("bob");
        return 0;
    }

    cout << "Unknown mode\n";
    return 1;
}