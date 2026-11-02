
#include "secureMemory.hpp"

#include <iostream>
#include <string>
#include <vector>

using namespace std;

int main() {
    try {
        vector<string> initialBlocks = {
            "Block 0: Alice",
            "Block 1: Balance 500",
            "Block 2: Transaction 42"
        };

        SecureMemory memory(initialBlocks);

        cout << "=== Secure Memory Simulator ===\n\n";

        // Test 1: Read an intact block.
        string plaintext;

        if (memory.readBlock(1, plaintext)) {
            cout << "[PASS] Initial read: "
                      << plaintext << '\n';
        } else {
            cout << "[FAIL] Initial read rejected\n";
            return 1;
        }

        // Test 2: Perform a legitimate write.
        if (!memory.writeBlock(1, "Block 1: Balance 900")) {
            cout << "[FAIL] Write operation failed\n";
            return 1;
        }

        cout << "[PASS] Legitimate write completed\n";

        if (memory.readBlock(1, plaintext)) {
            cout << "[PASS] Read after write: "
                      << plaintext << '\n';
        } else {
            cout << "[FAIL] Read after write rejected\n";
            return 1;
        }

        // Test 3: Simulate an attacker modifying stored ciphertext.
        if (!memory.tamperCiphertextForTesting(1)) {
            cout << "[FAIL] Could not simulate tampering\n";
            return 1;
        }

        cout << "\nSimulating an attacker modifying ciphertext...\n";

        const string previousOutput = plaintext;

        if (!memory.readBlock(1, plaintext)) {
            cout << "[PASS] Tampered block rejected\n";
        } else {
            cout << "[FAIL] Tampered block was accepted\n";
            return 1;
        }

        if (plaintext == previousOutput) {
            cout << "[PASS] Failed read exposed no new plaintext\n";
        } else {
            cout << "[FAIL] Output changed after rejected read\n";
            return 1;
        }

        // Test 4: Reject an invalid block index.
        if (!memory.readBlock(99, plaintext)) {
            cout << "[PASS] Invalid block index rejected\n";
        } else {
            cout << "[FAIL] Invalid index accepted\n";
            return 1;
        }

        cout << "\nAll secure-memory demo tests passed!\n";
        return 0;

    } catch (const std::exception& error) {
        cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }
}
