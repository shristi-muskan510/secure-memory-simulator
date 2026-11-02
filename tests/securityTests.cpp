
#include "crypto.hpp"

#include <iostream>
#include <string>

int main() {
    int failures = 0;

    // Test 1: Valid encryption and decryption
    std::cout << "Test 1: Round-trip encryption... ";

    crypto::Key key = crypto::generateKey();
    std::string original = "Balance = 500";

    auto block = crypto::encrypt(original, key);
    std::string recovered;

    if (crypto::decrypt(block, key, recovered) &&
        recovered == original) {
        std::cout << "PASS\n";
    } else {
        std::cout << "FAIL\n";
        failures++;
    }

    // Test 2: Modified ciphertext must be rejected
    std::cout << "Test 2: Ciphertext tampering... ";

    auto modifiedCiphertext = block;

    if (!modifiedCiphertext.ciphertext.empty()) {
        modifiedCiphertext.ciphertext[0] ^= 1;
    }

    recovered.clear();

    if (!modifiedCiphertext.ciphertext.empty() &&
        !crypto::decrypt(modifiedCiphertext, key, recovered)) {
        std::cout << "PASS\n";
    } else {
        std::cout << "FAIL\n";
        failures++;
    }

    // Test 3: Modified authentication tag must be rejected
    std::cout << "Test 3: Tag tampering... ";

    auto modifiedTag = block;
    modifiedTag.tag[0] ^= 1;

    recovered.clear();

    if (!crypto::decrypt(modifiedTag, key, recovered)) {
        std::cout << "PASS\n";
    } else {
        std::cout << "FAIL\n";
        failures++;
    }

    // Test 4: Wrong key must be rejected
    std::cout << "Test 4: Wrong key... ";

    crypto::Key wrongKey = crypto::generateKey();
    recovered.clear();

    if (!crypto::decrypt(block, wrongKey, recovered)) {
        std::cout << "PASS\n";
    } else {
        std::cout << "FAIL\n";
        failures++;
    }

    // Final summary
    std::cout << "\n";
    if (failures == 0) {
        std::cout << "All tests passed!\n";
        return 0;
    }

    std::cout << failures << " test(s) failed.\n";
    return 1;
}
