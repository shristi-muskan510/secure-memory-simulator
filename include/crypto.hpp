#ifndef CRYPTO_H
#define CRYPTO_H

#include <array>
#include <vector>
#include <string>
#include <cstdint>

namespace crypto {

    constexpr std::size_t KEY_SIZE = 32;
    constexpr std::size_t NONCE_SIZE = 12;
    constexpr std::size_t TAG_SIZE = 16;

    using Key = std::array<unsigned char, KEY_SIZE>;

    struct EncryptedBlock {
        std::vector<unsigned char> ciphertext;
        std::array<unsigned char, NONCE_SIZE> nonce;
        std::array<unsigned char, TAG_SIZE> tag;
    };

    Key generateKey();

    EncryptedBlock encrypt(
        const std::string& plaintext,
        const Key& key
    );

    bool decrypt(
        const EncryptedBlock& block,
        const Key& key,
        std::string& plaintext
    );

} // namespace crypto

#endif