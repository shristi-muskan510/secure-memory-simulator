#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <memory>
#include <stdexcept>
#include <algorithm>

namespace crypto {

using Context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

Key generateKey() {
    Key key{};

    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        throw std::runtime_error("Key generation failed");
    }

    return key;
}

EncryptedBlock encrypt( const std::string& plaintext, const Key& key){
    EncryptedBlock result{};

    if (RAND_bytes(result.nonce.data(),
                   static_cast<int>(result.nonce.size())) != 1) {
        throw std::runtime_error("Nonce generation failed");
    }

    Context ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (!ctx) {
        throw std::runtime_error("Context allocation failed");
    }

    if (EVP_EncryptInit_ex(
            ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(result.nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(
            ctx.get(), nullptr, nullptr,
            key.data(), result.nonce.data()) != 1) {
        throw std::runtime_error("Encryption initialization failed");
    }

    result.ciphertext.resize(plaintext.size() + 16);
    int written = 0;
    int finalWritten = 0;

    if (EVP_EncryptUpdate(
            ctx.get(), result.ciphertext.data(), &written,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(
            ctx.get(), result.ciphertext.data() + written,
            &finalWritten) != 1 ||
        EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_GCM_GET_TAG,
            static_cast<int>(result.tag.size()),
            result.tag.data()) != 1) {
        throw std::runtime_error("Encryption failed");
    }

    result.ciphertext.resize(written + finalWritten);
    return result;
}

bool decrypt(const EncryptedBlock& block, const Key& key, std::string& plaintext) {
    // Never leave old or unauthenticated plaintext in the output.
    plaintext.clear();

    Context ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (!ctx) {
        return false;
    }

    if (EVP_DecryptInit_ex(
            ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(block.nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(
            ctx.get(), nullptr, nullptr,
            key.data(), block.nonce.data()) != 1) {
        return false;
    }

    std::vector<unsigned char> buffer(block.ciphertext.size() + 16);
    int written = 0;
    int finalWritten = 0;

    if (EVP_DecryptUpdate(
            ctx.get(), buffer.data(), &written,
            block.ciphertext.data(),
            static_cast<int>(block.ciphertext.size())) != 1) {
        return false;
    }

    auto tag = block.tag;

    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_GCM_SET_TAG,
            static_cast<int>(tag.size()), tag.data()) != 1) {
        return false;
    }

    // Authentication is checked here.
    if (EVP_DecryptFinal_ex(
            ctx.get(), buffer.data() + written, &finalWritten) != 1) {
        return false;
    }

    // Expose plaintext only after authentication succeeds.
    plaintext.assign(
        reinterpret_cast<const char*>(buffer.data()),
        static_cast<std::size_t>(written + finalWritten));

    return true;
}

} // namespace Crypto