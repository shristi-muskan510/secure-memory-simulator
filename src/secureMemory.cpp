#include "secureMemory.hpp"

#include <cstdint>
#include <stdexcept>
#include <utility>

SecureMemory::SecureMemory(const std::vector<std::string>& initialBlocks) : key(crypto::generateKey()) {
    if (initialBlocks.empty()) {
        throw std::invalid_argument(
            "SecureMemory requires at least one block"
        );
    }

    blocks.reserve(initialBlocks.size());

    for (const auto& plaintext : initialBlocks) {
        blocks.push_back(crypto::encrypt(plaintext, key));
    }

    rebuildIntegrityTree();
}

std::string SecureMemory::serializeBlock(
    std::size_t index,
    const crypto::EncryptedBlock& block
) const {
    std::string record;

    // Encode integers in a fixed byte order.
    auto appendUint64 = [&record](std::uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            record.push_back(
                static_cast<char>((value >> shift) & 0xFF)
            );
        }
    };

    // Bind the data to its position and length.
    appendUint64(static_cast<std::uint64_t>(index));
    appendUint64(
        static_cast<std::uint64_t>(block.ciphertext.size())
    );

    // Include all authentication metadata and ciphertext.
    record.append(
        reinterpret_cast<const char*>(block.nonce.data()),
        block.nonce.size()
    );

    record.append(
        reinterpret_cast<const char*>(block.tag.data()),
        block.tag.size()
    );

    if (!block.ciphertext.empty()) {
        record.append(
            reinterpret_cast<const char*>(block.ciphertext.data()),
            block.ciphertext.size()
        );
    }

    return record;
}

void SecureMemory::rebuildIntegrityTree() {
    std::vector<std::string> leaves;
    leaves.reserve(blocks.size());

    for (std::size_t i = 0; i < blocks.size(); ++i) {
        leaves.push_back(serializeBlock(i, blocks[i]));
    }

    integrityTree = std::make_unique<Merkle::MerkleTree>(leaves);
    trustedRoot = integrityTree->getRoot();
}

bool SecureMemory::writeBlock(
    std::size_t index,
    const std::string& plaintext
) {
    if (index >= blocks.size()) {
        return false;
    }

    // Encrypt the replacement block.
    crypto::EncryptedBlock replacement =
        crypto::encrypt(plaintext, key);

    blocks[index] = std::move(replacement);

    // A legitimate write changes the integrity tree and its root.
    rebuildIntegrityTree();

    return true;
}

bool SecureMemory::readBlock(
    std::size_t index,
    std::string& plaintext
) const {
    if (index >= blocks.size()) {
        return false;
    }

    // Step 1: verify the stored encrypted block against the tree.
    const std::string record = serializeBlock(index, blocks[index]);

    if (!integrityTree->verifyLeaf(
            index, record, trustedRoot)) {
        return false;
    }

    // Step 2: decrypt only after the integrity check succeeds.
    std::string recovered;

    if (!crypto::decrypt(blocks[index], key, recovered)) {
        return false;
    }

    // Do not modify the caller's output unless every check succeeds.
    plaintext = std::move(recovered);
    return true;
}

std::size_t SecureMemory::size() const {
    return blocks.size();
}

bool SecureMemory::tamperCiphertextForTesting(
    std::size_t index
) {
    if (index >= blocks.size() ||
        blocks[index].ciphertext.empty()) {
        return false;
    }

    // Simulates an attacker flipping one bit in stored memory.
    blocks[index].ciphertext[0] ^= 0x01;
    return true;
}
