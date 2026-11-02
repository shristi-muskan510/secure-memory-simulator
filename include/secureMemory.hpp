
#ifndef SECURE_MEMORY_HPP
#define SECURE_MEMORY_HPP

#include "crypto.hpp"
#include "merkle.hpp"

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

class SecureMemory {
public:
    explicit SecureMemory(const std::vector<std::string>& initialBlocks);

    bool writeBlock(std::size_t index, const std::string& plaintext);

    bool readBlock(std::size_t index, std::string& plaintext) const;

    std::size_t size() const;

    // Demonstration only: simulate an attacker modifying stored memory.
    bool tamperCiphertextForTesting(std::size_t index);

private:
    crypto::Key key;
    std::vector<crypto::EncryptedBlock> blocks;

    // In this prototype, the tree and expected root are trusted state.
    std::unique_ptr<Merkle::MerkleTree> integrityTree;
    Merkle::Hash trustedRoot{};

    std::string serializeBlock(
        std::size_t index,
        const crypto::EncryptedBlock& block
    ) const;

    void rebuildIntegrityTree();
};

#endif
