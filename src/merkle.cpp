
#include "merkle.hpp"

#include <openssl/evp.h>

#include <memory>
#include <stdexcept>

namespace Merkle {

using DigestContext =
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

Hash hashData(const std::string& data) {
    Hash result{};
    unsigned int length = 0;

    DigestContext ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!ctx) {
        throw std::runtime_error("Failed to create hash context");
    }

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), result.data(), &length) != 1 ||
        length != result.size()) {
        throw std::runtime_error("SHA-256 hashing failed");
    }

    return result;
}

Hash MerkleTree::hashPair(const Hash& left, const Hash& right) {
    std::string combined;
    combined.reserve(left.size() + right.size());

    combined.append(
        reinterpret_cast<const char*>(left.data()), left.size());
    combined.append(
        reinterpret_cast<const char*>(right.data()), right.size());

    return hashData(combined);
}

MerkleTree::MerkleTree(const std::vector<std::string>& leaves) {
    if (leaves.empty()) {
        throw std::invalid_argument("Merkle tree needs at least one leaf");
    }

    std::vector<Hash> leafHashes;
    leafHashes.reserve(leaves.size());

    for (const auto& leaf : leaves) {
        leafHashes.push_back(hashData(leaf));
    }

    levels.push_back(std::move(leafHashes));

    while (levels.back().size() > 1) {
        const auto& current = levels.back();
        std::vector<Hash> next;

        for (std::size_t i = 0; i < current.size(); i += 2) {
            const Hash& left = current[i];
            const Hash& right =
                (i + 1 < current.size()) ? current[i + 1] : current[i];

            next.push_back(hashPair(left, right));
        }

        levels.push_back(std::move(next));
    }
}

Hash MerkleTree::getRoot() const {
    return levels.back().front();
}

std::size_t MerkleTree::leafCount() const {
    return levels.front().size();
}

bool MerkleTree::verifyLeaf(
    std::size_t index,
    const std::string& data,
    const Hash& trustedRoot
) const {
    if (index >= leafCount()) {
        return false;
    }

    Hash currentHash = hashData(data);
    std::size_t position = index;

    for (std::size_t level = 0; level + 1 < levels.size(); ++level) {
        const auto& currentLevel = levels[level];

        if (position % 2 == 0) {
            const std::size_t sibling = position + 1;

            const Hash& right =
                (sibling < currentLevel.size())
                    ? currentLevel[sibling]
                    : currentHash;

            currentHash = hashPair(currentHash, right);
        } else {
            const Hash& left = currentLevel[position - 1];
            currentHash = hashPair(left, currentHash);
        }

        position /= 2;
    }

    return currentHash == trustedRoot;
}

} // namespace Merkle
