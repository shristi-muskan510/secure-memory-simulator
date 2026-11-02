
#ifndef MERKLE_HPP
#define MERKLE_HPP

#include <array>
#include <cstddef>
#include <string>
#include <vector>

namespace Merkle {

using Hash = std::array<unsigned char, 32>;

Hash hashData(const std::string& data);

class MerkleTree {
public:
    explicit MerkleTree(const std::vector<std::string>& leaves);

    Hash getRoot() const;

    bool verifyLeaf(
        std::size_t index,
        const std::string& data,
        const Hash& trustedRoot
    ) const;

    std::size_t leafCount() const;

private:
    std::vector<std::vector<Hash>> levels;

    static Hash hashPair(const Hash& left, const Hash& right);
};

} // namespace Merkle

#endif
