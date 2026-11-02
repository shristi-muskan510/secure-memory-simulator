
#include "merkle.hpp"

#include <iostream>
#include <string>
#include <vector>

int main() {
    int failures = 0;

    auto check = [&](bool condition, const std::string& name) {
        if (condition) {
            std::cout << name << ": PASS\n";
        } else {
            std::cout << name << ": FAIL\n";
            ++failures;
        }
    };

    const std::vector<std::string> blocks = {
        "Block zero: Alice",
        "Block one: Balance 500",
        "Block two: Transaction 42"
    };

    Merkle::MerkleTree tree(blocks);
    const Merkle::Hash trustedRoot = tree.getRoot();

    // Test 1: correct leaf and root
    check(
        tree.verifyLeaf(1, blocks[1], trustedRoot),
        "Valid leaf verification"
    );

    // Test 2: modified leaf data
    check(
        !tree.verifyLeaf(1, "Block one: Balance 900", trustedRoot),
        "Modified leaf rejected"
    );

    // Test 3: wrong trusted root
    Merkle::Hash wrongRoot = trustedRoot;
    wrongRoot[0] ^= 1;

    check(
        !tree.verifyLeaf(1, blocks[1], wrongRoot),
        "Incorrect root rejected"
    );

    // Test 4: invalid leaf index
    check(
        !tree.verifyLeaf(99, "Invalid block", trustedRoot),
        "Invalid index rejected"
    );

    // Test 5: changing a block changes the root
    auto changedBlocks = blocks;
    changedBlocks[1] = "Block one: Balance 900";

    Merkle::MerkleTree changedTree(changedBlocks);

    check(
        changedTree.getRoot() != trustedRoot,
        "Changed data produces a different root"
    );

    // Test 6: empty tree is rejected
    bool emptyRejected = false;

    try {
        Merkle::MerkleTree emptyTree({});
    } catch (const std::invalid_argument&) {
        emptyRejected = true;
    }

    check(emptyRejected, "Empty tree rejected");

    if (failures == 0) {
        std::cout << "\nAll Merkle tests passed!\n";
        return 0;
    }

    std::cout << "\n" << failures << " test(s) failed.\n";
    return 1;
}
