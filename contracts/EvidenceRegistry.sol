// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title EvidenceRegistry
/// @notice Anchors opaque batch identifiers to Merkle roots on the current chain.
/// @dev This contract does not validate the evidence, signatures, or Merkle proofs.
contract EvidenceRegistry {
    error ZeroBatchId();
    error ZeroMerkleRoot();
    error BatchAlreadyAnchored(bytes32 batchId);
    error BatchNotFound(bytes32 batchId);

    struct BatchAnchor {
        bytes32 merkleRoot;
        uint256 anchoredAt;
        bool exists;
    }

    mapping(bytes32 batchId => BatchAnchor anchor) private _anchors;

    event EvidenceBatchAnchored(
        bytes32 indexed batchId,
        bytes32 indexed merkleRoot,
        uint256 anchoredAt,
        address indexed submitter
    );

    function anchorRoot(bytes32 batchId, bytes32 merkleRoot) external {
        if (batchId == bytes32(0)) revert ZeroBatchId();
        if (merkleRoot == bytes32(0)) revert ZeroMerkleRoot();
        if (_anchors[batchId].exists) revert BatchAlreadyAnchored(batchId);

        uint256 timestamp = block.timestamp;
        _anchors[batchId] = BatchAnchor({merkleRoot: merkleRoot, anchoredAt: timestamp, exists: true});
        emit EvidenceBatchAnchored(batchId, merkleRoot, timestamp, msg.sender);
    }

    function getBatch(bytes32 batchId) external view returns (bytes32 merkleRoot, uint256 anchoredAt) {
        BatchAnchor storage anchor = _anchors[batchId];
        if (!anchor.exists) revert BatchNotFound(batchId);
        return (anchor.merkleRoot, anchor.anchoredAt);
    }

    function getRoot(bytes32 batchId) external view returns (bytes32 merkleRoot) {
        BatchAnchor storage anchor = _anchors[batchId];
        if (!anchor.exists) revert BatchNotFound(batchId);
        return anchor.merkleRoot;
    }
}
