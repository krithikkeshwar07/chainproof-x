const { expect } = require('chai');
const { anyValue } = require('@nomicfoundation/hardhat-chai-matchers/withArgs');
const { ethers } = require('hardhat');

describe('EvidenceRegistry', function () {
  async function deploy() {
    const [owner] = await ethers.getSigners();
    const factory = await ethers.getContractFactory('EvidenceRegistry');
    const registry = await factory.deploy();
    await registry.waitForDeployment();
    return { registry, owner };
  }

  it('anchors a Merkle root once, records the block timestamp, and emits the anchor event', async function () {
    const { registry, owner } = await deploy();
    const batchId = ethers.id('synthetic-batch-001');
    const root = ethers.keccak256(ethers.toUtf8Bytes('synthetic-merkle-root'));
    const transaction = await registry.anchorRoot(batchId, root);
    const receipt = await transaction.wait();
    const block = await ethers.provider.getBlock(receipt.blockNumber);

    await expect(transaction)
      .to.emit(registry, 'EvidenceBatchAnchored')
      .withArgs(batchId, root, anyValue, owner.address);

    expect(await registry.getRoot(batchId)).to.equal(root);
    const anchor = await registry.getBatch(batchId);
    expect(anchor.merkleRoot).to.equal(root);
    expect(anchor.anchoredAt).to.equal(block.timestamp);
  });

  it('rejects an already anchored batch ID without changing its root', async function () {
    const { registry } = await deploy();
    const batchId = ethers.id('synthetic-batch-duplicate');
    const firstRoot = ethers.keccak256(ethers.toUtf8Bytes('root-one'));
    const secondRoot = ethers.keccak256(ethers.toUtf8Bytes('root-two'));
    await registry.anchorRoot(batchId, firstRoot);

    await expect(registry.anchorRoot(batchId, secondRoot))
      .to.be.revertedWithCustomError(registry, 'BatchAlreadyAnchored')
      .withArgs(batchId);
    expect(await registry.getRoot(batchId)).to.equal(firstRoot);
  });

  it('rejects zero batch IDs and zero roots', async function () {
    const { registry } = await deploy();
    const root = ethers.keccak256(ethers.toUtf8Bytes('synthetic-root'));
    const batchId = ethers.id('synthetic-batch-zero-root');

    await expect(registry.anchorRoot(ethers.ZeroHash, root)).to.be.revertedWithCustomError(registry, 'ZeroBatchId');
    await expect(registry.anchorRoot(batchId, ethers.ZeroHash)).to.be.revertedWithCustomError(registry, 'ZeroMerkleRoot');
  });

  it('fails clearly when retrieving an unknown batch', async function () {
    const { registry } = await deploy();
    const batchId = ethers.id('unknown-batch');
    await expect(registry.getRoot(batchId)).to.be.revertedWithCustomError(registry, 'BatchNotFound').withArgs(batchId);
    await expect(registry.getBatch(batchId)).to.be.revertedWithCustomError(registry, 'BatchNotFound').withArgs(batchId);
  });
});
