const fs = require('node:fs');
const path = require('node:path');
const { ethers } = require('hardhat');

async function main() {
  const outputPath = process.env.CHAINPROOF_DEPLOYMENT_FILE
    || path.resolve(__dirname, '..', 'data', 'hardhat-deployment.json');
  if (fs.existsSync(outputPath)) {
    throw new Error(`Refusing to overwrite existing deployment metadata: ${outputPath}. Select a new CHAINPROOF_DEPLOYMENT_FILE for a fresh local chain.`);
  }

  const [deployer] = await ethers.getSigners();
  const factory = await ethers.getContractFactory('EvidenceRegistry');
  const registry = await factory.deploy();
  const transaction = registry.deploymentTransaction();
  const receipt = await transaction.wait();
  const network = await ethers.provider.getNetwork();
  const contractAddress = await registry.getAddress();
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify({
    chain_id: Number(network.chainId),
    contract_address: contractAddress,
    deployment_tx_hash: receipt.hash,
    deployment_block_number: receipt.blockNumber,
    deployer_address: deployer.address,
  }, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  process.stdout.write(`${JSON.stringify({ ...JSON.parse(fs.readFileSync(outputPath, 'utf8')), deployment_file: outputPath })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : 'Contract deployment failed'}\n`);
  process.exitCode = 1;
});
