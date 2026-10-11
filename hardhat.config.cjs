require('@nomicfoundation/hardhat-toolbox');

module.exports = {
  solidity: '0.8.26',
  networks: {
    localhost: {
      url: process.env.CHAINPROOF_RPC_URL || 'http://127.0.0.1:8545',
      chainId: Number(process.env.CHAINPROOF_CHAIN_ID || '31337'),
    },
  },
  paths: {
    sources: './contracts',
    tests: './contract-test',
    cache: './cache',
    artifacts: './artifacts',
  },
};
