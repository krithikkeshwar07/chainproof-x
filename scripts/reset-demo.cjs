const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const dataRoot = path.join(root, 'data');
const demoRoot = path.join(dataRoot, 'demo');

function isApiRunning() {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: 8100 });
    let done = false;
    const finish = (running) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(running);
    };
    socket.setTimeout(700);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

async function main() {
  if (await isApiRunning()) {
    throw new Error('Stop the isolated demo stack before resetting it (port 8100 is in use).');
  }
  if (fs.existsSync(dataRoot) && fs.lstatSync(dataRoot).isSymbolicLink()) {
    throw new Error('Refusing to reset demo data because data/ is a symbolic link.');
  }
  if (fs.existsSync(demoRoot) && fs.lstatSync(demoRoot).isSymbolicLink()) {
    throw new Error('Refusing to reset demo data because data/demo is a symbolic link.');
  }
  fs.rmSync(demoRoot, { recursive: true, force: true });
  process.stdout.write('Isolated competition demo data reset. The normal workspace database and evidence directory were not touched.\n');
}

main().catch((error) => {
  process.stderr.write(`Demo reset failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
