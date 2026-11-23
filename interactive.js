
const readline = require('readline');
const { RootCAServer } = require('./src/ca/ca-server');
const { MeshNetwork } = require('./src/network/mesh-network');
const { createDefaultLabMeshTopology } = require('./src/network/router');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function question(prompt) {
  return new Promise((resolve) => rl.question(prompt, resolve));
}

function isValidNode(nodeName, availableNodes) {
  if (!availableNodes.includes(nodeName)) {
    console.log(`Error: Node "${nodeName}" does not exist.`);
    return false;
  }
  return true;
}

async function main() {
  const ca = new RootCAServer();
  const router = createDefaultLabMeshTopology();

  const network = new MeshNetwork({
    caServer: ca,
    router,
    mtu: 128,
  });

  const availableNodes = router.getAllNodes();

  let running = true;

  while (running) {
    console.log('\nSelect an action:');
    console.log('  1. Show network topology and Root CA status');
    console.log('  2. Perform a 7-step TLS Handshake between two nodes');
    console.log('  3. Send an encrypted chat message (AES-256-GCM)');
    console.log('  4. Transfer a file through a secure channel (SHA-256)');
    console.log('  5. Send a broadcast message across the network');
    console.log('  6. View a node inbox (received and decrypted data)');
    console.log('  7. Revoke a node certificate through Root CA');
    console.log('  0. Exit');

    const choice = (await question('\nYour choice (0-7): ')).trim();

    switch (choice) {
      case '1': {
        console.log('\n' + router.renderTopology());
        console.log('Root CA Status:');
        console.log(`  Name: ${ca.caName}`);
        console.log(`  Issued certificates: ${ca.issuedCertificates.size}`);
        console.log(`  Revoked certificates (CRL): ${ca.revocationList.size}`);
        break;
      }

      case '2': {
        console.log(`\nAvailable nodes: ${availableNodes.join(', ')}`);

        const src = (await question('Client node (e.g. Node_A): ')).trim();
        const dst = (await question('Server node (e.g. Node_F): ')).trim();

        if (
          !isValidNode(src, availableNodes) ||
          !isValidNode(dst, availableNodes)
        ) {
          break;
        }

        if (src === dst) {
          console.log('Error: Source and destination must be different.');
          break;
        }

        try {
          await network.performFullTlsHandshake(src, dst);
        } catch (err) {
          console.log(`Handshake error: ${err.message}`);
        }
        break;
      }

      case '3': {
        console.log(`\nAvailable nodes: ${availableNodes.join(', ')}`);

        const src = (await question('Sender (node with an active channel): ')).trim();
        const dst = (await question('Receiver: ')).trim();

        if (
          !isValidNode(src, availableNodes) ||
          !isValidNode(dst, availableNodes)
        ) {
          break;
        }

        if (src === dst) {
          console.log('Error: Sender and receiver must be different.');
          break;
        }

        const message = await question('Enter message text: ');

        try {
          await network.sendSecureChatMessage(src, dst, message);
          console.log('Message encrypted and delivered successfully.');
        } catch (err) {
          console.log(`Error: ${err.message}`);
        }
        break;
      }

      case '4': {
        console.log(`\nAvailable nodes: ${availableNodes.join(', ')}`);

        const src = (await question('Sender (node with an active channel): ')).trim();
        const dst = (await question('Receiver: ')).trim();

        if (
          !isValidNode(src, availableNodes) ||
          !isValidNode(dst, availableNodes)
        ) {
          break;
        }

        if (src === dst) {
          console.log('Error: Sender and receiver must be different.');
          break;
        }

        const filename = (await question('File name (e.g. document.txt): ')).trim();
        const content = await question('File content: ');

        try {
          await network.sendSecureFile(src, dst, filename, content);
          console.log('File encrypted, fragmented into radio frames, and delivered.');
        } catch (err) {
          console.log(`Error: ${err.message}`);
        }
        break;
      }

      case '5': {
        console.log(`\nAvailable nodes: ${availableNodes.join(', ')}`);

        const origin = (await question('Broadcast source node (e.g. Node_C): ')).trim();

        if (!isValidNode(origin, availableNodes)) {
          break;
        }

        const message = await question('Enter broadcast message: ');

        try {
          const result = await network.broadcast(origin, message);

          console.log('\nBroadcast completed.');
          console.log(`Source: ${origin}`);
          console.log(`Received by: ${result.receivedBy.join(', ')}`);
          console.log(`Total recipients: ${result.receivedBy.length}`);
        } catch (err) {
          console.log(`Error: ${err.message}`);
        }
        break;
      }

      case '6': {
        console.log(`\nAvailable nodes: ${availableNodes.join(', ')}`);

        const nodeName = (await question('Select a node to view its inbox: ')).trim();

        if (!isValidNode(nodeName, availableNodes)) {
          break;
        }

        try {
          const target = network.getNode(nodeName);

          console.log(`\nInbox [${nodeName}] (${target.inbox.length} items):`);

          if (target.inbox.length === 0) {
            console.log('Inbox is empty.');
          }

          target.inbox.forEach((item, index) => {
            console.log(`\n[${index + 1}] From ${item.from} (${item.type}):`);

            if (item.type === 'CHAT_MESSAGE') {
              console.log(`  Message: "${item.payload.text}"`);
            } else if (item.type === 'FILE_TRANSFER') {
              console.log(`  File: ${item.payload.filename}`);
              console.log(`  Size: ${item.payload.sizeBytes} bytes`);
              console.log(`  SHA-256: ${item.payload.sha256}`);
            }
          });
        } catch (err) {
          console.log(`Error: ${err.message}`);
        }
        break;
      }

      case '7': {
        console.log(`\nAvailable nodes: ${availableNodes.join(', ')}`);

        const nodeName = (await question('Select a node whose certificate should be revoked: ')).trim();

        if (!isValidNode(nodeName, availableNodes)) {
          break;
        }

        try {
          const target = network.getNode(nodeName);

          ca.revokeCertificate(
            target.serialNumber,
            'Manual revocation through CLI'
          );

          console.log(`Certificate for ${nodeName} has been revoked.`);
          console.log(`Serial number: ${target.serialNumber}`);
        } catch (err) {
          console.log(`Error: ${err.message}`);
        }
        break;
      }

      case '0':
        running = false;
        console.log('Application terminated.');
        break;

      default:
        console.log('Invalid selection. Please choose a number from 0 to 7.');
    }
  }

  rl.close();
}

if (require.main === module) {
  main().catch((err) => {
    console.error('error:', err);
    rl.close();
  });
}

module.exports = { main };
