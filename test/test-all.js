
const assert = require('assert');
const { RootCAServer } = require('../src/ca/ca-server');
const { createDefaultLabMeshTopology } = require('../src/network/router');
const { RadioLink } = require('../src/network/radio-link');
const { MeshNetwork } = require('../src/network/mesh-network');
const { sha256 } = require('../src/crypto/tls-crypto');

async function runTests() {
  let passed = 0;
  let total = 0;

  function test(name, fn) {
    total++;
    try {
      fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`[FAIL] ${name}`);
      console.error(err);
    }
  }

  async function testAsync(name, fn) {
    total++;
    try {
      await fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`[FAIL] ${name}`);
      console.error(err);
    }
  }

  test('Root CA generates self-signed certificate and issues node certs', () => {
    const ca = new RootCAServer();
    const rootCert = ca.getRootCertificate();
    assert(rootCert.includes('-----BEGIN CERTIFICATE-----'), 'Root cert must be valid PEM');

    const nodeCert = ca.issueCertificate({
      subjectCN: 'Node_Test',
      subjectPublicKeyPem: ca.getRootPublicKey(),
    });
    assert(nodeCert.certificatePem.includes('-----BEGIN CERTIFICATE-----'));

    const verifyResult = ca.verifyCertificate(nodeCert.certificatePem, 'Node_Test');
    assert.strictEqual(verifyResult.valid, true);
    assert.strictEqual(verifyResult.status, 'VERIFIED');
  });

  test('Root CA detects revoked certificate in CRL', () => {
    const ca = new RootCAServer();
    const nodeCert = ca.issueCertificate({
      subjectCN: 'Node_Compromised',
      subjectPublicKeyPem: ca.getRootPublicKey(),
    });

    ca.revokeCertificate(nodeCert.serialNumber, 'Key compromised in radio attack');

    const verifyResult = ca.verifyCertificate(nodeCert.certificatePem, 'Node_Compromised');
    assert.strictEqual(verifyResult.valid, false);
    assert.strictEqual(verifyResult.status, 'REVOKED');
  });

  test('Radio Link fragments large payload and reassembles correctly', () => {
    const radio = new RadioLink({ mtu: 128 });
    const largeMessage = {
      greeting: 'Hello from slow radio channel!',
      filler: 'A'.repeat(500),
      timestamp: Date.now(),
    };

    const fragmentResult = radio.fragment(largeMessage);
    assert(fragmentResult.totalFrames > 5, 'Should split into multiple radio frames');

    let reassembled = null;
    for (const frame of fragmentResult.frames) {
      assert(frame.size <= 250, 'Frame should be reasonably sized for MTU');
      reassembled = radio.receiveFrame(frame);
    }

    assert(reassembled !== null, 'Message should be completely reassembled');
    assert.strictEqual(reassembled.filler, largeMessage.filler);
    assert.strictEqual(reassembled.greeting, largeMessage.greeting);
  });

  test('Mesh Router finds shortest path on non-fully connected topology', () => {
    const router = createDefaultLabMeshTopology();

    const route = router.findRoute('Node_A', 'Node_F');
    assert(route !== null, 'Route must exist');
    assert(route.path.length >= 3, 'Must have at least one intermediate hop');
    assert.strictEqual(route.path[0], 'Node_A');
    assert.strictEqual(route.path[route.path.length - 1], 'Node_F');
  });

  await testAsync('Full 7-step TLS Handshake across multi-hop radio mesh', async () => {
    const ca = new RootCAServer();
    const network = new MeshNetwork({
      caServer: ca,
      mtu: 128,
      onLog: () => {},
    });

    const result = await network.performFullTlsHandshake('Node_A', 'Node_F');
    assert.strictEqual(result.established, true);
    assert(result.masterSecretHex.length > 0);

    await network.sendSecureChatMessage('Node_A', 'Node_F', 'Hello Node F via multi-hop TLS!');
    const nodeF = network.getNode('Node_F');
    assert(nodeF.inbox.length >= 1);
    assert.strictEqual(nodeF.inbox[0].payload.text, 'Hello Node F via multi-hop TLS!');
  });

  await testAsync('Secure File Transfer with SHA-256 integrity check over TLS channel', async () => {
    const ca = new RootCAServer();
    const network = new MeshNetwork({
      caServer: ca,
      mtu: 128,
      onLog: () => {},
    });

    await network.performFullTlsHandshake('Node_B', 'Node_E');

    const fileContent = 'Secret configuration file content for Security Lab 8\n'.repeat(10);
    const expectedHash = sha256(fileContent);

    await network.sendSecureFile('Node_B', 'Node_E', 'secret_config.txt', fileContent);

    const nodeE = network.getNode('Node_E');
    const receivedFile = nodeE.inbox.find((item) => item.type === 'FILE_TRANSFER');
    assert(receivedFile, 'File must be in recipient inbox');
    assert.strictEqual(receivedFile.payload.filename, 'secret_config.txt');
    assert.strictEqual(receivedFile.payload.sha256, expectedHash);

    const reconstructedContent = Buffer.from(receivedFile.payload.dataBase64, 'base64').toString(
      'utf8'
    );
    assert.strictEqual(reconstructedContent, fileContent);
  });

  await testAsync('Topology-aware broadcast delivers to all nodes without loops', async () => {
    const ca = new RootCAServer();
    const network = new MeshNetwork({
      caServer: ca,
      mtu: 128,
      onLog: () => {},
    });

    const bcastResult = await network.broadcast('Node_C', 'Emergency Network Alert');
    assert.strictEqual(bcastResult.receivedBy.length, 6, 'All 6 nodes must receive the broadcast');
  });

  console.log(`${passed} / ${total} tests passed`);

  if (passed !== total) {
    process.exit(1);
  }
}
runTests();

