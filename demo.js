
const { RootCAServer } = require('./src/ca/ca-server');
const { MeshNetwork } = require('./src/network/mesh-network');
const { createDefaultLabMeshTopology } = require('./src/network/router');

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function runFullDemonstration() {
  console.clear();

  console.log('\n[STAGE 1] ROOT CERTIFICATE AUTHORITY');
  console.log('Generating RSA-2048 keys and a self-signed X.509 root certificate...');

  const ca = new RootCAServer({
    caName: 'KPI_CyberSecurity_Root_CA',
    org: 'National Technical University of Ukraine "KPI"',
  });

  console.log('[SUCCESS] Root CA initialized.');
  console.log('CA Name: KPI_CyberSecurity_Root_CA');
  console.log('Public Key: RSA-2048 (SPKI)');
  console.log('Root Certificate:');
  console.log(
    ca.getRootCertificate().split('\n').slice(0, 4).join('\n')
  );
  console.log('... [X.509 PEM data] ...');

  await delay(1000);

  console.log('\n[STAGE 2] DISTRIBUTED MESH NETWORK');
  const router = createDefaultLabMeshTopology();

  console.log('Network topology:');
  console.log(router.renderTopology());

  const nodeIds = [
    'Node_A',
    'Node_B',
    'Node_C',
    'Node_D',
    'Node_E',
    'Node_F',
  ];

  console.log('\nInitializing 6 network nodes...');
  console.log('Each node generates an RSA-2048 key pair and receives a CA-signed X.509 certificate.');

  const network = new MeshNetwork({
    caServer: ca,
    router,
    mtu: 128,
    nodeIds,
  });

  for (const nodeId of router.getAllNodes()) {
    const node = network.getNode(nodeId);
    console.log(
      `[SUCCESS] ${nodeId}: X.509 certificate issued (Serial: ${node.serialNumber})`
    );
  }

  await delay(1000);

  console.log('\n[STAGE 3] ROUTING AND RADIO LINK');
  console.log('Finding the shortest route from Node_A to Node_F...');

  const route = router.findRoute('Node_A', 'Node_F');

  console.log(`Route: ${route.path.join(' -> ')}`);
  console.log(`Number of hops: ${route.distance}`);
  console.log('Radio MTU: 128 bytes per packet.');
  console.log('Large messages and certificates are fragmented into smaller packets.');

  await delay(1000);

  console.log('\n[STAGE 4] TLS HANDSHAKE');
  console.log('Establishing a secure connection between Node_A and Node_F...');

  const handshakeResult = await network.performFullTlsHandshake(
    'Node_A',
    'Node_F'
  );

  console.log(
    `[RESULT] Handshake established: ${handshakeResult.established}`
  );

  await delay(1000);

  console.log('\n[STAGE 5] SECURE DATA TRANSFER');

  console.log('\nSending an encrypted chat message...');
  await network.sendSecureChatMessage(
    'Node_A',
    'Node_F',
    'Hello Node_F! This message is encrypted using AES-256-GCM.'
  );

  const secretFileText =
    '=== SOFTWARE SECURITY REPORT ===\n' +
    'University: KPI, Faculty of Informatics\n' +
    'Topic: TLS-like Handshake and Distributed Network\n' +
    'Status: Protected by AES-256-GCM.\n' +
    'Integrity: SHA-256 hash.\n';

  console.log('\nSending an encrypted file...');
  await network.sendSecureFile(
    'Node_A',
    'Node_F',
    'security_lab8_report.txt',
    secretFileText
  );

  const nodeF = network.getNode('Node_F');

  console.log('\nReceived data at Node_F:');

  for (const item of nodeF.inbox) {
    if (item.type === 'CHAT_MESSAGE') {
      console.log(`[CHAT] From ${item.from}: ${item.payload.text}`);
    } else if (item.type === 'FILE_TRANSFER') {
      const receivedContent = Buffer.from(
        item.payload.dataBase64,
        'base64'
      ).toString('utf8');

      console.log(`[FILE] From ${item.from}: ${item.payload.filename}`);
      console.log(`Size: ${item.payload.sizeBytes} bytes`);
      console.log(`SHA-256: ${item.payload.sha256}`);
      console.log(`Content:\n${receivedContent}`);
    }
  }

  await delay(1000);

  console.log('\n[STAGE 6] NETWORK BROADCAST');
  console.log('Node_C is broadcasting a message to the mesh network...');

  const broadcastResult = await network.broadcast(
    'Node_C',
    'Attention: A new node has been detected in the radio network!'
  );

  console.log(
    `Received by: ${broadcastResult.receivedBy.join(', ')}`
  );
  console.log(
    `Total recipients: ${broadcastResult.receivedBy.length}/6`
  );

  await delay(1000);

  console.log('\n[STAGE 7] CERTIFICATE REVOCATION');
  console.log('Simulating a compromised private key on Node_B...');

  const nodeB = network.getNode('Node_B');

  ca.revokeCertificate(
    nodeB.serialNumber,
    'Suspected private key compromise'
  );

  console.log(
    `[SUCCESS] Node_B certificate revoked. Serial: ${nodeB.serialNumber}`
  );

  console.log('\nAttempting a connection to Node_B...');

  try {
    await network.performFullTlsHandshake('Node_A', 'Node_B');
    console.log('[ERROR] Handshake should have been rejected.');
  } catch (err) {
    console.log('[SUCCESS] Connection rejected.');
    console.log(`Reason: ${err.message}`);
  }

  console.log('\n[NETWORK STATISTICS]');
  console.log(`Messages sent: ${network.packetMetrics.totalMessagesSent}`);
  console.log(`Radio frames: ${network.packetMetrics.totalRadioFrames}`);
  console.log(
    `Transferred data: ${network.packetMetrics.totalBytesTransferred} bytes`
  );
}

if (require.main === module) {
  runFullDemonstration().catch(console.error);
}

module.exports = { runFullDemonstration };
