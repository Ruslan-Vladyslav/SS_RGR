
const { MeshNode } = require('../node/mesh-node');
const { createDefaultLabMeshTopology } = require('./router');

class MeshNetwork {
  constructor({
    caServer,
    router = null,
    mtu = 128,
    nodeIds = ['Node_A', 'Node_B', 'Node_C', 'Node_D', 'Node_E', 'Node_F'],
    onLog = null,
  }) {
    this.caServer = caServer;
    this.router = router || createDefaultLabMeshTopology();
    this.mtu = mtu;
    this.onLog = onLog || console.log;

    this.nodes = new Map();
    this.packetMetrics = {
      totalMessagesSent: 0,
      totalRadioFrames: 0,
      totalBytesTransferred: 0,
    };

    for (const nodeId of nodeIds) {
      const node = new MeshNode({
        nodeId,
        caServer: this.caServer,
        mtu: this.mtu,
        onLog: this.onLog,
      });
      this.nodes.set(nodeId, node);
      this.router.addNode(nodeId);
    }
  }

  getNode(nodeId) {
    const node = this.nodes.get(nodeId);
    if (!node) {
      throw new Error(`Node ${nodeId} does not exist in the mesh network`);
    }
    return node;
  }

  async sendRoutedMessage(sourceId, destinationId, payload) {
    const sourceNode = this.getNode(sourceId);
    const destNode = this.getNode(destinationId);

    const routeInfo = this.router.findRoute(sourceId, destinationId);
    if (!routeInfo) {
      throw new Error(`Routing Error: No path found between ${sourceId} and ${destinationId}`);
    }

    const path = routeInfo.path;
    const fragmentResult = sourceNode.radioLink.fragment(payload);
    const { packetId, totalFrames, totalBytes, frames } = fragmentResult;

    this.packetMetrics.totalMessagesSent++;
    this.packetMetrics.totalRadioFrames += totalFrames;
    this.packetMetrics.totalBytesTransferred += totalBytes;

    const routeStr = path.join(' -> ');
    this.onLog(
      `[RADIO TRANSMISSION] [0m ${sourceId} -> ${destinationId} | Path: [${routeStr}] | Payload: ${totalBytes} bytes | MTU: ${this.mtu}B -> Split into ${totalFrames} radio frames`
    );

    for (const frame of frames) {
      for (let i = 0; i < path.length - 1; i++) {
        const currentHop = path[i];
        const nextHop = path[i + 1];
        await sourceNode.radioLink.sleepDelay();
      }
    }

    let reassembled = null;
    for (const frame of frames) {
      reassembled = destNode.radioLink.receiveFrame(frame);
    }

    if (!reassembled) {
      throw new Error(`Packet reassembly failed at destination ${destinationId}`);
    }
    const responsePayload = destNode.handleIncomingPayload(reassembled);

    return {
      delivered: true,
      packetId,
      route: path,
      hops: path.length - 1,
      totalBytes,
      totalFrames,
      response: responsePayload,
    };
  }

  async performFullTlsHandshake(clientNodeId, serverNodeId) {
    const clientNode = this.getNode(clientNodeId);
    const serverNode = this.getNode(serverNodeId);

    this.onLog(
      `TLS HANDSHAKE: [${clientNodeId}] <---> [${serverNodeId}]`
    );

    this.onLog(`[STEP 1/7] Client Hello`);
    const { sessionId, clientHello } = clientNode.initiateHandshake(serverNodeId);
    this.onLog(`Client Random: ${clientHello.clientRandomHex.substring(0, 32)}... (32 bytes)`);

    this.onLog(`[STEP 2/7] Server Hello & X.509 Certificate Response`);
    const step1Result = await this.sendRoutedMessage(clientNodeId, serverNodeId, clientHello);
    const serverHello = step1Result.response;

    this.onLog(`Server Random: ${serverHello.serverRandomHex.substring(0, 32)}... (32 bytes)`);
    this.onLog(
      `Server X.509 Certificate received (${serverHello.certificatePem.length} bytes PEM)`
    );

    this.onLog(
      `[STEP 3/7 & 4/7] Certificate Verification with Root CA & Premaster Secret`
    );

    const clientKeyExchange = clientNode.handleIncomingPayload(serverHello);

    const step4Result = await this.sendRoutedMessage(
      clientNodeId,
      serverNodeId,
      clientKeyExchange
    );

    this.onLog(
      `[STEP 5/7] Session Key Derivation (HKDF-SHA256) on Client & Server`
    );
    const clientSession = clientNode.activeHandshakes.get(sessionId);
    const serverSession = serverNode.activeHandshakes.get(sessionId);

    this.onLog(
      `Client Master Secret: ${clientSession.sessionKeys.masterSecret.toString('hex').substring(0, 32)}...`
    );
    this.onLog(
      `Server Master Secret: ${serverSession.sessionKeys.masterSecret.toString('hex').substring(0, 32)}...`
    );

    const keysMatch = clientSession.sessionKeys.masterSecret.equals(
      serverSession.sessionKeys.masterSecret
    );
    this.onLog(
      `Cryptographic Check: Session Keys MATCH on both nodes: ${keysMatch}`
    );

    this.onLog(`[STEP 6/7] Finished / Ready Messages Exchange`);
    const clientFinished = clientSession.createClientFinished();
    const step6Result = await this.sendRoutedMessage(clientNodeId, serverNodeId, clientFinished);
    const serverFinished = step6Result.response;
    clientNode.handleIncomingPayload(serverFinished);

    this.onLog(`[STEP 7/7] Handshake Established`);
    this.onLog(
      `TLS Handshake successfully completed between [${clientNodeId}] and [${serverNodeId}]`
    );
    this.onLog(
      `Secure Channel active using AES-256-GCM symmetric encryption with derived session keys.`
    );

    return {
      sessionId,
      clientNodeId,
      serverNodeId,
      established: true,
      masterSecretHex: clientSession.sessionKeys.masterSecret.toString('hex'),
    };
  }

  async sendSecureChatMessage(sourceId, destinationId, text) {
    const sourceNode = this.getNode(sourceId);
    const channel = sourceNode.secureChannels.get(destinationId);
    if (!channel) {
      throw new Error(`No active TLS channel between ${sourceId} and ${destinationId}. Run handshake first.`);
    }

    const encryptedRecord = channel.createChatMessage(text);
    this.onLog(
      `[SEND SECURE CHAT] ${sourceId} -> ${destinationId}: Plaintext="${text}" | Encrypted Ciphertext=${encryptedRecord.ciphertext.substring(0, 24)}... (AES-256-GCM, Tag: ${encryptedRecord.tag.substring(0, 8)})`
    );

    const result = await this.sendRoutedMessage(sourceId, destinationId, encryptedRecord);
    return result;
  }

  async sendSecureFile(sourceId, destinationId, filename, content) {
    const sourceNode = this.getNode(sourceId);
    const channel = sourceNode.secureChannels.get(destinationId);
    if (!channel) {
      throw new Error(`No active TLS channel between ${sourceId} and ${destinationId}. Run handshake first`);
    }

    const encryptedRecord = channel.createFileTransfer(filename, content);
    this.onLog(
      `[SEND SECURE FILE] ${sourceId} -> ${destinationId}: File="${filename}" | Size=${Buffer.byteLength(content)} bytes | Encrypted Ciphertext=${encryptedRecord.ciphertext.substring(0, 24)}... (AES-256-GCM)`
    );

    const result = await this.sendRoutedMessage(sourceId, destinationId, encryptedRecord);
    return result;
  }

  async broadcast(originNodeId, messageText) {
    const originNode = this.getNode(originNodeId);
    const broadcastId = `bcast-${originNodeId}-${Date.now()}`;

    this.onLog(
      `INITIATING TOPOLOGY-AWARE BROADCAST from [${originNodeId}]`
    );
    this.onLog(`Broadcast ID: ${broadcastId} | Content: "${messageText}"`);

    const broadcastPayload = {
      type: 'TOPOLOGY_BROADCAST',
      broadcastId,
      originNode: originNodeId,
      message: messageText,
      timestamp: Date.now(),
    };

    originNode.seenBroadcasts.add(broadcastId);


    const visitedNodes = new Set([originNodeId]);
    const deliveryLog = [];

    const directNeighbors = this.router.getNeighbors(originNodeId);
    let queue = directNeighbors.map((neighbor) => ({ from: originNodeId, to: neighbor }));

    while (queue.length > 0) {
      const nextQueue = [];
      for (const edge of queue) {
        const { from, to } = edge;
        const targetNode = this.getNode(to);

        if (targetNode.seenBroadcasts.has(broadcastId)) {
          continue;
        }

        const fragmentResult = this.getNode(from).radioLink.fragment(broadcastPayload);
        this.packetMetrics.totalMessagesSent++;
        this.packetMetrics.totalRadioFrames += fragmentResult.totalFrames;
        this.packetMetrics.totalBytesTransferred += fragmentResult.totalBytes;

        for (const frame of fragmentResult.frames) {
          targetNode.radioLink.receiveFrame(frame);
        }

        targetNode.handleIncomingPayload(broadcastPayload);
        visitedNodes.add(to);
        deliveryLog.push({ from, to, frames: fragmentResult.totalFrames });

        this.onLog(
          `  Broadcast Radio Hop: [${from}] -> [${to}] (MTU split: ${fragmentResult.totalFrames} frames) -> Delivered to ${to}`
        );

        const neighbors = this.router.getNeighbors(to);
        for (const nextNeighbor of neighbors) {
          if (!this.getNode(nextNeighbor).seenBroadcasts.has(broadcastId)) {
            nextQueue.push({ from: to, to: nextNeighbor });
          }
        }
      }

      queue = nextQueue;
    }

    this.onLog(
      `Broadcast Complete: delivered to ${visitedNodes.size} of ${this.nodes.size} nodes across mesh`
    );

    return {
      broadcastId,
      origin: originNodeId,
      receivedBy: Array.from(visitedNodes),
      totalHops: deliveryLog.length,
    };
  }
}
module.exports = {
  MeshNetwork,
};

