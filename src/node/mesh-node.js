
const { generateKeyPair } = require('../crypto/tls-crypto');
const { RadioLink } = require('../network/radio-link');
const { TlsHandshakeSession, HANDSHAKE_TYPE } = require('../protocol/tls-handshake');
const { SecureChannel } = require('../protocol/secure-channel');

class MeshNode {
  constructor({ nodeId, caServer, mtu = 128, onLog = null }) {
    this.nodeId = nodeId;
    this.caServer = caServer;
    this.mtu = mtu;
    this.onLog = onLog || console.log;

    const { publicKey, privateKey } = generateKeyPair();
    this.publicKeyPem = publicKey;
    this.privateKeyPem = privateKey;

    const issueResult = this.caServer.issueCertificate({
      subjectCN: this.nodeId,
      subjectPublicKeyPem: this.publicKeyPem,
      validityDays: 365,
    });
    this.certificatePem = issueResult.certificatePem;
    this.serialNumber = issueResult.serialNumber;
    this.radioLink = new RadioLink({ mtu: this.mtu });
    this.activeHandshakes = new Map();
    this.secureChannels = new Map();
    this.seenBroadcasts = new Set();
    this.inbox = [];
  }

  log(msg, level = 'INFO') {
    this.onLog(`[${this.nodeId}] [${level}] ${msg}`);
  }

  initiateHandshake(targetNodeId) {
    const sessionId = `tls-${this.nodeId}-${targetNodeId}-${Date.now()}`;
    const handshake = new TlsHandshakeSession({
      sessionId,
      clientNodeId: this.nodeId,
      serverNodeId: targetNodeId,
      role: 'CLIENT',
      caServer: this.caServer,
    });

    this.activeHandshakes.set(sessionId, handshake);
    const clientHello = handshake.createClientHello();

    this.log(`Initiated TLS Handshake with ${targetNodeId} (Session: ${sessionId})`);
    return { sessionId, clientHello };
  }

  handleIncomingPayload(packet) {
    if (!packet || typeof packet !== 'object') return null;

    if (packet.type && Object.values(HANDSHAKE_TYPE).includes(packet.type)) {
      return this._handleHandshakeMessage(packet);
    }

    if (packet.protocol === 'TLS_APPLICATION_DATA') {
      return this._handleApplicationData(packet);
    }

    if (packet.type === 'TOPOLOGY_BROADCAST') {
      return this._handleBroadcastPayload(packet);
    }

    return null;
  }

  _handleHandshakeMessage(packet) {
    const { type, sessionId, clientNodeId, serverNodeId } = packet;

    switch (type) {
      case HANDSHAKE_TYPE.CLIENT_HELLO: {
        const serverHandshake = new TlsHandshakeSession({
          sessionId,
          clientNodeId,
          serverNodeId: this.nodeId,
          role: 'SERVER',
          serverPrivateKeyPem: this.privateKeyPem,
          serverCertificatePem: this.certificatePem,
          caServer: this.caServer,
        });

        this.activeHandshakes.set(sessionId, serverHandshake);
        const serverHello = serverHandshake.handleClientHello(packet);
        this.log(`Received ClientHello from ${clientNodeId}. Responded with ServerHello + X.509 Cert.`);
        return serverHello;
      }

      case HANDSHAKE_TYPE.SERVER_HELLO: {
        const clientHandshake = this.activeHandshakes.get(sessionId);
        if (!clientHandshake) {
          throw new Error(`Session ${sessionId} not found on client`);
        }

        clientHandshake.handleServerHelloAndVerify(packet);
        this.log(`Verified X.509 Certificate of Server ${serverNodeId} with Root CA!`);

        const clientKeyExchange = clientHandshake.createClientKeyExchange();
        this.log(`Generated & encrypted Premaster Secret with ${serverNodeId}'s RSA Public Key.`);
        return clientKeyExchange;
      }

      case HANDSHAKE_TYPE.CLIENT_KEY_EXCHANGE: {
        const serverHandshake = this.activeHandshakes.get(sessionId);
        if (!serverHandshake) {
          throw new Error(`Session ${sessionId} not found on server`);
        }

        serverHandshake.handleClientKeyExchange(packet);
        this.log(`Decrypted Premaster Secret and derived AES-256 session keys.`);
        return null;
      }

      case HANDSHAKE_TYPE.CLIENT_FINISHED: {
        const serverHandshake = this.activeHandshakes.get(sessionId);
        if (!serverHandshake) {
          throw new Error(`Session ${sessionId} not found on server`);
        }

        const serverFinished = serverHandshake.handleClientFinishedAndCreateServerFinished(packet);
        this.log(`Verified ClientFinished. Handshake complete! Responded with ServerFinished.`);

        const channel = new SecureChannel({
          sessionId,
          role: 'SERVER',
          sessionKeys: serverHandshake.sessionKeys,
        });
        this.secureChannels.set(clientNodeId, channel);
        return serverFinished;
      }

      case HANDSHAKE_TYPE.SERVER_FINISHED: {
        const clientHandshake = this.activeHandshakes.get(sessionId);
        if (!clientHandshake) {
          throw new Error(`Session ${sessionId} not found on client`);
        }

        clientHandshake.handleServerFinished(packet);
        this.log(`Verified ServerFinished. Handshake complete! Secure AES-256-GCM channel active.`);

        const channel = new SecureChannel({
          sessionId,
          role: 'CLIENT',
          sessionKeys: clientHandshake.sessionKeys,
        });
        this.secureChannels.set(serverNodeId, channel);
        return null;
      }

      default:
        return null;
    }
  }

  _handleApplicationData(packet) {
    let matchedSender = null;
    let decryptedRecord = null;

    for (const [peerId, channel] of this.secureChannels.entries()) {
      if (channel.sessionId === packet.sessionId) {
        try {
          decryptedRecord = channel.decryptRecord(packet);
          matchedSender = peerId;
          break;
        } catch {
        }
      }
    }

    if (!matchedSender || !decryptedRecord) {
      throw new Error(`Cannot decrypt TLS application record: no matching session or tag failure.`);
    }

    const { type, payload } = decryptedRecord;
    this.inbox.push({
      from: matchedSender,
      type,
      payload,
      timestamp: Date.now(),
    });

    if (type === 'CHAT_MESSAGE') {
      this.log(`[Secure Chat Received from ${matchedSender}]: "${payload.text}"`);
    } else if (type === 'FILE_TRANSFER') {
      this.log(
        `[Secure File Received from ${matchedSender}]: "${payload.filename}" (${payload.sizeBytes} bytes, SHA-256: ${payload.sha256.substring(0, 10)}...)`
      );
    }

    return { received: true, type, sender: matchedSender };
  }

  _handleBroadcastPayload(packet) {
    const { broadcastId, originNode, message } = packet;
    if (this.seenBroadcasts.has(broadcastId)) {
      return null;
    }
    this.seenBroadcasts.add(broadcastId);
    this.log(`[Broadcast Received from ${originNode}]: "${message}"`);
    return packet;
  }
}

module.exports = {
  MeshNode,
};

