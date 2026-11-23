const {
  randomBytes,
  rsaEncrypt,
  rsaDecrypt,
  deriveSessionKeys,
  encryptAesGcm,
  decryptAesGcm,
  sha256,
} = require('../crypto/tls-crypto');

const HANDSHAKE_TYPE = {
  CLIENT_HELLO: 'CLIENT_HELLO',
  SERVER_HELLO: 'SERVER_HELLO',
  CLIENT_KEY_EXCHANGE: 'CLIENT_KEY_EXCHANGE',
  CLIENT_FINISHED: 'CLIENT_FINISHED',
  SERVER_FINISHED: 'SERVER_FINISHED',
};

class TlsHandshakeSession {
  constructor({
    sessionId,
    clientNodeId,
    serverNodeId,
    role,
    serverPrivateKeyPem = null,
    serverCertificatePem = null,
    caServer = null,
  }) {
    this.sessionId = sessionId;
    this.clientNodeId = clientNodeId;
    this.serverNodeId = serverNodeId;
    this.role = role;

    this.serverPrivateKeyPem = serverPrivateKeyPem;
    this.serverCertificatePem = serverCertificatePem;
    this.caServer = caServer;

    this.clientRandom = null;
    this.serverRandom = null;
    this.serverPublicKeyPem = null;
    this.premasterSecret = null;
    this.sessionKeys = null;

    this.step = 0;
    this.status = 'INITIALIZED';
    this.transcript = [];
    this.established = false;
  }

  logStep(stepNumber, description, data = {}) {
    this.step = stepNumber;
    const entry = {
      step: stepNumber,
      role: this.role,
      description,
      data,
      timestamp: new Date().toISOString(),
    };
    this.transcript.push(entry);
    return entry;
  }

  createClientHello() {
    if (this.role !== 'CLIENT') {
      throw new Error('Only client can initiate ClientHello');
    }

    this.clientRandom = randomBytes(32);
    const message = {
      type: HANDSHAKE_TYPE.CLIENT_HELLO,
      sessionId: this.sessionId,
      clientNodeId: this.clientNodeId,
      serverNodeId: this.serverNodeId,
      clientRandomHex: this.clientRandom.toString('hex'),
      timestamp: Date.now(),
      cipherSuites: ['TLS_RSA_WITH_AES_256_GCM_SHA256'],
    };

    this.logStep(1, 'Client initiates handshake with ClientHello and random string', {
      clientRandomHex: message.clientRandomHex,
      ciphers: message.cipherSuites,
    });

    return message;
  }

  handleClientHello(clientHelloMsg) {
    if (this.role !== 'SERVER') {
      throw new Error('Only server can handle ClientHello');
    }

    this.clientRandom = Buffer.from(clientHelloMsg.clientRandomHex, 'hex');
    this.serverRandom = randomBytes(32);

    const serverHelloMsg = {
      type: HANDSHAKE_TYPE.SERVER_HELLO,
      sessionId: this.sessionId,
      clientNodeId: this.clientNodeId,
      serverNodeId: this.serverNodeId,
      serverRandomHex: this.serverRandom.toString('hex'),
      selectedCipher: 'TLS_RSA_WITH_AES_256_GCM_SHA256',
      certificatePem: this.serverCertificatePem,
      timestamp: Date.now(),
    };

    this.logStep(2, 'Server responds with ServerHello (random string) and X.509 Certificate', {
      serverRandomHex: serverHelloMsg.serverRandomHex,
      hasCert: !!this.serverCertificatePem,
    });

    return serverHelloMsg;
  }

  handleServerHelloAndVerify(serverHelloMsg) {
    if (this.role !== 'CLIENT') {
      throw new Error('Only client can verify ServerHello');
    }

    this.serverRandom = Buffer.from(serverHelloMsg.serverRandomHex, 'hex');
    const certPem = serverHelloMsg.certificatePem;

    if (!certPem) {
      throw new Error('ServerHello did not include SSL/TLS certificate');
    }

    if (!this.caServer) {
      throw new Error('Client has no Root CA configured for authentication');
    }

    const caVerification = this.caServer.verifyCertificate(certPem, this.serverNodeId);

    if (!caVerification.valid) {
      this.status = 'AUTH_FAILED';
      throw new Error(
        `Server Authentication Failed: ${caVerification.reason} (Status: ${caVerification.status})`
      );
    }

    this.serverPublicKeyPem = caVerification.details.publicKeyPem;

    this.logStep(3, 'Client successfully authenticates Server X.509 Certificate via Root CA', {
      status: caVerification.status,
      subject: caVerification.details.subject,
      issuer: caVerification.details.issuer,
      fingerprint: caVerification.details.fingerprint,
    });

    return caVerification;
  }

  createClientKeyExchange() {
    if (this.role !== 'CLIENT') {
      throw new Error('Only client can create ClientKeyExchange');
    }
    if (!this.serverPublicKeyPem) {
      throw new Error('Server public key not yet verified');
    }

    this.premasterSecret = randomBytes(48);
    const encryptedPremaster = rsaEncrypt(this.serverPublicKeyPem, this.premasterSecret);

    const message = {
      type: HANDSHAKE_TYPE.CLIENT_KEY_EXCHANGE,
      sessionId: this.sessionId,
      clientNodeId: this.clientNodeId,
      serverNodeId: this.serverNodeId,
      encryptedPremasterHex: encryptedPremaster.toString('hex'),
    };

    this.logStep(4, 'Client generates Premaster Secret and encrypts it with Server Public Key', {
      premasterHexPreview: `${this.premasterSecret.toString('hex').substring(0, 16)}... (48 bytes)`,
      encryptedHexLength: encryptedPremaster.length,
    });
    this.deriveKeys();
    return message;
  }

  handleClientKeyExchange(clientKeyExchangeMsg) {
    if (this.role !== 'SERVER') {
      throw new Error('Only server can handle ClientKeyExchange');
    }

    const encryptedBuf = Buffer.from(clientKeyExchangeMsg.encryptedPremasterHex, 'hex');

    this.premasterSecret = rsaDecrypt(this.serverPrivateKeyPem, encryptedBuf);
    this.logStep(4, 'Server decrypts Premaster Secret using Server Private Key', {
      premasterHexPreview: `${this.premasterSecret.toString('hex').substring(0, 16)}... (48 bytes)`,
    });
    this.deriveKeys();
  }

  deriveKeys() {
    if (!this.premasterSecret || !this.clientRandom || !this.serverRandom) {
      throw new Error('Cannot derive keys: missing secrets or random values');
    }

    this.sessionKeys = deriveSessionKeys(
      this.premasterSecret,
      this.clientRandom,
      this.serverRandom
    );

    this.logStep(5, 'Session keys derived via HKDF-SHA256 from Premaster Secret + Randoms', {
      masterSecretPreview: `${this.sessionKeys.masterSecret.toString('hex').substring(0, 16)}...`,
      clientWriteKeyHex: `${this.sessionKeys.clientWriteKey.toString('hex').substring(0, 16)}...`,
      serverWriteKeyHex: `${this.sessionKeys.serverWriteKey.toString('hex').substring(0, 16)}...`,
    });
  }

  createClientFinished() {
    if (this.role !== 'CLIENT') {
      throw new Error('Only client creates ClientFinished');
    }

    const finishedPayload = JSON.stringify({
      message: 'CLIENT_FINISHED',
      sessionId: this.sessionId,
      transcriptHash: sha256(JSON.stringify(this.transcript)),
      timestamp: Date.now(),
    });

    const encrypted = encryptAesGcm(
      this.sessionKeys.clientWriteKey,
      this.sessionKeys.clientWriteIV,
      finishedPayload
    );

    const message = {
      type: HANDSHAKE_TYPE.CLIENT_FINISHED,
      sessionId: this.sessionId,
      clientNodeId: this.clientNodeId,
      serverNodeId: this.serverNodeId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      tag: encrypted.tag,
    };

    this.logStep(6, 'Client sends encrypted Finished/Ready message using Session Key', {
      tag: encrypted.tag,
    });

    return message;
  }

  handleClientFinishedAndCreateServerFinished(clientFinishedMsg) {
    if (this.role !== 'SERVER') {
      throw new Error('Only server handles ClientFinished');
    }

    const decryptedBuf = decryptAesGcm(
      this.sessionKeys.clientWriteKey,
      clientFinishedMsg.iv,
      clientFinishedMsg.ciphertext,
      clientFinishedMsg.tag
    );

    const payload = JSON.parse(decryptedBuf.toString('utf8'));
    if (payload.message !== 'CLIENT_FINISHED') {
      throw new Error('Invalid Client Finished payload');
    }

    this.logStep(6, 'Server successfully decrypted and verified Client Finished message');
    const serverPayload = JSON.stringify({
      message: 'SERVER_FINISHED',
      sessionId: this.sessionId,
      timestamp: Date.now(),
    });

    const encrypted = encryptAesGcm(
      this.sessionKeys.serverWriteKey,
      this.sessionKeys.serverWriteIV,
      serverPayload
    );

    const serverFinishedMsg = {
      type: HANDSHAKE_TYPE.SERVER_FINISHED,
      sessionId: this.sessionId,
      clientNodeId: this.clientNodeId,
      serverNodeId: this.serverNodeId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      tag: encrypted.tag,
    };

    this.established = true;
    this.status = 'HANDSHAKE_ESTABLISHED';
    this.logStep(7, 'Server completes TLS Handshake. Secure channel ready for symmetric encryption');

    return serverFinishedMsg;
  }

  handleServerFinished(serverFinishedMsg) {
    if (this.role !== 'CLIENT') {
      throw new Error('Only client handles ServerFinished');
    }

    const decryptedBuf = decryptAesGcm(
      this.sessionKeys.serverWriteKey,
      serverFinishedMsg.iv,
      serverFinishedMsg.ciphertext,
      serverFinishedMsg.tag
    );

    const payload = JSON.parse(decryptedBuf.toString('utf8'));
    if (payload.message !== 'SERVER_FINISHED') {
      throw new Error('Invalid Server Finished payload');
    }

    this.established = true;
    this.status = 'HANDSHAKE_ESTABLISHED';
    this.logStep(7, 'Client completes TLS Handshake. Secure channel ready for symmetric encryption');

    return true;
  }
}

module.exports = {
  HANDSHAKE_TYPE,
  TlsHandshakeSession,
};

