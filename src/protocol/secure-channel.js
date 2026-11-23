
const { encryptAesGcm, decryptAesGcm, sha256 } = require('../crypto/tls-crypto');

class SecureChannel {
  constructor({ sessionId, role, sessionKeys }) {
    this.sessionId = sessionId;
    this.role = role;
    this.sessionKeys = sessionKeys;

    if (role === 'CLIENT') {
      this.writeKey = sessionKeys.clientWriteKey;
      this.baseWriteIV = sessionKeys.clientWriteIV;
      this.readKey = sessionKeys.serverWriteKey;
      this.baseReadIV = sessionKeys.serverWriteIV;
    } else {
      this.writeKey = sessionKeys.serverWriteKey;
      this.baseWriteIV = sessionKeys.serverWriteIV;
      this.readKey = sessionKeys.clientWriteKey;
      this.baseReadIV = sessionKeys.clientWriteIV;
    }

    this.sendSequence = 0;
    this.receiveSequence = 0;
  }

  _computeIV(baseIV, seq) {
    const iv = Buffer.from(baseIV);
    const seqBuf = Buffer.alloc(8);
    seqBuf.writeBigUInt64BE(BigInt(seq));
    for (let i = 0; i < 8; i++) {
      iv[4 + i] ^= seqBuf[i];
    }
    return iv;
  }

  encryptRecord(payload, type = 'CHAT_MESSAGE') {
    const seq = this.sendSequence++;
    const iv = this._computeIV(this.baseWriteIV, seq);

    const recordPlaintext = JSON.stringify({
      type,
      sessionId: this.sessionId,
      senderRole: this.role,
      seq,
      timestamp: Date.now(),
      payload,
    });

    const aad = Buffer.from(`${this.sessionId}:${seq}`, 'utf8');
    const encrypted = encryptAesGcm(this.writeKey, iv, recordPlaintext, aad);

    return {
      protocol: 'TLS_APPLICATION_DATA',
      sessionId: this.sessionId,
      seq,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      tag: encrypted.tag,
    };
  }

  decryptRecord(record) {
    const { seq, ciphertext, iv, tag } = record;
    const expectedIV = this._computeIV(this.baseReadIV, seq);

    const aad = Buffer.from(`${this.sessionId}:${seq}`, 'utf8');
    const decryptedBuf = decryptAesGcm(this.readKey, expectedIV, ciphertext, tag, aad);

    this.receiveSequence = Math.max(this.receiveSequence, seq + 1);

    const data = JSON.parse(decryptedBuf.toString('utf8'));
    return data;
  }

  createChatMessage(text) {
    return this.encryptRecord({ text }, 'CHAT_MESSAGE');
  }

  createFileTransfer(filename, content, mimeType = 'text/plain') {
    const buf = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
    const fileHash = sha256(buf);

    return this.encryptRecord(
      {
        filename,
        mimeType,
        sizeBytes: buf.length,
        sha256: fileHash,
        dataBase64: buf.toString('base64'),
      },
      'FILE_TRANSFER'
    );
  }
}

module.exports = {
  SecureChannel,
};

