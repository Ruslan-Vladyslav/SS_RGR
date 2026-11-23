const crypto = require('crypto');

class RadioLink {
  constructor({ mtu = 128, delayMs = 2, verbose = false } = {}) {
    this.mtu = mtu;
    this.delayMs = delayMs;
    this.verbose = verbose;

    this.assemblyBuffers = new Map();
    this.packetCounter = 0;
  }

  fragment(data) {
    const serialized = typeof data === 'string' ? data : JSON.stringify(data);
    const dataBuffer = Buffer.from(serialized, 'utf8');

    this.packetCounter++;
    const packetId = `pkt-${Date.now()}-${this.packetCounter}-${crypto.randomBytes(4).toString('hex')}`;

    //const maxPayloadSize = Math.max(24, this.mtu - 64);
    const maxPayloadSize = this.mtu;
    const totalFrames = Math.ceil(dataBuffer.length / maxPayloadSize);
    const frames = [];

    for (let seq = 0; seq < totalFrames; seq++) {
      const start = seq * maxPayloadSize;
      const end = Math.min(start + maxPayloadSize, dataBuffer.length);
      const chunk = dataBuffer.subarray(start, end).toString('base64');
      const checksum = crypto
        .createHash('sha256')
        .update(chunk)
        .digest('hex')
        .substring(0, 8);

      const frame = {
        packetId,
        seq,
        total: totalFrames,
        payload: chunk,
        checksum,
        size: 0,
      };

      const frameRaw = JSON.stringify(frame);
      frame.size = Buffer.byteLength(frameRaw, 'utf8');
      frames.push(frame);
    }

    return {
      packetId,
      totalBytes: dataBuffer.length,
      totalFrames,
      frames,
    };
  }

  receiveFrame(frame) {
    const { packetId, seq, total, payload, checksum } = frame;

    const computedChecksum = crypto
      .createHash('sha256')
      .update(payload)
      .digest('hex')
      .substring(0, 8);
    if (computedChecksum !== checksum) {
      throw new Error(`Radio Frame Checksum Mismatch in ${packetId} seq ${seq}`);
    }

    if (!this.assemblyBuffers.has(packetId)) {
      this.assemblyBuffers.set(packetId, {
        total,
        receivedCount: 0,
        fragments: new Array(total),
      });
    }

    const state = this.assemblyBuffers.get(packetId);
    if (!state.fragments[seq]) {
      state.fragments[seq] = Buffer.from(payload, 'base64');
      state.receivedCount++;
    }

    if (state.receivedCount === state.total) {
      this.assemblyBuffers.delete(packetId);
      const fullBuffer = Buffer.concat(state.fragments);
      const rawString = fullBuffer.toString('utf8');

      try {
        return JSON.parse(rawString);
      } catch {
        return rawString;
      }
    }

    return null;
  }

  async sleepDelay() {
    if (this.delayMs <= 0) return;
    return new Promise((resolve) => setTimeout(resolve, this.delayMs));
  }
}
module.exports = {
  RadioLink,
};

