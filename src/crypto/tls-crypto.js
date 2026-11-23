const crypto = require('crypto');

function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });
  return { publicKey, privateKey };
}


function randomBytes(length = 32) {
  return crypto.randomBytes(length);
}

function rsaEncrypt(publicKeyPem, buffer) {
  return crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    buffer
  );
}

function rsaDecrypt(privateKeyPem, buffer) {
  return crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    buffer
  );
}


function deriveSessionKeys(premasterSecret, clientRandom, serverRandom) {
  const masterSecretSalt = Buffer.concat([clientRandom, serverRandom]);
  const masterSecret = crypto.hkdfSync(
    'sha256',
    premasterSecret,
    masterSecretSalt,
    Buffer.from('master secret', 'utf8'),
    48
  );

  const keyBlockSalt = Buffer.concat([serverRandom, clientRandom]);
  const keyBlock = crypto.hkdfSync(
    'sha256',
    Buffer.from(masterSecret),
    keyBlockSalt,
    Buffer.from('key expansion', 'utf8'),
    88
  );

  const keyBuffer = Buffer.from(keyBlock);
  let offset = 0;
  const clientWriteKey = keyBuffer.subarray(offset, offset + 32);
  offset += 32;
  const serverWriteKey = keyBuffer.subarray(offset, offset + 32);
  offset += 32;
  const clientWriteIV = keyBuffer.subarray(offset, offset + 12);
  offset += 12;
  const serverWriteIV = keyBuffer.subarray(offset, offset + 12);
  offset += 12;

  return {
    masterSecret: Buffer.from(masterSecret),
    clientWriteKey,
    serverWriteKey,
    clientWriteIV,
    serverWriteIV,
  };
}

function encryptAesGcm(key, iv, plaintext, aad) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) {
    cipher.setAAD(aad);
  }
  const input = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ciphertext: encrypted.toString('base64'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
  };
}

function decryptAesGcm(key, iv, ciphertextBase64, tagHex, aad) {
  const ivBuf = Buffer.isBuffer(iv) ? iv : Buffer.from(iv, 'hex');
  const tagBuf = Buffer.isBuffer(tagHex) ? tagHex : Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, ivBuf);
  decipher.setAuthTag(tagBuf);
  if (aad) {
    decipher.setAAD(aad);
  }
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertextBase64, 'base64')),
    decipher.final(),
  ]);
  return decrypted;
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

module.exports = {
  generateKeyPair,
  randomBytes,
  rsaEncrypt,
  rsaDecrypt,
  deriveSessionKeys,
  encryptAesGcm,
  decryptAesGcm,
  sha256,
  hmacSha256,
};

