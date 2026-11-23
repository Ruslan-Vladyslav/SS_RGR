const crypto = require('crypto');

function derLength(len) {
  if (len < 128) {
    return Buffer.from([len]);
  }
  const bytes = [];
  let temp = len;
  while (temp > 0) {
    bytes.unshift(temp & 0xff);
    temp >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTag(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function derSeq(...items) {
  return derTag(0x30, Buffer.concat(items));
}

function derInt(num) {
  if (typeof num === 'number') {
    const buf = Buffer.alloc(4);
    buf.writeInt32BE(num);
    let i = 0;
    while (i < 3 && buf[i] === 0 && (buf[i + 1] & 0x80) === 0) i++;
    return derTag(0x02, buf.subarray(i));
  }
  if (Buffer.isBuffer(num)) {
    if (num[0] & 0x80) {
      return derTag(0x02, Buffer.concat([Buffer.from([0x00]), num]));
    }
    return derTag(0x02, num);
  }
  throw new Error('Unsupported int value');
}

function derOid(oidStr) {
  const parts = oidStr.split('.').map(Number);
  const bytes = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let val = parts[i];
    const b = [];
    b.push(val & 0x7f);
    while (val >= 128) {
      val >>= 7;
      b.unshift((val & 0x7f) | 0x80);
    }
    bytes.push(...b);
  }
  return derTag(0x06, Buffer.from(bytes));
}

function derUtcTime(date) {
  const pad = (n) => String(n).padStart(2, '0');
  const str =
    pad(date.getUTCFullYear() % 100) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    'Z';
  return derTag(0x17, Buffer.from(str, 'ascii'));
}

function derPrintable(str) {
  return derTag(0x13, Buffer.from(str, 'utf8'));
}

function derUtf8(str) {
  return derTag(0x0c, Buffer.from(str, 'utf8'));
}

function derName(commonName, org = 'KPI Security Lab') {
  const cnRdn = derTag(0x31, derSeq(derOid('2.5.4.3'), derUtf8(commonName)));
  const oRdn = derTag(0x31, derSeq(derOid('2.5.4.10'), derUtf8(org)));
  return derSeq(cnRdn, oRdn);
}

function createX509Certificate({
  subjectCN,
  issuerCN,
  subjectPublicKey,
  signingPrivateKey,
  serialNumber = Math.floor(Math.random() * 1000000) + 1,
  validityDays = 365,
  org = 'KPI Security Lab',
}) {
  const pubKeyObj =
    typeof subjectPublicKey === 'string'
      ? crypto.createPublicKey(subjectPublicKey)
      : subjectPublicKey;
  const privKeyObj =
    typeof signingPrivateKey === 'string'
      ? crypto.createPrivateKey(signingPrivateKey)
      : signingPrivateKey;

  const spkiDer = pubKeyObj.export({ type: 'spki', format: 'der' });
  const sha256WithRsa = derSeq(derOid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00]));

  const now = new Date();
  const notAfter = new Date(now.getTime() + validityDays * 24 * 3600 * 1000);
  const validity = derSeq(derUtcTime(now), derUtcTime(notAfter));

  const tbs = derSeq(
    derTag(0xa0, derInt(2)),
    derInt(serialNumber),
    sha256WithRsa,
    derName(issuerCN, org),
    validity,
    derName(subjectCN, org),
    spkiDer
  );

  const signature = crypto.sign('sha256', tbs, privKeyObj);
  const sigBitString = derTag(0x03, Buffer.concat([Buffer.from([0x00]), signature]));
  const certDer = derSeq(tbs, sha256WithRsa, sigBitString);

  const base64 = certDer.toString('base64');
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}

function inspectCertificate(certPem, caPublicKey) {
  try {
    const x509 = new crypto.X509Certificate(certPem);
    let valid = true;
    let error;

    if (caPublicKey) {
      const pubKey =
        typeof caPublicKey === 'string' ? crypto.createPublicKey(caPublicKey) : caPublicKey;
      valid = x509.verify(pubKey);
      if (!valid) {
        error = 'Signature verification failed against CA public key';
      }
    }

    return {
      valid,
      subject: x509.subject,
      issuer: x509.issuer,
      validFrom: x509.validFrom,
      validTo: x509.validTo,
      fingerprint256: x509.fingerprint256,
      publicKeyPem: x509.publicKey.export({ type: 'spki', format: 'pem' }),
      error,
    };
  } catch (err) {
    return {
      valid: false,
      error: err.message,
    };
  }
}

module.exports = {
  createX509Certificate,
  inspectCertificate,
};

