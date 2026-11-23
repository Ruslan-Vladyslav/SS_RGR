const { generateKeyPair } = require('../crypto/tls-crypto');
const { createX509Certificate, inspectCertificate } = require('../crypto/x509');

class RootCAServer {
  constructor({ caName = 'KPI_Root_CA_Authority', org = 'KPI Cyber Security Dept' } = {}) {
    this.caName = caName;
    this.org = org;

    const { publicKey, privateKey } = generateKeyPair();
    this.publicKeyPem = publicKey;
    this.privateKeyPem = privateKey;

    this.serialCounter = 1000;
    this.issuedCertificates = new Map();
    this.revocationList = new Map();

    this.rootCertPem = createX509Certificate({
      subjectCN: this.caName,
      issuerCN: this.caName,
      subjectPublicKey: this.publicKeyPem,
      signingPrivateKey: this.privateKeyPem,
      serialNumber: 1,
      validityDays: 3650,
      org: this.org,
    });
  }

  getRootCertificate() {
    return this.rootCertPem;
  }

  getRootPublicKey() {
    return this.publicKeyPem;
  }

  issueCertificate({ subjectCN, subjectPublicKeyPem, validityDays = 365 }) {
    this.serialCounter++;
    const serialNumber = this.serialCounter;

    const certPem = createX509Certificate({
      subjectCN,
      issuerCN: this.caName,
      subjectPublicKey: subjectPublicKeyPem,
      signingPrivateKey: this.privateKeyPem,
      serialNumber,
      validityDays,
      org: this.org,
    });

    const now = new Date();
    const expiresAt = new Date(now.getTime() + validityDays * 24 * 3600 * 1000);

    const record = {
      serialNumber,
      subjectCN,
      certPem,
      issuedAt: now,
      expiresAt,
      status: 'ACTIVE',
    };

    this.issuedCertificates.set(serialNumber, record);

    return {
      serialNumber,
      certificatePem: certPem,
    };
  }

  verifyCertificate(certPem, expectedSubjectCN) {
    const inspection = inspectCertificate(certPem, this.publicKeyPem);

    if (!inspection.valid) {
      return {
        valid: false,
        status: 'INVALID_SIGNATURE',
        reason: inspection.error || 'Cryptographic signature invalid against Root CA',
      };
    }

    const now = new Date();
    const validFrom = new Date(inspection.validFrom);
    const validTo = new Date(inspection.validTo);

    if (now < validFrom || now > validTo) {
      return {
        valid: false,
        status: 'EXPIRED',
        reason: `Certificate validity period expired or not yet valid (${inspection.validFrom} - ${inspection.validTo})`,
      };
    }

    for (const [serial, revInfo] of this.revocationList.entries()) {
      const rec = this.issuedCertificates.get(serial);
      if (rec && rec.certPem.trim() === certPem.trim()) {
        return {
          valid: false,
          status: 'REVOKED',
          reason: `Certificate was revoked on ${revInfo.revokedAt.toISOString()}: ${revInfo.reason}`,
        };
      }
    }

    if (expectedSubjectCN && !inspection.subject.includes(`CN=${expectedSubjectCN}`)) {
      return {
        valid: false,
        status: 'HOSTNAME_MISMATCH',
        reason: `Subject CN mismatch: Expected '${expectedSubjectCN}', got '${inspection.subject}'`,
      };
    }

    return {
      valid: true,
      status: 'VERIFIED',
      details: {
        subject: inspection.subject,
        issuer: inspection.issuer,
        validFrom: inspection.validFrom,
        validTo: inspection.validTo,
        fingerprint: inspection.fingerprint256,
        publicKeyPem: inspection.publicKeyPem,
      },
    };
  }

  revokeCertificate(serialNumber, reason = 'Key Compromise') {
    const rec = this.issuedCertificates.get(serialNumber);
    if (!rec) {
      throw new Error(`Certificate with serial #${serialNumber} not found in CA registry.`);
    }
    rec.status = 'REVOKED';
    this.revocationList.set(serialNumber, {
      revokedAt: new Date(),
      reason,
    });
    return true;
  }
}

module.exports = {
  RootCAServer,
};

