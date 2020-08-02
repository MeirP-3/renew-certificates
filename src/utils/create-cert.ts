import { pki } from 'node-forge';

export function createCert(csr: pki.Certificate, caCert: pki.Certificate, caKey: pki.PrivateKey) {

  if (!csr.verify(csr)) {
    throw new Error('csr failed verification');
  }

  const cert = pki.createCertificate();
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  cert.setSubject(csr.subject.attributes);
  cert.setIssuer(caCert.subject.attributes);
  if (csr.extensions) {
    cert.setExtensions(csr.extensions);
  }
  cert.publicKey = csr.publicKey;
  cert.sign(caKey);

  return cert;
}