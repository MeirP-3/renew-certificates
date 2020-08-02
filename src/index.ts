import YAML from 'yaml';
import { promises as fs } from 'fs';
import path from 'path';
import { connectThroughBastion } from './ssh/connection';
import { pki } from 'node-forge';
import { errorHandler } from './utils/error-handler';

interface HostConfig {
  host: string
  certs_dir: string
  user: string
}

interface CaConfig {
  cert: string
  key: string
}

interface Config {
  ca: CaConfig
  bastion: string
  hosts: HostConfig[]
}

interface CertError {
  error: Error
  path?: string
}

interface HostStatus extends HostConfig {
  status: 'pending' | 'connected' | 'completed' | 'error'
  errors: CertError[]
  certsByPath: {
    [path: string]: {
      cert: string
      csr: string
    }
  }
}

interface CsrsByPath {
  [path: string]: {
    csr: string
  }
}

interface CaData {
  caKey: pki.PrivateKey
  caCert: pki.Certificate
}


async function renewAll() {

  const content = await fs.readFile(path.join(__dirname, 'config.yaml'), 'utf8');
  const { ca, bastion, hosts }: Config = YAML.parse(content);

  if (!ca) {
    return errorHandler(new Error('ca entry not provided'));
  }

  if (!bastion) {
    return errorHandler(new Error('bastion entry not provided'));
  }

  if (!hosts) {
    return errorHandler(new Error('hosts entry not provided'));
  }

  const allHostsStatus: HostStatus[] = hosts.map<HostStatus>
    ((host) => ({ ...host, status: 'pending', certsByPath: {}, errors: [] }));

  const caCertPem = await fs.readFile(ca.cert, 'utf8');
  const caKeyPem = await fs.readFile(ca.key, 'utf8');

  const caData: CaData = {
    caCert: pki.certificateFromPem(caCertPem),
    caKey: pki.privateKeyFromPem(caKeyPem)
  };

  const results = await Promise.all(
    allHostsStatus.map(
      host => renewHost(caData, bastion, host)
    )
  );

  console.log(results);

}

renewAll()


async function renewHost({ caKey, caCert }: CaData, bastion: string, hostStatus: HostStatus) {

  const { host, user, certs_dir, certsByPath } = hostStatus;

  return new Promise(async (resolve, reject) => {

    const onError = (error: Error) => {
      hostStatus.status = 'error';
      hostStatus.errors.push({ error });
      return resolve(hostStatus);
    };

    const connection = await connectThroughBastion({ bastion, username: user, host });

    hostStatus.status = 'connected';

    connection.sftp((err, sftp) => {

      if (err) {
        return onError(err);
      }

      const collectCsrsScriptName = 'collect-csr.js';
      const collectCsrsScriptPath = path.join(__dirname, 'scripts', collectCsrsScriptName);

      sftp.fastPut(collectCsrsScriptPath, `${certs_dir}/${collectCsrsScriptName}`, err => {

        if (err) {
          return onError(err);
        }

        connection.exec(`. .nvm/nvm.sh; cd ${certs_dir} && node ${collectCsrsScriptName}`,
          (err, channel) => {

            if (err) {
              return onError(err);
            }

            channel.once('error', e => {
              onError(e);
            });         
            
            channel.on('data', data => {
              console.log(data.toString());
            })

            channel.once('data', (data) => {


              sftp.readFile(`${certs_dir}/__COLLECTED__CSRS___.json`, (err, content) => {

                if (err) {
                  return onError(err);
                }

                let csrsByPath: CsrsByPath, entries;

                try {
                  csrsByPath = JSON.parse(content.toString());
  
                  entries = Object.entries(csrsByPath);

                  if (entries.length === 0) {
                    hostStatus.status = 'completed';
                    return resolve(hostStatus);
                  }

                } catch (error) {

                  return onError(error);

                }

                const length = entries.length;
                let completedCount = 0;

                const onCertError = (path: string, error: Error) => {
                  hostStatus.status = 'error';
                  hostStatus.errors.push({ path, error });
                }

                entries.forEach(async ([path, { csr: csrPem }], index) => {

                  let stream, certPem;

                  try {

                    const csr = pki.certificationRequestFromPem(csrPem);

                    const cert = createCert(csr, caCert, caKey);

                    certPem = pki.certificateToPem(cert);

                    stream = sftp.createWriteStream(path);

                  } catch (error) {

                    completedCount++;

                    onCertError(path, error);

                  }

                  stream.write(certPem, err => {

                    completedCount++;

                    if (err) {

                      onCertError(path, err);

                    } else {

                      certsByPath[path] = {
                        csr: csrPem,
                        cert: certPem
                      };

                    }

                    if (completedCount === length) {
                      hostStatus.status = 'completed';
                      resolve(hostStatus);
                    }

                  });

                  stream.end();

                });

              });
            });
          });
      });
    });

  });
}

function createCert(csr: pki.Certificate, caCert: pki.Certificate, caKey: pki.PrivateKey) {

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