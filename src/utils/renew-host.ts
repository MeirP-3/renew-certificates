import path from 'path';
import { CaData, HostStatus, CsrsByPath } from "../typs";
import { connectThroughBastion } from "../ssh/connection";
import { pki } from 'node-forge';
import { createCert } from './create-cert';


export async function renewHost({ caKey, caCert }: CaData, bastion: string, hostStatus: HostStatus) {

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
