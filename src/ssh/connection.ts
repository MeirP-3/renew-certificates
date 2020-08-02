import { Client } from 'ssh2';
import { promises as fs } from 'fs';
import { homedir } from 'os';
import path from 'path';

interface ConnectionConfig {
  username: string
  bastion: string
  host: string
}

export const connectThroughBastion:
  (config: ConnectionConfig) => Promise<Client>
  = async ({
    username,
    bastion,
    host
  }) => {

    const privateKey = await fs.readFile(path.join(homedir(), '.ssh', 'id_rsa'));

    return new Promise((resolve, reject) => {

      const c1 = new Client();
      const c2 = new Client();

      c1.connect({
        host: bastion,
        username,
        privateKey
      });

      c1.on('ready', () => {

        c1.forwardOut(bastion, 22, host, 22, (err, stream) => {
          if (err) {
            c1.end();
            return reject(err);
          }

          c2.connect({
            sock: stream,
            username,
            privateKey
          });
        });

      });

      c2.on('end', () => {
        c1.end();
      })

      c2.on('ready', () => {
        resolve(c2);
      });
    });
  }