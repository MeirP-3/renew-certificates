import { promises as fs } from 'fs';
import { pki } from 'node-forge';
import path from 'path';
import YAML from 'yaml';
import { CaData, Config, HostStatus } from './typs';
import { errorHandler } from './utils/error-handler';
import { renewHost } from './utils/renew-host';


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

renewAll();
