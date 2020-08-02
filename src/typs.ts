
export interface HostConfig {
  host: string
  certs_dir: string
  user: string
}

export interface CaConfig {
  cert: string
  key: string
}

export interface Config {
  ca: CaConfig
  bastion: string
  hosts: HostConfig[]
}

export interface CertError {
  error: Error
  path?: string
}

export interface HostStatus extends HostConfig {
  status: 'pending' | 'connected' | 'completed' | 'error'
  errors: CertError[]
  certsByPath: {
    [path: string]: {
      cert: string
      csr: string
    }
  }
}

export interface CsrsByPath {
  [path: string]: {
    csr: string
  }
}

export interface CaData {
  caKey: pki.PrivateKey
  caCert: pki.Certificate
}
