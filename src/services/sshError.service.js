import { AppError } from '../middleware/errorHandler.js';

export function mapSshError(err) {
  const message = err?.message ?? '';
  const code = err?.code ?? '';
  const level = err?.level ?? '';

  if (
    message.includes('public key') ||
    message.includes('PUBLIC_KEY_SUPPLIED') ||
    code === 'PUBLIC_KEY_SUPPLIED'
  ) {
    return {
      code: 'PUBLIC_KEY_SUPPLIED',
      message:
        'This looks like a public key. Use the private key (the file without .pub).',
      hint: 'Open the private key file — it should start with -----BEGIN ... PRIVATE KEY-----.',
    };
  }

  if (
    /Cannot parse privateKey/i.test(message) ||
    /parsing private key/i.test(message) ||
    /Unsupported key format/i.test(message)
  ) {
    return {
      code: 'KEY_PARSE_ERROR',
      message:
        "This key file couldn't be read. Make sure it's an OpenSSH or PEM private key, not a .pub public key.",
      hint: 'Confirm the file starts with -----BEGIN and contains PRIVATE KEY.',
    };
  }

  if (
    /Encrypted private key detected, but no passphrase/i.test(message) ||
    /no passphrase given/i.test(message)
  ) {
    return {
      code: 'PASSPHRASE_REQUIRED',
      message: 'This key is passphrase-protected. Enter the passphrase.',
      hint: 'Toggle passphrase / password-protected key and try again.',
    };
  }

  if (
    /bad decrypt/i.test(message) ||
    /incorrect passphrase/i.test(message) ||
    /Integrity check failed/i.test(message) ||
    /Wrong passphrase/i.test(message)
  ) {
    return {
      code: 'PASSPHRASE_WRONG',
      message: 'The passphrase for this key is incorrect.',
      hint: 'Double-check the passphrase and try again.',
    };
  }

  if (
    code === 'HOST_KEY_MISMATCH' ||
    /Host key verification failed/i.test(message) ||
    /host key/i.test(message) && /mismatch/i.test(message)
  ) {
    return {
      code: 'HOST_KEY_MISMATCH',
      message:
        "The server's identity has changed. This could be a reinstall — or an attack. Verify before continuing.",
      hint: 'Confirm the host was rebuilt intentionally before updating the stored fingerprint.',
    };
  }

  if (code === 'ECONNREFUSED' || /ECONNREFUSED/i.test(message)) {
    return {
      code: 'CONNECTION_REFUSED',
      message:
        'Nothing is listening on that port. Check the port and that SSH is running.',
      hint: 'Verify sshd is up and the security group / firewall allows the port.',
    };
  }

  if (
    code === 'ETIMEDOUT' ||
    code === 'ECONNABORTED' ||
    /Timed out while waiting for handshake/i.test(message) ||
    /Timed out/i.test(message) ||
    /timeout/i.test(message)
  ) {
    return {
      code: 'TIMEOUT',
      message:
        "Couldn't reach the host. Check the IP and your firewall or security group.",
      hint: 'Confirm the host is reachable from this API server and port 22 (or your custom port) is open.',
    };
  }

  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || /getaddrinfo/i.test(message)) {
    return {
      code: 'HOST_NOT_FOUND',
      message: "Hostname couldn't be resolved.",
      hint: 'Check the hostname spelling or use an IP address.',
    };
  }

  if (
    /All configured authentication methods failed/i.test(message) ||
    /Authentication failure/i.test(message) ||
    /Permission denied/i.test(message) ||
    level === 'client-authentication'
  ) {
    return {
      code: 'AUTH_FAILED',
      message:
        'Authentication failed. Check the username and that this key is authorised on the server.',
      hint: "Confirm the public key is in ~/.ssh/authorized_keys for the username you entered.",
    };
  }

  return {
    code: 'UNKNOWN',
    message: 'Connection failed. Check host, port, username, and credentials.',
    hint: message ? message.slice(0, 200) : undefined,
  };
}

const STATUS_BY_CODE = {
  TIMEOUT: 504,
  CONNECTION_REFUSED: 502,
  HOST_NOT_FOUND: 502,
  HOST_KEY_MISMATCH: 409,
  AUTH_FAILED: 401,
  PASSPHRASE_WRONG: 401,
  PASSPHRASE_REQUIRED: 401,
  PUBLIC_KEY_SUPPLIED: 400,
  KEY_PARSE_ERROR: 400,
};

export function sshErrorToAppError(err) {
  if (err instanceof AppError) return err;
  const mapped = mapSshError(err);
  return new AppError(
    mapped.code,
    STATUS_BY_CODE[mapped.code] ?? 502,
    mapped.message,
    mapped.hint,
  );
}
