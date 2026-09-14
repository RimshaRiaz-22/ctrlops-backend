import net from 'net';
import dns from 'node:dns/promises';
import { env } from '../config/env.js';
import { parseProxyCommand } from './parseProxyCommand.js';

export function hostBlockedError(message) {
  return {
    code: 'HOST_BLOCKED',
    message:
      message ??
      'This host address is not allowed. Private, loopback, and cloud metadata IPs are blocked.',
    hint: 'Use a public host, or set ALLOW_PRIVATE_IPS=true for local development.',
  };
}

export function normalizeHost(host) {
  const hostname = String(host || '')
    .trim()
    .replace(/^\[|\]$/g, '')
    .split('%')[0];

  if (net.isIPv6(hostname) || hostname.includes(':') === false) {
    return hostname;
  }

  if (hostname.includes('.')) {
    return hostname.split(':')[0];
  }

  return hostname;
}

export function isPrivateOrBlocked(ip) {
  if (!ip) return true;

  const normalized = ip.toLowerCase().replace(/^\[|\]$/g, '');

  if (
    normalized === 'localhost' ||
    normalized === '::1' ||
    normalized === '0.0.0.0' ||
    normalized === '::'
  ) {
    return true;
  }

  if (net.isIPv4(normalized)) {
    const parts = normalized.split('.').map(Number);
    const [a, b] = parts;

    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;

    return false;
  }

  if (net.isIPv6(normalized)) {
    if (normalized === '::1') return true;
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
    if (normalized.startsWith('fe80')) return true;
    return false;
  }

  if (
    normalized.endsWith('.local') ||
    normalized.endsWith('.internal') ||
    normalized === 'metadata.google.internal'
  ) {
    return true;
  }

  return false;
}

/**
 * Returns an error object if host should be blocked, otherwise null.
 */
export function blockPrivateIp(host, { allowPrivateIps = env.ALLOW_PRIVATE_IPS } = {}) {
  if (allowPrivateIps) return null;

  const bare = normalizeHost(host);

  if (isPrivateOrBlocked(bare) || bare === '169.254.169.254') {
    return hostBlockedError();
  }

  return null;
}

export async function assertResolvedNotPrivate(
  host,
  { allowPrivateIps = env.ALLOW_PRIVATE_IPS, lookup = dns.lookup } = {},
) {
  if (allowPrivateIps) return null;

  const bare = normalizeHost(host);
  if (!bare) return hostBlockedError();
  if (net.isIP(bare)) {
    return isPrivateOrBlocked(bare) ? hostBlockedError() : null;
  }

  try {
    const results = await lookup(bare, { all: true });
    const addrs = Array.isArray(results) ? results : [results];
    for (const entry of addrs) {
      const address = entry?.address ?? entry;
      if (isPrivateOrBlocked(address)) {
        return hostBlockedError(
          'This hostname resolves to a private, loopback, or cloud metadata address.',
        );
      }
    }
  } catch {
    return null;
  }

  return null;
}

/**
 * Block target and bastion hosts (literal + DNS) before opening SSH.
 */
export async function assertSshTargetsAllowed(
  host,
  { proxyCommand, allowPrivateIps = env.ALLOW_PRIVATE_IPS, lookup } = {},
) {
  const targetBlocked = blockPrivateIp(host, { allowPrivateIps });
  if (targetBlocked) return targetBlocked;

  const targetDns = await assertResolvedNotPrivate(host, { allowPrivateIps, lookup });
  if (targetDns) return targetDns;

  const bastion = parseProxyCommand(proxyCommand);
  if (!bastion?.host) return null;

  const bastionBlocked = blockPrivateIp(bastion.host, { allowPrivateIps });
  if (bastionBlocked) {
    return hostBlockedError(
      'This bastion address is not allowed. Private, loopback, and cloud metadata IPs are blocked.',
    );
  }

  return assertResolvedNotPrivate(bastion.host, { allowPrivateIps, lookup });
}
