/**
 * Parse OpenSSH ProxyCommand-style strings into bastion connection fields.
 * Supported: ssh -W %h:%p user@bastion [-p port]
 */
export function parseProxyCommand(proxyCommand) {
  if (!proxyCommand?.trim()) return null;

  const s = proxyCommand.trim();
  if (!/-W\s+%h:%p/i.test(s)) return null;

  const portMatch = s.match(/-p\s+(\d+)/);
  const userHostMatch = s.match(/([\w.-]+)@([\w.\-:]+)/);
  if (!userHostMatch) return null;

  const host = userHostMatch[2].split(':')[0];

  return {
    username: userHostMatch[1],
    host,
    port: portMatch ? Number(portMatch[1]) : 22,
  };
}
