export const firewallNetworkChecks = [
  {
    id: 'fw-enabled',
    auditId: 'firewall-network',
    title: 'Host firewall is active',
    severity: 'HIGH',
    weight: 9,
    requiresSudo: true,
    commands: {
      debian: 'ufw status 2>/dev/null | head -1',
      rhel: 'firewall-cmd --state 2>/dev/null',
      _fallback:
        'nft list ruleset 2>/dev/null | head -5 || iptables -L -n 2>/dev/null | head -5',
    },
    evaluate: (out, _err, _code, env) => {
      const t = out.trim().toLowerCase();
      if (env?.family === 'debian') {
        if (/\binactive\b/.test(t) || t.includes('not running')) {
          return { status: 'FAIL', detail: 'ufw is inactive.' };
        }
        if (/\bactive\b/.test(t) && !/\binactive\b/.test(t)) {
          return { status: 'PASS', detail: 'ufw is active.' };
        }
        return { status: 'FAIL', detail: 'ufw status unclear or missing.' };
      }
      if (env?.family === 'rhel') {
        return t === 'running'
          ? { status: 'PASS', detail: 'firewalld is running.' }
          : { status: 'FAIL', detail: 'firewalld is not running.' };
      }
      return t.length > 0
        ? {
            status: 'WARNING',
            detail: 'Raw firewall rules present; could not confirm a managed firewall.',
          }
        : { status: 'FAIL', detail: 'No active firewall detected.' };
    },
    remediation: {
      summary: 'Enable ufw (Debian) or firewalld (RHEL) and allow only needed ports.',
    },
  },
  {
    id: 'fw-ssh-open',
    auditId: 'firewall-network',
    title: 'SSH port is listening',
    severity: 'INFO',
    weight: 2,
    requiresSudo: false,
    command: "ss -tln 2>/dev/null | grep -E ':22\\s' || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) {
        return {
          status: 'WARNING',
          detail: 'Nothing listening on :22 — confirm alternate SSH port or access path.',
        };
      }
      return { status: 'PASS', detail: 'SSH appears to be listening.' };
    },
  },
  {
    id: 'fw-risky-ports',
    auditId: 'firewall-network',
    title: 'Risky management ports not publicly bound',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    command:
      "ss -tln 2>/dev/null | grep -E ':(23|21|3389|5900|11211|9200|5601)\\s' || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) {
        return { status: 'PASS', detail: 'No common risky management ports listening.' };
      }
      const publicLines = out
        .trim()
        .split('\n')
        .filter((l) => /0\.0\.0\.0:|:::/.test(l));
      if (publicLines.length) {
        return {
          status: 'FAIL',
          detail: `Risky ports publicly bound:\n${publicLines.slice(0, 5).join('\n')}`,
        };
      }
      return {
        status: 'WARNING',
        detail: 'Risky ports listening (may be localhost-only):\n' + out.trim().slice(0, 200),
      };
    },
  },
  {
    id: 'fw-ip-forward',
    auditId: 'firewall-network',
    title: 'IP forwarding disabled unless intentional',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: false,
    command: 'sysctl -n net.ipv4.ip_forward 2>/dev/null || cat /proc/sys/net/ipv4/ip_forward',
    evaluate: (out) => {
      const v = out.trim();
      if (v === '0') return { status: 'PASS', detail: 'IPv4 forwarding disabled.' };
      if (v === '1') {
        return {
          status: 'WARNING',
          detail: 'IPv4 forwarding enabled — expected for routers/Docker hosts only.',
        };
      }
      return { status: 'ERROR', detail: `Unexpected value: ${v}` };
    },
  },
  {
    id: 'fw-docker-iptables',
    auditId: 'firewall-network',
    title: 'Docker does not silently bypass host firewall awareness',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: {
      command: 'command -v docker >/dev/null && echo yes || echo no',
      expect: 'yes',
    },
    command:
      "docker info 2>/dev/null | grep -i 'FirewallBackend\\|iptables' | head -5; iptables -L DOCKER-USER -n 2>/dev/null | head -5 || echo 'NO_DOCKER_USER'",
    evaluate: (out) => {
      if (out.includes('NO_DOCKER_USER') && !/iptables/i.test(out)) {
        return {
          status: 'WARNING',
          detail: 'Docker present but DOCKER-USER chain not visible — review published ports.',
        };
      }
      return {
        status: 'PASS',
        detail: 'Docker networking info captured; review published ports separately.',
      };
    },
  },
  {
    id: 'fw-syn-cookies',
    auditId: 'firewall-network',
    title: 'TCP SYN cookies enabled',
    severity: 'LOW',
    weight: 3,
    requiresSudo: false,
    command:
      'sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null',
    evaluate: (out) => {
      const v = out.trim();
      if (v === '1') return { status: 'PASS', detail: 'tcp_syncookies enabled.' };
      if (v === '0') return { status: 'FAIL', detail: 'tcp_syncookies disabled.' };
      return { status: 'WARNING', detail: `Unexpected tcp_syncookies value: ${v || 'empty'}` };
    },
    remediation: {
      summary: 'sysctl -w net.ipv4.tcp_syncookies=1 and persist in sysctl.conf',
      command: 'sysctl -w net.ipv4.tcp_syncookies=1',
    },
  },
];
