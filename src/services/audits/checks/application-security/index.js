export const applicationSecurityChecks = [
  {
    id: 'app-tls-cert-expiry',
    auditId: 'application-security',
    title: 'TLS certificate not expired (common paths)',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    command:
      "for f in /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/letsencrypt/live/*/fullchain.pem /etc/nginx/ssl/*.crt /etc/httpd/ssl/*.crt; do [ -f \"$f\" ] || continue; end=$(openssl x509 -enddate -noout -in \"$f\" 2>/dev/null | cut -d= -f2); echo \"$f|$end\"; done | head -5; echo DONE",
    evaluate: (out) => {
      const lines = out
        .trim()
        .split('\n')
        .filter((l) => l.includes('|') && !l.startsWith('DONE'));
      if (!lines.length) {
        return {
          status: 'SKIP',
          detail: 'No common TLS certificate paths found to inspect.',
        };
      }
      const now = Date.now();
      for (const line of lines) {
        const end = line.split('|')[1];
        const t = Date.parse(end);
        if (!Number.isNaN(t) && t < now) {
          return { status: 'FAIL', detail: `Expired certificate: ${line}` };
        }
        if (!Number.isNaN(t) && t - now < 30 * 864e5) {
          return {
            status: 'WARNING',
            detail: `Certificate expires within 30 days: ${line}`,
          };
        }
      }
      return { status: 'PASS', detail: `Checked ${lines.length} certificate path(s).` };
    },
    remediation: {
      summary: 'Renew certificates before expiry (e.g. certbot renew).',
    },
  },
  {
    id: 'app-node-version',
    auditId: 'application-security',
    title: 'Node.js runtime is not ancient',
    severity: 'MEDIUM',
    weight: 4,
    requiresSudo: false,
    applicability: { command: 'command -v node >/dev/null && echo yes || echo no', expect: 'yes' },
    command: 'node -v 2>/dev/null',
    evaluate: (out) => {
      const m = out.trim().match(/v?(\d+)/);
      if (!m) return { status: 'ERROR', detail: 'Could not parse node version.' };
      const major = Number(m[1]);
      if (major < 18) {
        return { status: 'FAIL', detail: `Node ${out.trim()} is EOL / unsupported.` };
      }
      if (major < 20) {
        return { status: 'WARNING', detail: `Node ${out.trim()} — prefer current LTS.` };
      }
      return { status: 'PASS', detail: `Node ${out.trim()}.` };
    },
  },
  {
    id: 'app-python-version',
    auditId: 'application-security',
    title: 'Python runtime is not EOL',
    severity: 'MEDIUM',
    weight: 4,
    requiresSudo: false,
    applicability: {
      command: 'command -v python3 >/dev/null && echo yes || echo no',
      expect: 'yes',
    },
    command: 'python3 -V 2>&1',
    evaluate: (out) => {
      const m = out.match(/Python\s+(\d+)\.(\d+)/i);
      if (!m) return { status: 'ERROR', detail: 'Could not parse python version.' };
      const major = Number(m[1]);
      const minor = Number(m[2]);
      if (major < 3 || (major === 3 && minor < 9)) {
        return { status: 'FAIL', detail: `${out.trim()} is past support.` };
      }
      if (major === 3 && minor < 11) {
        return { status: 'WARNING', detail: `${out.trim()} — prefer 3.11+.` };
      }
      return { status: 'PASS', detail: out.trim() };
    },
  },
  {
    id: 'app-db-listening-localhost',
    auditId: 'application-security',
    title: 'Database ports not exposed on all interfaces',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    command:
      "ss -tln 2>/dev/null | grep -E ':(3306|5432|27017|6379)\\s' || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) {
        return { status: 'PASS', detail: 'No common DB ports listening.' };
      }
      const lines = out.trim().split('\n').filter(Boolean);
      const publicBind = lines.filter(
        (l) => /0\.0\.0\.0:|:::|\[::\]:/.test(l) && !/127\.0\.0\.1:|\[::1\]:/.test(l),
      );
      if (publicBind.length) {
        return {
          status: 'FAIL',
          detail: `Database port bound publicly:\n${publicBind.slice(0, 3).join('\n')}`,
        };
      }
      return { status: 'PASS', detail: 'DB listeners appear localhost-only or absent.' };
    },
    remediation: {
      summary: 'Bind databases to 127.0.0.1 or protect with firewall rules.',
    },
  },
  {
    id: 'app-world-readable-env',
    auditId: 'application-security',
    title: 'No world-readable .env under /var/www or /home',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    command:
      "find /var/www /home -xdev -name '.env' -type f -perm -0004 2>/dev/null | head -20 | wc -l",
    evaluate: (out) => {
      const n = Number(out.trim());
      if (Number.isNaN(n)) return { status: 'ERROR', detail: 'Could not parse output.' };
      if (n === 0) return { status: 'PASS', detail: 'No world-readable .env files found.' };
      return {
        status: 'FAIL',
        detail: `${n} world-readable .env file(s) under /var/www or /home.`,
      };
    },
    remediation: {
      summary: 'chmod 600 on .env files and restrict ownership.',
      command: "find /var/www /home -xdev -name '.env' -type f -perm -0004 -exec chmod 600 {} \\;",
    },
  },
];
