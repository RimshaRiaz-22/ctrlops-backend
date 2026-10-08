const SSHD = '/etc/ssh/sshd_config';
const APP = {
  command: `test -f ${SSHD} && echo yes || echo no`,
  expect: 'yes',
};

function grepLine(directive) {
  return `grep -E '^\\s*${directive}\\b' ${SSHD} 2>/dev/null | tail -1`;
}

function valueOf(out) {
  const parts = out.trim().split(/\s+/);
  return parts[1]?.toLowerCase() ?? null;
}

export const sshHardeningChecks = [
  {
    id: 'ssh-root-login',
    auditId: 'ssh-hardening',
    title: 'Root SSH login disabled',
    description: 'Direct root login over SSH should be disabled.',
    severity: 'HIGH',
    weight: 9,
    requiresSudo: true,
    applicability: APP,
    command: grepLine('PermitRootLogin'),
    evaluate: (out) => {
      const v = valueOf(out);
      if (!v) {
        return {
          status: 'WARNING',
          detail: 'PermitRootLogin not set. Confirm distro default is not yes.',
        };
      }
      if (v === 'no' || v === 'prohibit-password' || v === 'without-password') {
        return { status: 'PASS', detail: `PermitRootLogin ${v}.` };
      }
      return { status: 'FAIL', detail: `PermitRootLogin is ${v}.` };
    },
    remediation: {
      summary: 'Set PermitRootLogin no, then reload sshd.',
      command: `sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' ${SSHD} && systemctl reload sshd`,
    },
  },
  {
    id: 'ssh-password-auth',
    auditId: 'ssh-hardening',
    title: 'Password authentication disabled',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: APP,
    command: grepLine('PasswordAuthentication'),
    evaluate: (out) => {
      const v = valueOf(out);
      if (!v) {
        return {
          status: 'WARNING',
          detail: 'Not set. sshd defaults to yes, so passwords are accepted.',
        };
      }
      return v === 'no'
        ? { status: 'PASS', detail: 'Key-based authentication only.' }
        : { status: 'FAIL', detail: 'Password authentication is enabled.' };
    },
    remediation: {
      summary: 'Set PasswordAuthentication no, then reload sshd.',
      command: `sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' ${SSHD} && systemctl reload sshd`,
    },
  },
  {
    id: 'ssh-permit-empty-passwords',
    auditId: 'ssh-hardening',
    title: 'Empty passwords disallowed',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: APP,
    command: grepLine('PermitEmptyPasswords'),
    evaluate: (out) => {
      const v = valueOf(out);
      if (!v || v === 'no') {
        return { status: 'PASS', detail: 'Empty passwords are not accepted.' };
      }
      return { status: 'FAIL', detail: 'PermitEmptyPasswords is yes.' };
    },
    remediation: {
      summary: 'Set PermitEmptyPasswords no.',
      command: `sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' ${SSHD} && systemctl reload sshd`,
    },
  },
  {
    id: 'ssh-max-auth-tries',
    auditId: 'ssh-hardening',
    title: 'MaxAuthTries is limited',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: APP,
    command: grepLine('MaxAuthTries'),
    evaluate: (out) => {
      const v = valueOf(out);
      if (!v) {
        return {
          status: 'WARNING',
          detail: 'MaxAuthTries not set (default is often 6). Prefer ≤4.',
        };
      }
      const n = Number(v);
      if (Number.isNaN(n)) return { status: 'ERROR', detail: 'Could not parse MaxAuthTries.' };
      if (n <= 4) return { status: 'PASS', detail: `MaxAuthTries ${n}.` };
      return { status: 'FAIL', detail: `MaxAuthTries is ${n}; prefer ≤4.` };
    },
    remediation: {
      summary: 'Set MaxAuthTries 4.',
      command: `sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' ${SSHD} && systemctl reload sshd`,
    },
  },
  {
    id: 'ssh-client-alive',
    auditId: 'ssh-hardening',
    title: 'Idle session timeout configured',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: APP,
    command: `${grepLine('ClientAliveInterval')}; ${grepLine('ClientAliveCountMax')}`,
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      const intervalLine = lines.find((l) => /ClientAliveInterval/i.test(l));
      const countLine = lines.find((l) => /ClientAliveCountMax/i.test(l));
      const interval = intervalLine ? Number(intervalLine.trim().split(/\s+/)[1]) : null;
      const count = countLine ? Number(countLine.trim().split(/\s+/)[1]) : null;
      if (!interval || interval <= 0) {
        return {
          status: 'WARNING',
          detail: 'ClientAliveInterval not set; idle sessions may hang indefinitely.',
        };
      }
      const maxIdle = interval * (count && count > 0 ? count : 3);
      if (maxIdle <= 900) {
        return { status: 'PASS', detail: `Idle disconnect ~${maxIdle}s.` };
      }
      return {
        status: 'WARNING',
        detail: `Idle disconnect ~${maxIdle}s is longer than 15 minutes.`,
      };
    },
    remediation: {
      summary: 'Set ClientAliveInterval 300 and ClientAliveCountMax 2.',
      command: `printf '\\nClientAliveInterval 300\\nClientAliveCountMax 2\\n' >> ${SSHD} && systemctl reload sshd`,
    },
  },
  {
    id: 'ssh-x11-forwarding',
    auditId: 'ssh-hardening',
    title: 'X11 forwarding disabled',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: APP,
    command: grepLine('X11Forwarding'),
    evaluate: (out) => {
      const v = valueOf(out);
      if (!v || v === 'no') {
        return { status: 'PASS', detail: 'X11 forwarding is disabled.' };
      }
      return { status: 'WARNING', detail: 'X11Forwarding is enabled.' };
    },
    remediation: {
      summary: 'Set X11Forwarding no.',
      command: `sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' ${SSHD} && systemctl reload sshd`,
    },
  },
  {
    id: 'ssh-protocol',
    auditId: 'ssh-hardening',
    title: 'SSH protocol is modern',
    severity: 'MEDIUM',
    weight: 4,
    requiresSudo: true,
    applicability: APP,
    command: `${grepLine('Protocol')}; sshd -T 2>/dev/null | grep -i '^protocol ' || true`,
    evaluate: (out) => {
      const t = out.toLowerCase();
      if (t.includes('protocol 1') && !t.includes('protocol 2')) {
        return { status: 'FAIL', detail: 'SSH protocol 1 appears enabled.' };
      }
      if (!t.includes('protocol')) {
        return {
          status: 'PASS',
          detail: 'Protocol directive absent (OpenSSH 7+ is protocol 2 only).',
        };
      }
      return { status: 'PASS', detail: 'SSH protocol configuration looks modern.' };
    },
  },
];
