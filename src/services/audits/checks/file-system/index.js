export const fileSystemChecks = [
  {
    id: 'fs-world-writable-files',
    auditId: 'file-system',
    title: 'No world-writable files outside /tmp',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    command:
      "find / -xdev -type f -perm -0002 -not -path '/tmp/*' -not -path '/var/tmp/*' -not -path '/proc/*' -not -path '/dev/*' -not -path '/sys/*' 2>/dev/null | head -50 | wc -l",
    evaluate: (out) => {
      const n = Number(out.trim());
      if (Number.isNaN(n)) return { status: 'ERROR', detail: 'Could not parse output.' };
      if (n === 0) return { status: 'PASS', detail: 'No world-writable files found.' };
      if (n < 5) return { status: 'WARNING', detail: `${n} world-writable file(s) found.` };
      return { status: 'FAIL', detail: `${n}+ world-writable files found (capped sample).` };
    },
  },
  {
    id: 'fs-world-writable-dirs',
    auditId: 'file-system',
    title: 'No sticky-bit-missing world-writable dirs in /',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    command:
      "find / -xdev -type d -perm -0002 ! -perm -1000 -not -path '/tmp' -not -path '/var/tmp' -not -path '/dev/*' -not -path '/proc/*' 2>/dev/null | head -30 | wc -l",
    evaluate: (out) => {
      const n = Number(out.trim());
      if (Number.isNaN(n)) return { status: 'ERROR', detail: 'Could not parse output.' };
      if (n === 0) return { status: 'PASS', detail: 'No unsafe world-writable directories.' };
      return {
        status: 'FAIL',
        detail: `${n} world-writable director(ies) without sticky bit.`,
      };
    },
  },
  {
    id: 'fs-suid-binaries',
    auditId: 'file-system',
    title: 'SUID binary count is reasonable',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    command:
      "find / -xdev -type f -perm -4000 2>/dev/null | head -200 | wc -l",
    evaluate: (out) => {
      const n = Number(out.trim());
      if (Number.isNaN(n)) return { status: 'ERROR', detail: 'Could not parse output.' };
      if (n <= 50) return { status: 'PASS', detail: `${n} SUID binaries (sample).` };
      if (n <= 100) {
        return { status: 'WARNING', detail: `${n} SUID binaries — review unexpected ones.` };
      }
      return { status: 'FAIL', detail: `${n} SUID binaries is unusually high.` };
    },
  },
  {
    id: 'fs-shadow-perms',
    auditId: 'file-system',
    title: '/etc/shadow is not world-readable',
    severity: 'CRITICAL',
    weight: 10,
    requiresSudo: true,
    applicability: { command: 'test -f /etc/shadow && echo yes || echo no', expect: 'yes' },
    command: "stat -c '%a %U:%G' /etc/shadow 2>/dev/null || stat -f '%OLp %Su:%Sg' /etc/shadow 2>/dev/null",
    evaluate: (out) => {
      const mode = out.trim().split(/\s+/)[0];
      if (!mode) return { status: 'ERROR', detail: 'Could not read /etc/shadow mode.' };
      const n = parseInt(mode, 8);
      if (Number.isNaN(n)) {
        return { status: 'WARNING', detail: `Unexpected mode output: ${out.trim()}` };
      }
      if (n & 0o007) {
        return { status: 'FAIL', detail: `/etc/shadow mode ${mode} is too open.` };
      }
      return { status: 'PASS', detail: `/etc/shadow mode ${mode}.` };
    },
    remediation: {
      summary: 'chmod 640 /etc/shadow && chown root:shadow /etc/shadow (or root:root).',
      command: 'chmod 640 /etc/shadow',
    },
  },
  {
    id: 'fs-passwd-perms',
    auditId: 'file-system',
    title: '/etc/passwd is not writable by others',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: false,
    command: "stat -c '%a' /etc/passwd 2>/dev/null || stat -f '%OLp' /etc/passwd 2>/dev/null",
    evaluate: (out) => {
      const mode = out.trim();
      const n = parseInt(mode, 8);
      if (Number.isNaN(n)) return { status: 'ERROR', detail: 'Could not parse mode.' };
      if (n & 0o022) {
        return { status: 'FAIL', detail: `/etc/passwd mode ${mode} is group/world writable.` };
      }
      return { status: 'PASS', detail: `/etc/passwd mode ${mode}.` };
    },
  },
  {
    id: 'fs-home-dot-ssh',
    auditId: 'file-system',
    title: '~/.ssh directories are not group/world accessible',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    command:
      "find /home /root -xdev -type d -name '.ssh' 2>/dev/null | while read d; do echo \"$d $(stat -c '%a' \"$d\" 2>/dev/null)\"; done | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) {
        return { status: 'SKIP', detail: 'No .ssh directories found under /home or /root.' };
      }
      const bad = lines.filter((l) => {
        const mode = Number(l.trim().split(/\s+/).pop());
        return !Number.isNaN(mode) && mode > 700;
      });
      if (bad.length) {
        return { status: 'FAIL', detail: `Over-permissive .ssh dirs:\n${bad.join('\n')}` };
      }
      return { status: 'PASS', detail: `Checked ${lines.length} .ssh director(ies).` };
    },
    remediation: {
      summary: 'chmod 700 on each user .ssh directory.',
    },
  },
  {
    id: 'fs-tmp-sticky',
    auditId: 'file-system',
    title: '/tmp has sticky bit',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: false,
    command: "stat -c '%a' /tmp 2>/dev/null || stat -f '%OLp' /tmp 2>/dev/null",
    evaluate: (out) => {
      const mode = out.trim();
      if (!mode) return { status: 'ERROR', detail: 'Could not stat /tmp.' };
      if (mode.length >= 4 && mode[0] === '1') {
        return { status: 'PASS', detail: `/tmp mode ${mode}.` };
      }
      const n = parseInt(mode, 8);
      if (!Number.isNaN(n) && n & 0o1000) {
        return { status: 'PASS', detail: `/tmp mode ${mode}.` };
      }
      return { status: 'FAIL', detail: `/tmp mode ${mode} lacks sticky bit.` };
    },
    remediation: {
      summary: 'chmod 1777 /tmp',
      command: 'chmod 1777 /tmp',
    },
  },
];
