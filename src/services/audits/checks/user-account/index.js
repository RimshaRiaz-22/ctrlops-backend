export const userAccountChecks = [
  {
    id: 'user-empty-password-hashes',
    auditId: 'user-account',
    title: 'No unlocked empty password fields in shadow',
    severity: 'CRITICAL',
    weight: 10,
    requiresSudo: true,
    applicability: { command: 'test -r /etc/shadow && echo yes || echo no', expect: 'yes' },
    command: "awk -F: '($2==\"\") {print $1}' /etc/shadow 2>/dev/null | head -20",
    evaluate: (out) => {
      const users = out.trim().split('\n').filter(Boolean);
      if (!users.length) {
        return { status: 'PASS', detail: 'No empty password hashes in shadow.' };
      }
      return {
        status: 'FAIL',
        detail: `Accounts with empty password hash: ${users.join(', ')}`,
      };
    },
    remediation: {
      summary: 'Lock or set passwords for listed accounts (passwd -l).',
    },
  },
  {
    id: 'user-duplicate-uids',
    auditId: 'user-account',
    title: 'No duplicate UIDs in /etc/passwd',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: false,
    command: 'cut -d: -f3 /etc/passwd | sort | uniq -d | head -10',
    evaluate: (out) => {
      const dups = out.trim().split('\n').filter(Boolean);
      if (!dups.length) return { status: 'PASS', detail: 'No duplicate UIDs.' };
      return { status: 'FAIL', detail: `Duplicate UIDs: ${dups.join(', ')}` };
    },
  },
  {
    id: 'user-uid0-accounts',
    auditId: 'user-account',
    title: 'Only root has UID 0',
    severity: 'CRITICAL',
    weight: 10,
    requiresSudo: false,
    command: "awk -F: '($3==0) {print $1}' /etc/passwd",
    evaluate: (out) => {
      const names = out.trim().split('\n').filter(Boolean);
      if (names.length === 1 && names[0] === 'root') {
        return { status: 'PASS', detail: 'Only root has UID 0.' };
      }
      return { status: 'FAIL', detail: `UID 0 accounts: ${names.join(', ')}` };
    },
  },
  {
    id: 'user-sudo-group',
    auditId: 'user-account',
    title: 'Sudo/wheel group membership is limited',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: false,
    command:
      "getent group sudo wheel 2>/dev/null | head -5; echo '---'; grep -E '^%sudo|^%wheel|^root' /etc/sudoers 2>/dev/null | head -10 || true",
    evaluate: (out) => {
      const memberLine = out.split('\n').find((l) => /^(sudo|wheel):/.test(l));
      if (!memberLine) {
        return {
          status: 'WARNING',
          detail: 'Could not read sudo/wheel group membership.',
        };
      }
      const members = (memberLine.split(':')[3] || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      if (members.length > 5) {
        return {
          status: 'WARNING',
          detail: `${members.length} sudoers in group — review least privilege.`,
        };
      }
      return {
        status: 'PASS',
        detail: `Sudo-capable group members: ${members.length || 0}.`,
      };
    },
  },
  {
    id: 'user-password-aging',
    auditId: 'user-account',
    title: 'Password max age configured for human accounts',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: { command: 'test -f /etc/login.defs && echo yes || echo no', expect: 'yes' },
    command: "grep -E '^PASS_MAX_DAYS' /etc/login.defs | tail -1",
    evaluate: (out) => {
      const m = out.trim().match(/PASS_MAX_DAYS\s+(\d+)/i);
      if (!m) {
        return { status: 'WARNING', detail: 'PASS_MAX_DAYS not set in login.defs.' };
      }
      const days = Number(m[1]);
      if (days === 99999 || days > 365) {
        return {
          status: 'WARNING',
          detail: `PASS_MAX_DAYS=${days} effectively disables aging.`,
        };
      }
      if (days > 90) {
        return { status: 'WARNING', detail: `PASS_MAX_DAYS=${days} — prefer ≤90.` };
      }
      return { status: 'PASS', detail: `PASS_MAX_DAYS=${days}.` };
    },
  },
  {
    id: 'user-nopasswd-sudo',
    auditId: 'user-account',
    title: 'NOPASSWD sudo is not broadly granted',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    command:
      "grep -RIn 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^#' | head -20 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) {
        return { status: 'PASS', detail: 'No NOPASSWD entries found.' };
      }
      const broad = out
        .trim()
        .split('\n')
        .filter((l) => /NOPASSWD:\s*ALL/i.test(l));
      if (broad.length) {
        return {
          status: 'FAIL',
          detail: `Broad NOPASSWD grants:\n${broad.slice(0, 5).join('\n')}`,
        };
      }
      return {
        status: 'WARNING',
        detail: 'NOPASSWD entries present — review for least privilege.',
      };
    },
  },
];
