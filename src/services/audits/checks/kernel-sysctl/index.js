export const kernelSysctlChecks = [
  {
    id: 'sysctl-ip-forward',
    auditId: 'kernel-sysctl',
    title: 'IPv4 forwarding disabled by default',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: false,
    command: 'cat /proc/sys/net/ipv4/ip_forward 2>/dev/null',
    evaluate: (out) => {
      const v = out.trim();
      if (v === '0') return { status: 'PASS', detail: 'ip_forward=0.' };
      if (v === '1') {
        return {
          status: 'WARNING',
          detail: 'ip_forward=1 — expected only for routers/NAT hosts.',
        };
      }
      return { status: 'ERROR', detail: `Unexpected: ${v}` };
    },
  },
  {
    id: 'sysctl-accept-source-route',
    auditId: 'kernel-sysctl',
    title: 'Source routing disabled',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: false,
    command:
      'cat /proc/sys/net/ipv4/conf/all/accept_source_route 2>/dev/null; echo; cat /proc/sys/net/ipv4/conf/default/accept_source_route 2>/dev/null',
    evaluate: (out) => {
      const vals = out
        .trim()
        .split(/\s+/)
        .filter((x) => x === '0' || x === '1');
      if (!vals.length) return { status: 'ERROR', detail: 'Could not read accept_source_route.' };
      if (vals.every((v) => v === '0')) {
        return { status: 'PASS', detail: 'accept_source_route disabled.' };
      }
      return { status: 'FAIL', detail: `accept_source_route values: ${vals.join(',')}` };
    },
    remediation: {
      summary: 'sysctl -w net.ipv4.conf.all.accept_source_route=0',
      command: 'sysctl -w net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0',
    },
  },
  {
    id: 'sysctl-aslr',
    auditId: 'kernel-sysctl',
    title: 'ASLR is fully enabled',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: false,
    command: 'cat /proc/sys/kernel/randomize_va_space 2>/dev/null',
    evaluate: (out) => {
      const v = out.trim();
      if (v === '2') return { status: 'PASS', detail: 'randomize_va_space=2.' };
      if (v === '1') {
        return { status: 'WARNING', detail: 'ASLR partially enabled (1); prefer 2.' };
      }
      if (v === '0') return { status: 'FAIL', detail: 'ASLR disabled.' };
      return { status: 'ERROR', detail: `Unexpected: ${v}` };
    },
    remediation: {
      summary: 'sysctl -w kernel.randomize_va_space=2',
      command: 'sysctl -w kernel.randomize_va_space=2',
    },
  },
  {
    id: 'sysctl-kptr-restrict',
    auditId: 'kernel-sysctl',
    title: 'Kernel pointer restriction enabled',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: false,
    command: 'cat /proc/sys/kernel/kptr_restrict 2>/dev/null',
    evaluate: (out) => {
      const v = out.trim();
      if (v === '1' || v === '2') {
        return { status: 'PASS', detail: `kptr_restrict=${v}.` };
      }
      if (v === '0') {
        return { status: 'WARNING', detail: 'kptr_restrict=0 exposes kernel pointers.' };
      }
      return { status: 'ERROR', detail: `Unexpected: ${v}` };
    },
  },
  {
    id: 'sysctl-core-dumps',
    auditId: 'kernel-sysctl',
    title: 'Core dumps restricted for setuid',
    severity: 'MEDIUM',
    weight: 4,
    requiresSudo: false,
    command: 'cat /proc/sys/fs/suid_dumpable 2>/dev/null',
    evaluate: (out) => {
      const v = out.trim();
      if (v === '0') return { status: 'PASS', detail: 'suid_dumpable=0.' };
      if (v === '1' || v === '2') {
        return {
          status: 'WARNING',
          detail: `suid_dumpable=${v} may leak sensitive memory in dumps.`,
        };
      }
      return { status: 'ERROR', detail: `Unexpected: ${v}` };
    },
  },
];
