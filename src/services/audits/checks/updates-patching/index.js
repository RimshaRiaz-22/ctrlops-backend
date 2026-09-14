export const updatesPatchingChecks = [
  {
    id: 'upd-pending-security',
    auditId: 'updates-patching',
    title: 'Pending security updates are manageable',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    commands: {
      debian: '(apt-get -s upgrade 2>/dev/null | grep -i security | wc -l) || echo 0',
      rhel:
        '(dnf updateinfo list security 2>/dev/null | grep -cE "Important|Critical|Moderate" || yum updateinfo list security 2>/dev/null | grep -cE "Important|Critical" || echo 0)',
      _fallback: 'echo UNKNOWN',
    },
    evaluate: (out, _e, _c, env) => {
      const t = out.trim();
      if (t === 'UNKNOWN') {
        return {
          status: 'SKIP',
          detail: `No package manager probe for family ${env?.family ?? 'unknown'}.`,
        };
      }
      const n = Number(t.split('\n').pop());
      if (Number.isNaN(n)) {
        return { status: 'WARNING', detail: `Could not parse update count: ${t.slice(0, 80)}` };
      }
      if (n === 0) return { status: 'PASS', detail: 'No pending security update lines detected.' };
      if (n < 10) {
        return { status: 'WARNING', detail: `~${n} security-related update line(s).` };
      }
      return { status: 'FAIL', detail: `~${n} security-related update line(s) pending.` };
    },
    remediation: {
      summary: 'Apply security updates (apt upgrade / dnf update).',
    },
  },
  {
    id: 'upd-unattended-upgrades',
    auditId: 'updates-patching',
    title: 'Automatic security updates enabled (Debian family)',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: false,
    command:
      'if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then cat /etc/apt/apt.conf.d/20auto-upgrades; elif dpkg -l unattended-upgrades 2>/dev/null | grep -q ^ii; then echo INSTALLED_NO_AUTO; else echo MISSING; fi',
    evaluate: (out, _e, _c, env) => {
      if (env?.family && env.family !== 'debian') {
        return {
          status: 'SKIP',
          detail: 'unattended-upgrades check applies to Debian-family hosts.',
        };
      }
      const t = out.trim();
      if (t.includes('MISSING')) {
        return { status: 'FAIL', detail: 'unattended-upgrades not configured.' };
      }
      if (
        /APT::Periodic::Unattended-Upgrade\s+"1"/.test(t) ||
        /Unattended-Upgrade\s+"1"/.test(t)
      ) {
        return { status: 'PASS', detail: 'Automatic unattended upgrades appear enabled.' };
      }
      if (t.includes('INSTALLED_NO_AUTO')) {
        return {
          status: 'WARNING',
          detail: 'Package installed but auto-upgrade config not found.',
        };
      }
      return { status: 'WARNING', detail: `Config present but unclear:\n${t.slice(0, 120)}` };
    },
  },
  {
    id: 'upd-reboot-required',
    auditId: 'updates-patching',
    title: 'No pending reboot for kernel updates',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: false,
    command:
      'if [ -f /var/run/reboot-required ]; then echo YES; cat /var/run/reboot-required.pkgs 2>/dev/null | head -5; else echo NO; fi',
    evaluate: (out) => {
      if (out.trim().startsWith('NO')) {
        return { status: 'PASS', detail: 'No reboot-required flag.' };
      }
      return {
        status: 'WARNING',
        detail: 'Reboot required after package updates.\n' + out.trim().slice(0, 200),
      };
    },
  },
  {
    id: 'upd-package-manager-present',
    auditId: 'updates-patching',
    title: 'Package manager is available',
    severity: 'INFO',
    weight: 2,
    requiresSudo: false,
    command:
      'command -v apt-get || command -v dnf || command -v yum || command -v zypper || echo NONE',
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) {
        return { status: 'FAIL', detail: 'No common package manager found.' };
      }
      return { status: 'PASS', detail: `Found: ${out.trim().split('\n')[0]}` };
    },
  },
];
