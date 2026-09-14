/** Shared applicability probes for web stacks */
export const HAS_NGINX = {
  command: 'command -v nginx >/dev/null && echo yes || echo no',
  expect: 'yes',
};
export const HAS_APACHE = {
  command: '(command -v apache2 || command -v httpd) >/dev/null && echo yes || echo no',
  expect: 'yes',
};
export const HAS_WEB = {
  command:
    '(command -v nginx || command -v apache2 || command -v httpd || command -v caddy) >/dev/null && echo yes || echo no',
  expect: 'yes',
};

export const webConfigurationChecks = [
  {
    id: 'web-root-perms',
    auditId: 'web-configuration',
    title: 'Web root is not world-writable',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "for d in /var/www/html /usr/share/nginx/html /var/www; do [ -d \"$d\" ] || continue; echo \"$d $(stat -c '%a' \"$d\" 2>/dev/null)\"; done | head -5",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No common web root found.' };
      const bad = lines.filter((l) => {
        const mode = parseInt(l.trim().split(/\s+/).pop(), 8);
        return !Number.isNaN(mode) && mode & 0o002;
      });
      if (bad.length) return { status: 'FAIL', detail: `World-writable web roots:\n${bad.join('\n')}` };
      return { status: 'PASS', detail: `Checked ${lines.length} web root(s).` };
    },
  },
  {
    id: 'web-config-perms',
    auditId: 'web-configuration',
    title: 'Web server config not world-writable',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "for f in /etc/nginx/nginx.conf /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf; do [ -f \"$f\" ] || continue; echo \"$f $(stat -c '%a' \"$f\" 2>/dev/null)\"; done",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No common config files found.' };
      const bad = lines.filter((l) => {
        const mode = parseInt(l.trim().split(/\s+/).pop(), 8);
        return !Number.isNaN(mode) && mode & 0o022;
      });
      if (bad.length) return { status: 'FAIL', detail: bad.join('\n') };
      return { status: 'PASS', detail: 'Config file permissions look sane.' };
    },
  },
  {
    id: 'web-run-as-nonroot',
    auditId: 'web-configuration',
    title: 'Web worker not running as root',
    severity: 'CRITICAL',
    weight: 10,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "ps -eo user,comm | grep -E 'nginx|apache2|httpd|caddy' | grep -v grep | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No web processes found.' };
      const asRoot = lines.filter((l) => /^root\s/.test(l) && !/master|nginx: master/i.test(l));
      // nginx master as root is normal; workers should not be
      const workersAsRoot = lines.filter(
        (l) => /^root\s/.test(l) && /worker|apache2|httpd/i.test(l) && !/master/i.test(l),
      );
      if (workersAsRoot.length) {
        return { status: 'FAIL', detail: `Workers running as root:\n${workersAsRoot.join('\n')}` };
      }
      return { status: 'PASS', detail: 'No obvious non-master web workers as root.' };
    },
  },
  {
    id: 'web-client-body-limit',
    auditId: 'web-configuration',
    title: 'Request body size is limited (nginx)',
    severity: 'MEDIUM',
    weight: 4,
    requiresSudo: true,
    applicability: HAS_NGINX,
    command:
      "grep -RIn 'client_max_body_size' /etc/nginx 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) {
        return {
          status: 'WARNING',
          detail: 'client_max_body_size not set (nginx default 1m may be fine; confirm).',
        };
      }
      return { status: 'PASS', detail: 'client_max_body_size configured.' };
    },
  },
  {
    id: 'web-server-tokens',
    auditId: 'web-configuration',
    title: 'Server tokens / signature reduced',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "(grep -RIn 'server_tokens' /etc/nginx 2>/dev/null | head -3; grep -RIn 'ServerTokens\\|ServerSignature' /etc/apache2 /etc/httpd 2>/dev/null | head -3) || echo NONE",
    evaluate: (out) => {
      const t = out.toLowerCase();
      if (t.includes('server_tokens off') || t.includes('servertokens prod')) {
        return { status: 'PASS', detail: 'Version disclosure settings look hardened.' };
      }
      if (out.includes('NONE')) {
        return { status: 'WARNING', detail: 'No server_tokens/ServerTokens hardening found.' };
      }
      return { status: 'WARNING', detail: 'Review version disclosure settings.' };
    },
  },
  {
    id: 'web-modules-minimal',
    auditId: 'web-configuration',
    title: 'Unnecessary modules not obviously loaded',
    severity: 'INFO',
    weight: 2,
    requiresSudo: true,
    applicability: HAS_APACHE,
    command:
      "apache2ctl -M 2>/dev/null | head -40 || httpd -M 2>/dev/null | head -40 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'SKIP', detail: 'Could not list modules.' };
      const risky = ['status_module', 'info_module', 'autoindex_module'].filter((m) =>
        out.includes(m),
      );
      if (risky.length) {
        return {
          status: 'WARNING',
          detail: `Potentially sensitive modules loaded: ${risky.join(', ')}`,
        };
      }
      return { status: 'PASS', detail: 'No common sensitive modules spotted.' };
    },
  },
];

export const webContentExposureChecks = [
  {
    id: 'web-autoindex',
    auditId: 'web-content-exposure',
    title: 'Directory listing disabled',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "(grep -RIn 'autoindex\\s\\+on' /etc/nginx 2>/dev/null; grep -RIn 'Options.*Indexes' /etc/apache2 /etc/httpd 2>/dev/null | grep -v '\\-Indexes') | head -10 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) {
        return { status: 'PASS', detail: 'No obvious directory listing enabled.' };
      }
      return { status: 'FAIL', detail: `Directory listing may be enabled:\n${out.slice(0, 300)}` };
    },
  },
  {
    id: 'web-dotfiles',
    auditId: 'web-content-exposure',
    title: 'Hidden files blocked from serving',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_NGINX,
    command:
      "grep -RIn 'location.*\\.\\|/\\.\\|' /etc/nginx 2>/dev/null | head -10 || echo NONE",
    evaluate: (out) => {
      if (/deny\s+all|return\s+404/i.test(out)) {
        return { status: 'PASS', detail: 'Dotfile/hidden path deny rules found.' };
      }
      return {
        status: 'WARNING',
        detail: 'No clear nginx rule denying dotfiles — verify app does not serve .env/.git.',
      };
    },
  },
  {
    id: 'web-backup-files',
    auditId: 'web-content-exposure',
    title: 'No backup archives in web root',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "find /var/www /usr/share/nginx/html -xdev -type f \\( -name '*.bak' -o -name '*.old' -o -name '*~' -o -name '*.zip' -o -name '*.sql' \\) 2>/dev/null | head -20 | wc -l",
    evaluate: (out) => {
      const n = Number(out.trim());
      if (Number.isNaN(n)) return { status: 'ERROR', detail: 'Could not parse.' };
      if (n === 0) return { status: 'PASS', detail: 'No backup-like files in common web roots.' };
      return { status: 'FAIL', detail: `${n} backup-like file(s) under web roots.` };
    },
  },
  {
    id: 'web-git-exposed',
    auditId: 'web-content-exposure',
    title: '.git not present under web root',
    severity: 'CRITICAL',
    weight: 10,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "find /var/www /usr/share/nginx/html -xdev -type d -name '.git' 2>/dev/null | head -10",
    evaluate: (out) => {
      const hits = out.trim().split('\n').filter(Boolean);
      if (!hits.length) return { status: 'PASS', detail: 'No .git directories under common web roots.' };
      return { status: 'FAIL', detail: `.git found:\n${hits.join('\n')}` };
    },
  },
  {
    id: 'web-trace-method',
    auditId: 'web-content-exposure',
    title: 'TRACE/TRACK method not enabled',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: HAS_APACHE,
    command:
      "grep -RIn 'TraceEnable' /etc/apache2 /etc/httpd 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (/TraceEnable\s+off/i.test(out)) return { status: 'PASS', detail: 'TraceEnable off.' };
      if (out.includes('NONE')) {
        return { status: 'WARNING', detail: 'TraceEnable not explicitly set.' };
      }
      return { status: 'WARNING', detail: out.slice(0, 200) };
    },
  },
  {
    id: 'web-status-endpoint',
    auditId: 'web-content-exposure',
    title: 'Server status endpoint not publicly exposed',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "grep -RIn 'stub_status\\|server-status\\|server-info' /etc/nginx /etc/apache2 /etc/httpd 2>/dev/null | head -10 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) {
        return { status: 'PASS', detail: 'No status endpoint config found.' };
      }
      if (/allow\s+127\.0\.0\.1|deny\s+all/i.test(out)) {
        return { status: 'PASS', detail: 'Status endpoint appears restricted.' };
      }
      return { status: 'WARNING', detail: 'Status endpoint configured — confirm IP restriction.' };
    },
  },
];
