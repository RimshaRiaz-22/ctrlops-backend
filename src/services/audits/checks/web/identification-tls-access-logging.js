import { HAS_WEB, HAS_NGINX, HAS_APACHE } from './configuration-and-content.js';

export const webIdentificationChecks = [
  {
    id: 'web-nginx-version',
    auditId: 'web-identification',
    title: 'nginx version is not ancient',
    severity: 'MEDIUM',
    weight: 4,
    requiresSudo: false,
    applicability: HAS_NGINX,
    command: 'nginx -v 2>&1',
    evaluate: (out) => {
      const m = out.match(/nginx\/(\d+)\.(\d+)/i);
      if (!m) return { status: 'WARNING', detail: `Could not parse: ${out.trim()}` };
      const major = Number(m[1]);
      const minor = Number(m[2]);
      if (major < 1 || (major === 1 && minor < 18)) {
        return { status: 'FAIL', detail: `nginx ${m[1]}.${m[2]} is quite old.` };
      }
      return { status: 'PASS', detail: out.trim() };
    },
  },
  {
    id: 'web-apache-version',
    auditId: 'web-identification',
    title: 'Apache version is not ancient',
    severity: 'MEDIUM',
    weight: 4,
    requiresSudo: false,
    applicability: HAS_APACHE,
    command: 'apache2 -v 2>&1 | head -1 || httpd -v 2>&1 | head -1',
    evaluate: (out) => {
      const m = out.match(/Apache\/(\d+)\.(\d+)/i);
      if (!m) return { status: 'WARNING', detail: `Could not parse: ${out.trim()}` };
      if (Number(m[1]) < 2 || (Number(m[1]) === 2 && Number(m[2]) < 4)) {
        return { status: 'FAIL', detail: out.trim() };
      }
      return { status: 'PASS', detail: out.trim() };
    },
  },
  {
    id: 'web-banner-leak',
    auditId: 'web-identification',
    title: 'Local HTTP banner does not shout version',
    severity: 'LOW',
    weight: 3,
    requiresSudo: false,
    applicability: HAS_WEB,
    command:
      "curl -sI --max-time 3 http://127.0.0.1/ 2>/dev/null | grep -i '^server:' || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'PASS', detail: 'No Server header from localhost.' };
      if (/nginx\/\d|Apache\/\d/i.test(out)) {
        return { status: 'WARNING', detail: `Version in Server header: ${out.trim()}` };
      }
      return { status: 'PASS', detail: out.trim() };
    },
  },
  {
    id: 'web-package-updates',
    auditId: 'web-identification',
    title: 'Web packages appear installed via package manager',
    severity: 'INFO',
    weight: 2,
    requiresSudo: false,
    applicability: HAS_WEB,
    command:
      '(dpkg -l nginx apache2 2>/dev/null | grep ^ii; rpm -q nginx httpd 2>/dev/null) | head -10 || echo NONE',
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) {
        return { status: 'WARNING', detail: 'Could not confirm packaged web server install.' };
      }
      return { status: 'PASS', detail: 'Packaged web server detected.' };
    },
  },
  {
    id: 'web-eol-hint',
    auditId: 'web-identification',
    title: 'No obvious EOL stack markers in configs',
    severity: 'LOW',
    weight: 2,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "grep -RIn 'php5\\|python2\\.7' /etc/nginx /etc/apache2 /var/www 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) return { status: 'PASS', detail: 'No obvious EOL markers.' };
      return { status: 'WARNING', detail: `Possible EOL references:\n${out.slice(0, 200)}` };
    },
  },
];

export const webTlsChecks = [
  {
    id: 'web-tls-listen',
    auditId: 'web-tls',
    title: 'HTTPS listener present',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: false,
    applicability: HAS_WEB,
    command: "ss -tln 2>/dev/null | grep -E ':443\\s' || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) {
        return { status: 'FAIL', detail: 'Nothing listening on :443.' };
      }
      return { status: 'PASS', detail: 'Port 443 is listening.' };
    },
  },
  {
    id: 'web-tls-protocols',
    auditId: 'web-tls',
    title: 'TLS 1.0/1.1 not explicitly enabled',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: HAS_NGINX,
    command:
      "grep -RIn 'ssl_protocols' /etc/nginx 2>/dev/null | head -10 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) {
        return { status: 'WARNING', detail: 'ssl_protocols not found — verify defaults.' };
      }
      if (/TLSv1[^.]|TLSv1\.0|TLSv1\.1/i.test(out) && !/TLSv1\.2|TLSv1\.3/i.test(out)) {
        return { status: 'FAIL', detail: 'Only old TLS protocols configured.' };
      }
      if (/TLSv1\.0|TLSv1\.1/i.test(out)) {
        return { status: 'FAIL', detail: 'TLS 1.0/1.1 still listed in ssl_protocols.' };
      }
      return { status: 'PASS', detail: 'Modern ssl_protocols appear configured.' };
    },
  },
  {
    id: 'web-hsts',
    auditId: 'web-tls',
    title: 'HSTS header configured',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "grep -RIn 'Strict-Transport-Security\\|add_header.*Strict' /etc/nginx /etc/apache2 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'WARNING', detail: 'HSTS not found in configs.' };
      return { status: 'PASS', detail: 'HSTS configuration found.' };
    },
  },
  {
    id: 'web-cert-readable',
    auditId: 'web-tls',
    title: 'TLS certificate files are not world-readable keys',
    severity: 'CRITICAL',
    weight: 10,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "find /etc/nginx /etc/letsencrypt/live /etc/ssl/private -xdev -type f \\( -name '*.key' -o -name 'privkey.pem' \\) -perm -0004 2>/dev/null | head -10 | wc -l",
    evaluate: (out) => {
      const n = Number(out.trim());
      if (Number.isNaN(n)) return { status: 'ERROR', detail: 'Could not parse.' };
      if (n === 0) return { status: 'PASS', detail: 'No world-readable private keys found.' };
      return { status: 'FAIL', detail: `${n} world-readable private key file(s).` };
    },
  },
  {
    id: 'web-ssl-prefer-server-ciphers',
    auditId: 'web-tls',
    title: 'Server cipher preference enabled (nginx)',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: HAS_NGINX,
    command:
      "grep -RIn 'ssl_prefer_server_ciphers' /etc/nginx 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (/ssl_prefer_server_ciphers\s+on/i.test(out)) {
        return { status: 'PASS', detail: 'ssl_prefer_server_ciphers on.' };
      }
      return { status: 'WARNING', detail: 'ssl_prefer_server_ciphers not clearly enabled.' };
    },
  },
  {
    id: 'web-redirect-http',
    auditId: 'web-tls',
    title: 'HTTP to HTTPS redirect present',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_NGINX,
    command:
      "grep -RIn 'return 301 https\\|rewrite .*https' /etc/nginx 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) {
        return { status: 'WARNING', detail: 'No obvious HTTP→HTTPS redirect in nginx configs.' };
      }
      return { status: 'PASS', detail: 'HTTPS redirect rules found.' };
    },
  },
];

export const webAccessControlChecks = [
  {
    id: 'web-admin-path',
    auditId: 'web-access-control',
    title: 'Admin paths not openly configured',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "grep -RIn 'location.*/\\(admin\\|wp-admin\\|phpmyadmin\\|manager\\)' /etc/nginx /etc/apache2 2>/dev/null | head -10 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) {
        return { status: 'PASS', detail: 'No obvious admin location blocks (may be app-level).' };
      }
      if (/allow\s+|deny\s+|auth_basic|satisfy/i.test(out)) {
        return { status: 'PASS', detail: 'Admin paths appear access-controlled.' };
      }
      return { status: 'WARNING', detail: 'Admin paths present — confirm auth/IP rules.' };
    },
  },
  {
    id: 'web-basic-auth-files',
    auditId: 'web-access-control',
    title: 'htpasswd files not world-readable',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "find /etc/nginx /etc/apache2 /etc/httpd -xdev -type f \\( -name '*htpasswd*' -o -name '.htpasswd' \\) -perm -0004 2>/dev/null | head -10 | wc -l",
    evaluate: (out) => {
      const n = Number(out.trim());
      if (Number.isNaN(n)) return { status: 'ERROR', detail: 'Could not parse.' };
      if (n === 0) return { status: 'PASS', detail: 'No world-readable htpasswd files.' };
      return { status: 'FAIL', detail: `${n} world-readable htpasswd file(s).` };
    },
  },
  {
    id: 'web-ip-allowlist-hint',
    auditId: 'web-access-control',
    title: 'IP allow/deny directives exist where expected',
    severity: 'INFO',
    weight: 2,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "grep -RIn 'allow \\|deny ' /etc/nginx /etc/apache2 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) {
        return {
          status: 'WARNING',
          detail: 'No allow/deny directives found — fine if auth is app-level.',
        };
      }
      return { status: 'PASS', detail: 'IP allow/deny rules present somewhere.' };
    },
  },
  {
    id: 'web-root-owned',
    auditId: 'web-access-control',
    title: 'Web root not owned by a login user unnecessarily',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "stat -c '%U:%G' /var/www/html 2>/dev/null || stat -c '%U:%G' /usr/share/nginx/html 2>/dev/null || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'SKIP', detail: 'No common web root.' };
      if (/^root:|^www-data:|^nginx:|^apache:|^http:/i.test(out.trim())) {
        return { status: 'PASS', detail: `Owner ${out.trim()}.` };
      }
      return { status: 'WARNING', detail: `Unusual web root owner: ${out.trim()}` };
    },
  },
];

export const webLoggingChecks = [
  {
    id: 'web-access-log',
    auditId: 'web-logging',
    title: 'Access logging enabled',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "grep -RIn 'access_log\\|CustomLog' /etc/nginx /etc/apache2 /etc/httpd 2>/dev/null | grep -v '#' | head -5 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'FAIL', detail: 'No access_log/CustomLog found.' };
      if (/access_log\s+off/i.test(out)) {
        return { status: 'FAIL', detail: 'access_log off detected.' };
      }
      return { status: 'PASS', detail: 'Access logging configured.' };
    },
  },
  {
    id: 'web-error-log',
    auditId: 'web-logging',
    title: 'Error logging enabled',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "grep -RIn 'error_log\\|ErrorLog' /etc/nginx /etc/apache2 /etc/httpd 2>/dev/null | grep -v '#' | head -5 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'FAIL', detail: 'No error_log/ErrorLog found.' };
      return { status: 'PASS', detail: 'Error logging configured.' };
    },
  },
  {
    id: 'web-log-perms',
    auditId: 'web-logging',
    title: 'Web logs not world-writable',
    severity: 'MEDIUM',
    weight: 4,
    requiresSudo: true,
    applicability: HAS_WEB,
    command:
      "find /var/log/nginx /var/log/apache2 /var/log/httpd -xdev -type f -perm -0002 2>/dev/null | head -10 | wc -l",
    evaluate: (out) => {
      const n = Number(out.trim());
      if (Number.isNaN(n)) return { status: 'SKIP', detail: 'Log dirs missing or unreadable.' };
      if (n === 0) return { status: 'PASS', detail: 'No world-writable web logs.' };
      return { status: 'FAIL', detail: `${n} world-writable log file(s).` };
    },
  },
  {
    id: 'web-logrotate',
    auditId: 'web-logging',
    title: 'Logrotate config exists for web server',
    severity: 'LOW',
    weight: 3,
    requiresSudo: false,
    applicability: HAS_WEB,
    command:
      'ls /etc/logrotate.d/nginx /etc/logrotate.d/apache2 /etc/logrotate.d/httpd 2>/dev/null || echo NONE',
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) {
        return { status: 'WARNING', detail: 'No web logrotate drop-in found.' };
      }
      return { status: 'PASS', detail: out.trim().split('\n')[0] };
    },
  },
];
