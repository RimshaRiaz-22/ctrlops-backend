import { HAS_DB, HAS_MYSQL, HAS_POSTGRES, HAS_REDIS } from './authentication.js';

export const dbConfigurationChecks = [
  {
    id: 'db-service-user',
    auditId: 'db-configuration',
    title: 'Database processes not running as root',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: HAS_DB,
    command:
      "ps -eo user,comm | grep -E 'mysqld|postgres|mongod|redis-server' | grep -v grep | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No DB processes found.' };
      const asRoot = lines.filter((l) => /^root\s/.test(l));
      if (asRoot.length) return { status: 'FAIL', detail: asRoot.join('\n') };
      return { status: 'PASS', detail: 'DB processes run as non-root users.' };
    },
  },
  {
    id: 'db-datadir-perms',
    auditId: 'db-configuration',
    title: 'Data directories not world-readable',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    applicability: HAS_DB,
    command:
      "for d in /var/lib/mysql /var/lib/postgresql /var/lib/pgsql /var/lib/mongodb /var/lib/redis; do [ -d \"$d\" ] || continue; echo \"$d $(stat -c '%a' \"$d\" 2>/dev/null)\"; done",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No common data dirs.' };
      const bad = lines.filter((l) => {
        const mode = parseInt(l.split(/\s+/).pop(), 8);
        return !Number.isNaN(mode) && mode & 0o007;
      });
      if (bad.length) return { status: 'FAIL', detail: bad.join('\n') };
      return { status: 'PASS', detail: 'Data dir modes look restricted.' };
    },
  },
  {
    id: 'db-error-log-present',
    auditId: 'db-configuration',
    title: 'Database error logs exist',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: HAS_DB,
    command:
      'ls /var/log/mysql /var/log/postgresql /var/log/mongodb /var/log/redis 2>/dev/null | head -20 || echo NONE',
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) {
        return { status: 'WARNING', detail: 'No common DB log directories found.' };
      }
      return { status: 'PASS', detail: 'DB log directories present.' };
    },
  },
  {
    id: 'db-mysql-local-infile',
    auditId: 'db-configuration',
    title: 'MySQL local_infile disabled',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_MYSQL,
    command:
      "mysql --protocol=socket -NBe \"SHOW VARIABLES LIKE 'local_infile'\" 2>/dev/null || echo NEED_CREDS",
    evaluate: (out) => {
      if (out.includes('NEED_CREDS') || /ERROR|Access denied/i.test(out)) {
        return { status: 'SKIP', detail: 'Cannot query MySQL.' };
      }
      if (/\bOFF\b|0\b/i.test(out)) return { status: 'PASS', detail: 'local_infile off.' };
      return { status: 'FAIL', detail: out.trim() };
    },
  },
  {
    id: 'db-postgres-logging',
    auditId: 'db-configuration',
    title: 'Postgres logging collector enabled',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: HAS_POSTGRES,
    command:
      "grep -RIn '^logging_collector' /etc/postgresql /var/lib/pgsql 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (/logging_collector\s*=\s*on/i.test(out)) {
        return { status: 'PASS', detail: 'logging_collector on.' };
      }
      return { status: 'WARNING', detail: 'logging_collector not clearly enabled.' };
    },
  },
  {
    id: 'db-backup-hint',
    auditId: 'db-configuration',
    title: 'Backup tooling present',
    severity: 'MEDIUM',
    weight: 4,
    requiresSudo: false,
    applicability: HAS_DB,
    command:
      'command -v mysqldump; command -v pg_dump; command -v mongodump; echo DONE',
    evaluate: (out) => {
      if (/mysqldump|pg_dump|mongodump/.test(out)) {
        return { status: 'PASS', detail: 'At least one dump tool is installed.' };
      }
      return { status: 'WARNING', detail: 'No common DB dump tools found in PATH.' };
    },
  },
  {
    id: 'db-test-databases',
    auditId: 'db-configuration',
    title: 'Installer test databases removed (MySQL)',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: HAS_MYSQL,
    command:
      "mysql --protocol=socket -NBe \"SHOW DATABASES LIKE 'test'\" 2>/dev/null || echo NEED_CREDS",
    evaluate: (out) => {
      if (out.includes('NEED_CREDS') || /ERROR|Access denied/i.test(out)) {
        return { status: 'SKIP', detail: 'Cannot list databases.' };
      }
      if (/^test$/m.test(out.trim())) {
        return { status: 'FAIL', detail: 'test database still present.' };
      }
      return { status: 'PASS', detail: 'No test database.' };
    },
  },
];

export const dbCredentialStorageChecks = [
  {
    id: 'db-config-in-webroot',
    auditId: 'db-credential-storage',
    title: 'DB config files not under web root',
    severity: 'CRITICAL',
    weight: 10,
    requiresSudo: true,
    applicability: HAS_DB,
    command:
      "find /var/www /usr/share/nginx/html -xdev -type f \\( -name 'wp-config.php' -o -name '.env' -o -name 'database.yml' -o -name 'settings.php' \\) 2>/dev/null | head -20",
    evaluate: (out) => {
      const hits = out.trim().split('\n').filter(Boolean);
      if (!hits.length) {
        return { status: 'PASS', detail: 'No common DB config files under web roots (or none found).' };
      }
      // Presence under web root is expected for WP; check perms instead in companion — warn
      return {
        status: 'WARNING',
        detail: `DB-related configs under web tree:\n${hits.slice(0, 5).join('\n')}`,
      };
    },
  },
  {
    id: 'db-env-perms',
    auditId: 'db-credential-storage',
    title: 'App .env with DB creds not world-readable',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: HAS_DB,
    command:
      "find /var/www /home /opt -xdev -name '.env' -type f -perm -0004 2>/dev/null | head -20 | wc -l",
    evaluate: (out) => {
      const n = Number(out.trim());
      if (Number.isNaN(n)) return { status: 'ERROR', detail: 'Could not parse.' };
      if (n === 0) return { status: 'PASS', detail: 'No world-readable .env files found.' };
      return { status: 'FAIL', detail: `${n} world-readable .env file(s).` };
    },
  },
  {
    id: 'db-git-credentials',
    auditId: 'db-credential-storage',
    title: 'No .git with configs under web root',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: HAS_DB,
    command:
      "find /var/www -xdev -type d -name '.git' 2>/dev/null | head -10 | wc -l",
    evaluate: (out) => {
      const n = Number(out.trim());
      if (n === 0) return { status: 'PASS', detail: 'No .git under /var/www.' };
      return { status: 'FAIL', detail: `${n} .git director(ies) under /var/www.` };
    },
  },
  {
    id: 'db-client-history',
    auditId: 'db-credential-storage',
    title: 'DB client history files not world-readable',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_DB,
    command:
      "find /root /home -xdev -type f \\( -name '.mysql_history' -o -name '.psql_history' \\) -perm -0004 2>/dev/null | head -10 | wc -l",
    evaluate: (out) => {
      const n = Number(out.trim());
      if (Number.isNaN(n)) return { status: 'SKIP', detail: 'Could not scan histories.' };
      if (n === 0) return { status: 'PASS', detail: 'No world-readable DB history files.' };
      return { status: 'FAIL', detail: `${n} world-readable history file(s).` };
    },
  },
];

export const dbNetworkExposureChecks = [
  {
    id: 'db-bind-public',
    auditId: 'db-network-exposure',
    title: 'DB not bound on all interfaces',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: HAS_DB,
    command: "ss -tln 2>/dev/null | grep -E ':(3306|5432|27017|6379)\\s' || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'PASS', detail: 'No common DB ports listening.' };
      const pub = out
        .trim()
        .split('\n')
        .filter((l) => /0\.0\.0\.0:|:::/.test(l));
      if (pub.length) return { status: 'FAIL', detail: pub.slice(0, 5).join('\n') };
      return { status: 'PASS', detail: 'DB ports not on 0.0.0.0.' };
    },
  },
  {
    id: 'db-mysql-bind-address',
    auditId: 'db-network-exposure',
    title: 'MySQL bind-address is localhost-oriented',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    applicability: HAS_MYSQL,
    command:
      "grep -RIn '^bind-address' /etc/mysql /etc/my.cnf /etc/my.cnf.d 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'WARNING', detail: 'bind-address not found.' };
      if (/0\.0\.0\.0|::\b/.test(out)) {
        return { status: 'FAIL', detail: out.trim() };
      }
      return { status: 'PASS', detail: out.trim() };
    },
  },
  {
    id: 'db-postgres-listen',
    auditId: 'db-network-exposure',
    title: 'Postgres listen_addresses tightened',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    applicability: HAS_POSTGRES,
    command:
      "grep -RIn '^listen_addresses' /etc/postgresql /var/lib/pgsql 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'WARNING', detail: 'listen_addresses not found.' };
      if (/\*/.test(out)) return { status: 'FAIL', detail: out.trim() };
      return { status: 'PASS', detail: out.trim() };
    },
  },
  {
    id: 'db-firewall-hint',
    auditId: 'db-network-exposure',
    title: 'Host firewall present for DB exposure control',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_DB,
    commands: {
      debian: 'ufw status 2>/dev/null | head -1',
      rhel: 'firewall-cmd --state 2>/dev/null',
      _fallback: 'echo UNKNOWN',
    },
    evaluate: (out, _e, _c, env) => {
      const t = out.trim().toLowerCase();
      if (env?.family === 'debian' && /\bactive\b/.test(t) && !/\binactive\b/.test(t)) {
        return { status: 'PASS', detail: 'ufw active.' };
      }
      if (env?.family === 'rhel' && t === 'running') {
        return { status: 'PASS', detail: 'firewalld running.' };
      }
      return { status: 'WARNING', detail: 'Could not confirm host firewall for DB ports.' };
    },
  },
  {
    id: 'db-mongo-bind',
    auditId: 'db-network-exposure',
    title: 'MongoDB bindIp not 0.0.0.0',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    applicability: {
      command: '(command -v mongod || command -v mongosh) >/dev/null && echo yes || echo no',
      expect: 'yes',
    },
    command:
      "grep -RIn 'bindIp' /etc/mongod.conf 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'SKIP', detail: 'mongod.conf bindIp not found.' };
      if (/0\.0\.0\.0/.test(out)) return { status: 'FAIL', detail: out.trim() };
      return { status: 'PASS', detail: out.trim() };
    },
  },
];

export const dbPrivilegesChecks = [
  {
    id: 'db-mysql-grant-all',
    auditId: 'db-privileges',
    title: 'No wildcard GRANT ALL users (MySQL)',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: HAS_MYSQL,
    command:
      "mysql --protocol=socket -NBe \"SELECT user,host FROM mysql.user WHERE Super_priv='Y'\" 2>/dev/null | head -20 || echo NEED_CREDS",
    evaluate: (out) => {
      if (out.includes('NEED_CREDS') || /ERROR|Access denied/i.test(out)) {
        return { status: 'SKIP', detail: 'Cannot query privilege tables.' };
      }
      const lines = out.trim().split('\n').filter(Boolean);
      if (lines.length <= 1) return { status: 'PASS', detail: 'Few SUPER users.' };
      return {
        status: 'WARNING',
        detail: `${lines.length} SUPER-privileged accounts — review least privilege.`,
      };
    },
  },
  {
    id: 'db-mysql-wildcard-host',
    auditId: 'db-privileges',
    title: 'MySQL users not granted from %',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: HAS_MYSQL,
    command:
      "mysql --protocol=socket -NBe \"SELECT user,host FROM mysql.user WHERE host='%'\" 2>/dev/null | head -20 || echo NEED_CREDS",
    evaluate: (out) => {
      if (out.includes('NEED_CREDS') || /ERROR|Access denied/i.test(out)) {
        return { status: 'SKIP', detail: 'Cannot query mysql.user.' };
      }
      if (!out.trim()) return { status: 'PASS', detail: 'No users with host=%.' };
      return { status: 'FAIL', detail: out.slice(0, 300) };
    },
  },
  {
    id: 'db-postgres-superusers',
    auditId: 'db-privileges',
    title: 'Postgres superuser count is small',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_POSTGRES,
    command:
      "sudo -u postgres psql -tAc \"SELECT count(*) FROM pg_roles WHERE rolsuper\" 2>/dev/null || echo NEED_CREDS",
    evaluate: (out) => {
      if (out.includes('NEED_CREDS') || /FATAL|ERROR/i.test(out)) {
        return { status: 'SKIP', detail: 'Cannot query pg_roles.' };
      }
      const n = Number(out.trim());
      if (Number.isNaN(n)) return { status: 'WARNING', detail: out.trim() };
      if (n <= 2) return { status: 'PASS', detail: `${n} superuser role(s).` };
      return { status: 'WARNING', detail: `${n} superuser roles.` };
    },
  },
  {
    id: 'db-redis-protected-mode',
    auditId: 'db-privileges',
    title: 'Redis protected-mode on',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    applicability: HAS_REDIS,
    command:
      "grep -E '^protected-mode' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null | head -3 || echo NONE",
    evaluate: (out) => {
      if (/protected-mode\s+yes/i.test(out)) return { status: 'PASS', detail: 'protected-mode yes.' };
      if (out.includes('NONE')) return { status: 'WARNING', detail: 'protected-mode not found.' };
      return { status: 'FAIL', detail: out.trim() };
    },
  },
  {
    id: 'db-admin-count-hint',
    auditId: 'db-privileges',
    title: 'Admin DB accounts inventory (informational)',
    severity: 'INFO',
    weight: 2,
    requiresSudo: true,
    applicability: HAS_DB,
    command: 'echo REVIEW',
    evaluate: () => ({
      status: 'WARNING',
      detail: 'Review admin accounts manually; full privilege mapping needs DB credentials.',
    }),
  },
];

export const dbEncryptionChecks = [
  {
    id: 'db-mysql-ssl',
    auditId: 'db-encryption',
    title: 'MySQL SSL variables present',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_MYSQL,
    command:
      "mysql --protocol=socket -NBe \"SHOW VARIABLES LIKE 'have_ssl'\" 2>/dev/null || echo NEED_CREDS",
    evaluate: (out) => {
      if (out.includes('NEED_CREDS') || /ERROR|Access denied/i.test(out)) {
        return { status: 'SKIP', detail: 'Cannot query SSL variables.' };
      }
      if (/YES|DISABLED/i.test(out)) {
        return /YES/i.test(out)
          ? { status: 'PASS', detail: 'have_ssl=YES.' }
          : { status: 'WARNING', detail: out.trim() };
      }
      return { status: 'WARNING', detail: out.trim() || 'Unknown SSL state.' };
    },
  },
  {
    id: 'db-postgres-ssl',
    auditId: 'db-encryption',
    title: 'Postgres ssl enabled in config',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_POSTGRES,
    command:
      "grep -RIn '^ssl\\s*=' /etc/postgresql /var/lib/pgsql 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (/ssl\s*=\s*on/i.test(out)) return { status: 'PASS', detail: 'ssl=on.' };
      if (out.includes('NONE')) return { status: 'WARNING', detail: 'ssl setting not found.' };
      return { status: 'WARNING', detail: out.trim() };
    },
  },
  {
    id: 'db-tls-ports',
    auditId: 'db-encryption',
    title: 'Prefer TLS for remote DB clients (policy)',
    severity: 'INFO',
    weight: 2,
    requiresSudo: false,
    applicability: HAS_DB,
    command: 'echo POLICY',
    evaluate: () => ({
      status: 'WARNING',
      detail: 'Enforce require_secure_transport / hostssl in pg_hba for remote clients.',
    }),
  },
  {
    id: 'db-at-rest-hint',
    auditId: 'db-encryption',
    title: 'At-rest encryption is environment-specific',
    severity: 'INFO',
    weight: 2,
    requiresSudo: false,
    applicability: HAS_DB,
    command: 'echo POLICY',
    evaluate: () => ({
      status: 'WARNING',
      detail: 'Verify disk/volume encryption (LUKS/cloud CMEK) outside this SSH audit.',
    }),
  },
];
