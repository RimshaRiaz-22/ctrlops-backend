export const HAS_MYSQL = {
  command: '(command -v mysql || command -v mariadb) >/dev/null && echo yes || echo no',
  expect: 'yes',
};
export const HAS_POSTGRES = {
  command: 'command -v psql >/dev/null && echo yes || echo no',
  expect: 'yes',
};
export const HAS_DB = {
  command:
    '(command -v mysql || command -v mariadb || command -v psql || command -v mongosh || command -v mongo) >/dev/null && echo yes || echo no',
  expect: 'yes',
};
export const HAS_REDIS = {
  command: 'command -v redis-cli >/dev/null && echo yes || echo no',
  expect: 'yes',
};

export const dbAuthenticationChecks = [
  {
    id: 'db-anon-mysql',
    auditId: 'db-authentication',
    title: 'MySQL anonymous users absent (local probe)',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: HAS_MYSQL,
    command:
      "mysql --protocol=socket -NBe \"SELECT user,host FROM mysql.user WHERE user=''\" 2>/dev/null || echo NEED_CREDS",
    evaluate: (out) => {
      if (out.includes('NEED_CREDS') || /ERROR|Access denied/i.test(out)) {
        return {
          status: 'SKIP',
          detail: 'Cannot query mysql.user without credentials — configure a read-only audit user later.',
        };
      }
      if (!out.trim()) return { status: 'PASS', detail: 'No anonymous MySQL users.' };
      return { status: 'FAIL', detail: `Anonymous users:\n${out.slice(0, 200)}` };
    },
  },
  {
    id: 'db-mysql-root-remote',
    auditId: 'db-authentication',
    title: 'MySQL root not allowed from remote hosts',
    severity: 'CRITICAL',
    weight: 10,
    requiresSudo: true,
    applicability: HAS_MYSQL,
    command:
      "mysql --protocol=socket -NBe \"SELECT user,host FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')\" 2>/dev/null || echo NEED_CREDS",
    evaluate: (out) => {
      if (out.includes('NEED_CREDS') || /ERROR|Access denied/i.test(out)) {
        return { status: 'SKIP', detail: 'Cannot query mysql.user without credentials.' };
      }
      if (!out.trim()) return { status: 'PASS', detail: 'root only on localhost-like hosts.' };
      return { status: 'FAIL', detail: `Remote root accounts:\n${out.slice(0, 200)}` };
    },
  },
  {
    id: 'db-postgres-pg-hba',
    auditId: 'db-authentication',
    title: 'Postgres pg_hba avoids trust on non-local',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: HAS_POSTGRES,
    command:
      "grep -RIn '^[^#].*trust' /etc/postgresql /var/lib/pgsql 2>/dev/null | head -15 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) {
        return { status: 'PASS', detail: 'No obvious trust auth lines.' };
      }
      const remote = out
        .trim()
        .split('\n')
        .filter((l) => !/127\.0\.0\.1|::1|local\s/.test(l));
      if (remote.length) {
        return { status: 'FAIL', detail: `Non-local trust entries:\n${remote.slice(0, 5).join('\n')}` };
      }
      return { status: 'WARNING', detail: 'trust present but appears local-only — confirm.' };
    },
  },
  {
    id: 'db-postgres-peer-local',
    auditId: 'db-authentication',
    title: 'Postgres local auth method configured',
    severity: 'MEDIUM',
    weight: 4,
    requiresSudo: true,
    applicability: HAS_POSTGRES,
    command:
      "grep -RIn '^local' /etc/postgresql/*/main/pg_hba.conf /var/lib/pgsql/*/data/pg_hba.conf 2>/dev/null | head -10 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'SKIP', detail: 'pg_hba.conf not found.' };
      return { status: 'PASS', detail: 'local lines present in pg_hba.' };
    },
  },
  {
    id: 'db-redis-requirepass',
    auditId: 'db-authentication',
    title: 'Redis requires authentication',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: HAS_REDIS,
    command:
      "grep -E '^requirepass|^masterauth' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (/^requirepass\s+\S+/m.test(out) || /requirepass\s+\S+/.test(out)) {
        return { status: 'PASS', detail: 'requirepass set.' };
      }
      return { status: 'FAIL', detail: 'requirepass not found in common redis.conf paths.' };
    },
  },
  {
    id: 'db-redis-bind',
    auditId: 'db-authentication',
    title: 'Redis bind is not 0.0.0.0 without protection',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    applicability: HAS_REDIS,
    command: "grep -E '^bind ' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null | head -5 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'WARNING', detail: 'bind directive not found.' };
      if (/0\.0\.0\.0|::/.test(out)) {
        return { status: 'WARNING', detail: `Redis bind is broad:\n${out.trim()}` };
      }
      return { status: 'PASS', detail: out.trim() };
    },
  },
  {
    id: 'db-mysql-plugin',
    auditId: 'db-authentication',
    title: 'MySQL default auth plugin not ancient',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: HAS_MYSQL,
    command:
      "mysql --protocol=socket -NBe \"SHOW VARIABLES LIKE 'default_authentication_plugin'\" 2>/dev/null || echo NEED_CREDS",
    evaluate: (out) => {
      if (out.includes('NEED_CREDS') || /ERROR|Access denied/i.test(out)) {
        return { status: 'SKIP', detail: 'Cannot query MySQL variables.' };
      }
      if (/mysql_native_password/i.test(out)) {
        return { status: 'WARNING', detail: 'mysql_native_password still default.' };
      }
      return { status: 'PASS', detail: out.trim() || 'OK' };
    },
  },
  {
    id: 'db-listening-auth-surface',
    auditId: 'db-authentication',
    title: 'Database ports require network controls',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_DB,
    command: "ss -tln 2>/dev/null | grep -E ':(3306|5432|27017|6379)\\s' || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'PASS', detail: 'No common DB ports listening.' };
      if (/0\.0\.0\.0:|:::/.test(out)) {
        return {
          status: 'WARNING',
          detail: 'DB ports on all interfaces — ensure auth + firewall.',
        };
      }
      return { status: 'PASS', detail: 'DB listeners look local-oriented.' };
    },
  },
];
