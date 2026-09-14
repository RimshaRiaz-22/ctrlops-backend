import { shellQuote } from '../../utils/shellQuote.js';
import { section } from './parseBatch.js';

export function parseOsRelease(text) {
  const map = {};
  for (const line of String(text).split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    map[m[1].toLowerCase()] = v;
  }
  return {
    id: map.id ?? 'unknown',
    name: map.name ?? map.pretty_name ?? 'Unknown',
    version_id: map.version_id ?? '',
  };
}

export function familyOf(id) {
  const d = String(id).toLowerCase();
  if (['debian', 'ubuntu', 'linuxmint', 'pop', 'raspbian'].includes(d)) return 'debian';
  if (['rhel', 'centos', 'fedora', 'rocky', 'almalinux', 'ol', 'amzn'].includes(d)) return 'rhel';
  if (['opensuse', 'sles', 'suse'].includes(d)) return 'suse';
  if (d === 'alpine') return 'alpine';
  return 'unknown';
}

export function parseEnvironmentOutput(out) {
  const os = parseOsRelease(section(out, 'OS'));
  const uid = Number(section(out, 'USER').trim());
  const sudoRaw = section(out, 'SUDO');

  let sudoMode;
  if (uid === 0) sudoMode = 'ROOT';
  else if (sudoRaw.includes('EXIT:0')) sudoMode = 'PASSWORDLESS';
  else sudoMode = 'UNAVAILABLE';

  return {
    sudoMode,
    family: familyOf(os.id),
    distro: os.name,
    version: os.version_id,
  };
}

export async function detectEnvironment(conn, execFn) {
  const cmd = [
    'echo "===OS==="',
    'cat /etc/os-release 2>/dev/null',
    'echo "===SUDO==="',
    'sudo -n true 2>&1; echo "EXIT:$?"',
    'echo "===USER==="',
    'id -u',
    'echo "===DONE==="',
  ].join('; ');

  const out = await execFn(conn, cmd, { timeoutMs: 15_000 });
  return parseEnvironmentOutput(out);
}

export function resolveCommand(check, family) {
  if (check.commands) {
    return (
      check.commands[family] ||
      check.commands._fallback ||
      check.command ||
      'true'
    );
  }
  return check.command || 'true';
}

export function sudoPrefix(env, check) {
  if (!check.requiresSudo) return '';
  if (env.sudoMode === 'PASSWORDLESS') return 'sudo -n ';
  if (env.sudoMode === 'ROOT') return '';
  return null; // UNAVAILABLE — caller should SKIP
}

export function buildAuditBatch(checks, env) {
  return (
    checks
      .map((c) => {
        const cmd = resolveCommand(c, env.family);
        const prefix = env.sudoMode === 'PASSWORDLESS' && c.requiresSudo ? 'sudo -n ' : '';
        const wrapped = `${prefix}${cmd}`;
        return [
          `echo "===CHECK:${c.id}==="`,
          `timeout 10 sh -c ${shellQuote(wrapped)} 2>&1`,
          `echo "===EXIT:$?==="`,
        ].join('; ');
      })
      .join('; ') + '; echo "===DONE==="'
  );
}

export function buildApplicabilityBatch(checks) {
  const withApp = checks.filter((c) => c.applicability?.command);
  if (!withApp.length) return null;
  return (
    withApp
      .map((c) => `echo "===APP:${c.id}==="; ${c.applicability.command} 2>&1`)
      .join('; ') + '; echo "===DONE==="'
  );
}
