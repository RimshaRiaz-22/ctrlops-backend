export const HAS_DOCKER = {
  command: 'command -v docker >/dev/null && echo yes || echo no',
  expect: 'yes',
};

export const dockerDaemonSocketChecks = [
  {
    id: 'docker-socket-tcp',
    auditId: 'docker-daemon-socket',
    title: 'Docker daemon not exposed over TCP',
    severity: 'CRITICAL',
    weight: 10,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: "ss -tlnp 2>/dev/null | grep -E ':(2375|2376)\\s' || echo 'NONE'",
    evaluate: (out) => {
      if (out.includes('NONE')) {
        return { status: 'PASS', detail: 'Docker is not listening on TCP 2375/2376.' };
      }
      if (out.includes(':2375')) {
        return {
          status: 'FAIL',
          detail:
            'Docker is exposed on 2375 without TLS. This grants unauthenticated root-equivalent access.',
        };
      }
      return {
        status: 'WARNING',
        detail: 'Docker is exposed on 2376 (TLS). Verify certificate auth is enforced.',
      };
    },
    remediation: {
      summary: 'Remove the TCP socket from the daemon configuration and restart Docker.',
      warning: 'Remote Docker clients using this endpoint will stop working.',
    },
  },
  {
    id: 'docker-socket-perms',
    auditId: 'docker-daemon-socket',
    title: 'Docker unix socket is not world-accessible',
    severity: 'CRITICAL',
    weight: 10,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: "stat -c '%a %U:%G' /var/run/docker.sock 2>/dev/null || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'SKIP', detail: 'docker.sock not found.' };
      const mode = parseInt(out.trim().split(/\s+/)[0], 8);
      if (!Number.isNaN(mode) && mode & 0o007) {
        return { status: 'FAIL', detail: `/var/run/docker.sock mode too open: ${out.trim()}` };
      }
      return { status: 'PASS', detail: out.trim() };
    },
  },
  {
    id: 'docker-group-members',
    auditId: 'docker-daemon-socket',
    title: 'docker group membership is limited',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: false,
    applicability: HAS_DOCKER,
    command: "getent group docker 2>/dev/null || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'SKIP', detail: 'No docker group.' };
      const members = (out.split(':')[3] || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      if (members.length > 5) {
        return {
          status: 'WARNING',
          detail: `${members.length} users in docker group (root-equivalent).`,
        };
      }
      return { status: 'PASS', detail: `docker group members: ${members.length}` };
    },
  },
  {
    id: 'docker-info-reachable',
    auditId: 'docker-daemon-socket',
    title: 'Docker daemon responds to docker info',
    severity: 'INFO',
    weight: 2,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: 'docker info >/dev/null 2>&1; echo EXIT:$?',
    evaluate: (out) => {
      if (out.includes('EXIT:0')) return { status: 'PASS', detail: 'docker info succeeded.' };
      return { status: 'WARNING', detail: 'docker info failed — permission or daemon down.' };
    },
  },
  {
    id: 'docker-live-restore',
    auditId: 'docker-daemon-socket',
    title: 'Live restore considered',
    severity: 'LOW',
    weight: 2,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: "docker info 2>/dev/null | grep -i 'Live Restore' || echo NONE",
    evaluate: (out) => {
      if (/true/i.test(out)) return { status: 'PASS', detail: 'Live restore enabled.' };
      return { status: 'WARNING', detail: 'Live restore not enabled (optional hardening).' };
    },
  },
  {
    id: 'docker-logging-driver',
    auditId: 'docker-daemon-socket',
    title: 'Logging driver is set',
    severity: 'LOW',
    weight: 2,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: "docker info 2>/dev/null | grep -i 'Logging Driver' || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'SKIP', detail: 'Could not read logging driver.' };
      return { status: 'PASS', detail: out.trim() };
    },
  },
  {
    id: 'docker-rootless-hint',
    auditId: 'docker-daemon-socket',
    title: 'Rootless mode awareness',
    severity: 'INFO',
    weight: 2,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: "docker info 2>/dev/null | grep -i rootless || echo 'rootful'",
    evaluate: (out) => {
      if (/rootless:\s*true/i.test(out)) return { status: 'PASS', detail: 'Rootless Docker.' };
      return {
        status: 'WARNING',
        detail: 'Docker appears rootful — expected on many hosts; tighten socket access.',
      };
    },
  },
  {
    id: 'docker-iptables',
    auditId: 'docker-daemon-socket',
    title: 'Docker manages iptables',
    severity: 'INFO',
    weight: 2,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: "docker info 2>/dev/null | grep -i 'FirewallBackend\\|iptables' | head -5 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'SKIP', detail: 'No iptables info.' };
      return { status: 'PASS', detail: out.trim().slice(0, 200) };
    },
  },
];

export const dockerContainerHardeningChecks = [
  {
    id: 'docker-no-privileged',
    auditId: 'docker-container-hardening',
    title: 'No privileged containers running',
    severity: 'CRITICAL',
    weight: 10,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps -q 2>/dev/null | while read id; do docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}' \"$id\"; done | grep -i true || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) {
        return { status: 'PASS', detail: 'No privileged containers detected.' };
      }
      return { status: 'FAIL', detail: `Privileged containers:\n${out.slice(0, 300)}` };
    },
  },
  {
    id: 'docker-nonroot-user',
    auditId: 'docker-container-hardening',
    title: 'Running containers prefer non-root user',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps -q 2>/dev/null | while read id; do docker inspect --format '{{.Name}} {{.Config.User}}' \"$id\"; done | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No running containers.' };
      const asRoot = lines.filter((l) => {
        const user = l.trim().split(/\s+/).slice(1).join(' ');
        return !user || user === '0' || user === 'root' || user.startsWith('0:');
      });
      if (asRoot.length === lines.length) {
        return { status: 'WARNING', detail: 'All sampled containers run as root/default.' };
      }
      if (asRoot.length) {
        return {
          status: 'WARNING',
          detail: `${asRoot.length}/${lines.length} containers without explicit non-root user.`,
        };
      }
      return { status: 'PASS', detail: 'Containers specify non-root users.' };
    },
  },
  {
    id: 'docker-no-new-privileges',
    auditId: 'docker-container-hardening',
    title: 'SecurityOpt no-new-privileges used',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps -q 2>/dev/null | while read id; do docker inspect --format '{{.Name}} {{.HostConfig.SecurityOpt}}' \"$id\"; done | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No running containers.' };
      const ok = lines.filter((l) => /no-new-privileges/i.test(l)).length;
      if (ok === lines.length) return { status: 'PASS', detail: 'no-new-privileges on all.' };
      if (ok === 0) {
        return { status: 'WARNING', detail: 'no-new-privileges not set on running containers.' };
      }
      return { status: 'WARNING', detail: `${ok}/${lines.length} have no-new-privileges.` };
    },
  },
  {
    id: 'docker-cap-drop',
    auditId: 'docker-container-hardening',
    title: 'Capabilities are dropped where possible',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps -q 2>/dev/null | while read id; do docker inspect --format '{{.Name}} CapDrop={{.HostConfig.CapDrop}}' \"$id\"; done | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No running containers.' };
      const withDrop = lines.filter((l) => /CapDrop=\[.+\]/i.test(l) && !/CapDrop=\[\]/.test(l));
      if (!withDrop.length) {
        return { status: 'WARNING', detail: 'No CapDrop observed on running containers.' };
      }
      return { status: 'PASS', detail: `${withDrop.length} container(s) drop capabilities.` };
    },
  },
  {
    id: 'docker-sensitive-mounts',
    auditId: 'docker-container-hardening',
    title: 'No docker.sock mounted into containers',
    severity: 'CRITICAL',
    weight: 10,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps -q 2>/dev/null | while read id; do docker inspect --format '{{.Name}} {{range .Mounts}}{{.Source}} {{end}}' \"$id\"; done | grep docker.sock || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'PASS', detail: 'No docker.sock mounts.' };
      return { status: 'FAIL', detail: `docker.sock mounted:\n${out.slice(0, 300)}` };
    },
  },
];
