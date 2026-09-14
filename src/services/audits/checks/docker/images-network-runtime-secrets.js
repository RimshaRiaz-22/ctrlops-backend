import { HAS_DOCKER } from './daemon-and-containers.js';

export const dockerImageVulnsChecks = [
  {
    id: 'docker-latest-tags',
    auditId: 'docker-image-vulns',
    title: 'Running images avoid floating :latest tags',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps --format '{{.Image}}' 2>/dev/null | head -30",
    evaluate: (out) => {
      const images = out.trim().split('\n').filter(Boolean);
      if (!images.length) return { status: 'SKIP', detail: 'No running containers.' };
      const latest = images.filter((i) => /:latest$|^[^:/]+$/.test(i));
      if (latest.length) {
        return {
          status: 'WARNING',
          detail: `${latest.length} image(s) use latest/untagged: ${latest.slice(0, 5).join(', ')}`,
        };
      }
      return { status: 'PASS', detail: 'Running images use pinned tags.' };
    },
  },
  {
    id: 'docker-image-age-hint',
    auditId: 'docker-image-vulns',
    title: 'Local images exist to be scanned',
    severity: 'INFO',
    weight: 2,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: 'docker images -q 2>/dev/null | wc -l',
    evaluate: (out) => {
      const n = Number(out.trim());
      if (!n) return { status: 'SKIP', detail: 'No local images.' };
      return {
        status: 'PASS',
        detail: `${n} local image(s). Run a scanner (Trivy/Grype) separately — not a CVE engine.`,
      };
    },
  },
  {
    id: 'docker-dangling-images',
    auditId: 'docker-image-vulns',
    title: 'Dangling images cleaned up',
    severity: 'LOW',
    weight: 2,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: 'docker images -f dangling=true -q 2>/dev/null | wc -l',
    evaluate: (out) => {
      const n = Number(out.trim());
      if (n === 0) return { status: 'PASS', detail: 'No dangling images.' };
      if (n < 10) return { status: 'WARNING', detail: `${n} dangling image(s).` };
      return { status: 'FAIL', detail: `${n} dangling images — prune recommended.` };
    },
  },
  {
    id: 'docker-official-base-hint',
    auditId: 'docker-image-vulns',
    title: 'Prefer known registries for running images',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: "docker ps --format '{{.Image}}' 2>/dev/null | head -20",
    evaluate: (out) => {
      const images = out.trim().split('\n').filter(Boolean);
      if (!images.length) return { status: 'SKIP', detail: 'No running containers.' };
      const shady = images.filter((i) => /localhost:|0\.0\.0\.0:|\[::\]/.test(i));
      if (shady.length) {
        return { status: 'WARNING', detail: `Images from local/odd registries: ${shady.join(', ')}` };
      }
      return { status: 'PASS', detail: 'No obviously local-registry-only images.' };
    },
  },
  {
    id: 'docker-content-trust',
    auditId: 'docker-image-vulns',
    title: 'Docker Content Trust awareness',
    severity: 'INFO',
    weight: 2,
    requiresSudo: false,
    applicability: HAS_DOCKER,
    command: 'echo "DOCKER_CONTENT_TRUST=${DOCKER_CONTENT_TRUST:-unset}"',
    evaluate: (out) => {
      if (/DOCKER_CONTENT_TRUST=1/.test(out)) {
        return { status: 'PASS', detail: 'Content trust enabled in this shell env.' };
      }
      return {
        status: 'WARNING',
        detail: 'DOCKER_CONTENT_TRUST not set in probe env (may still be set for CI).',
      };
    },
  },
];

export const dockerNetworkChecks = [
  {
    id: 'docker-default-bridge',
    auditId: 'docker-network',
    title: 'Containers not all on legacy default bridge',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_DOCKER,
      command:
      "docker ps -q 2>/dev/null | while read id; do docker inspect --format '{{.Name}} {{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' \"$id\"; done | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No running containers.' };
      const onBridge = lines.filter((l) => /\bbridge\b/.test(l));
      if (onBridge.length === lines.length) {
        return {
          status: 'WARNING',
          detail: 'All containers on default bridge — prefer user-defined networks.',
        };
      }
      return { status: 'PASS', detail: 'Not all containers solely on default bridge.' };
    },
  },
  {
    id: 'docker-published-ports',
    auditId: 'docker-network',
    title: 'Published ports inventory',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: "docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | head -30",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No running containers.' };
      const publicish = lines.filter((l) => /0\.0\.0\.0:|:::/i.test(l));
      if (publicish.length) {
        return {
          status: 'WARNING',
          detail: `${publicish.length} container(s) publish on all interfaces — review.`,
        };
      }
      return { status: 'PASS', detail: 'No 0.0.0.0 published ports in sample.' };
    },
  },
  {
    id: 'docker-icc-hint',
    auditId: 'docker-network',
    title: 'User-defined networks exist',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: "docker network ls --format '{{.Name}} {{.Driver}}' 2>/dev/null | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter((l) => l && !/^bridge |^host |^none /.test(l));
      if (!lines.length) {
        return { status: 'WARNING', detail: 'Only built-in networks found.' };
      }
      return { status: 'PASS', detail: `${lines.length} custom/other network(s).` };
    },
  },
  {
    id: 'docker-host-network',
    auditId: 'docker-network',
    title: 'Host networking used sparingly',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps -q 2>/dev/null | while read id; do docker inspect --format '{{.Name}} {{.HostConfig.NetworkMode}}' \"$id\"; done | grep -w host || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'PASS', detail: 'No host-network containers.' };
      return { status: 'WARNING', detail: `Host network mode:\n${out.slice(0, 200)}` };
    },
  },
  {
    id: 'docker-expose-db-ports',
    auditId: 'docker-network',
    title: 'DB ports not broadly published',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E '0\\.0\\.0\\.0:(3306|5432|27017|6379)->' || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE')) return { status: 'PASS', detail: 'No public DB port publishes.' };
      return { status: 'FAIL', detail: `Public DB ports:\n${out.slice(0, 300)}` };
    },
  },
];

export const dockerRuntimePolicyChecks = [
  {
    id: 'docker-restart-policy',
    auditId: 'docker-runtime-policy',
    title: 'Restart policies set on running containers',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps -q 2>/dev/null | while read id; do docker inspect --format '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' \"$id\"; done | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No running containers.' };
      const none = lines.filter((l) => /\bno\b|^\S+\s*$/.test(l.split(/\s+/).pop()));
      if (none.length === lines.length) {
        return { status: 'WARNING', detail: 'No restart policies set.' };
      }
      return { status: 'PASS', detail: 'Restart policies present on some/all containers.' };
    },
  },
  {
    id: 'docker-memory-limit',
    auditId: 'docker-runtime-policy',
    title: 'Memory limits configured',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps -q 2>/dev/null | while read id; do docker inspect --format '{{.Name}} {{.HostConfig.Memory}}' \"$id\"; done | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No running containers.' };
      const limited = lines.filter((l) => {
        const mem = Number(l.trim().split(/\s+/).pop());
        return mem > 0;
      });
      if (!limited.length) {
        return { status: 'WARNING', detail: 'No memory limits on running containers.' };
      }
      return { status: 'PASS', detail: `${limited.length}/${lines.length} have memory limits.` };
    },
  },
  {
    id: 'docker-cpu-limit',
    auditId: 'docker-runtime-policy',
    title: 'CPU limits configured',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps -q 2>/dev/null | while read id; do docker inspect --format '{{.Name}} NanoCpus={{.HostConfig.NanoCpus}} CpuShares={{.HostConfig.CpuShares}}' \"$id\"; done | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No running containers.' };
      const limited = lines.filter((l) => /NanoCpus=[1-9]|CpuShares=[1-9]/.test(l));
      if (!limited.length) {
        return { status: 'WARNING', detail: 'No CPU limits observed.' };
      }
      return { status: 'PASS', detail: `${limited.length} container(s) have CPU limits.` };
    },
  },
  {
    id: 'docker-healthcheck',
    auditId: 'docker-runtime-policy',
    title: 'Healthchecks defined',
    severity: 'LOW',
    weight: 3,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps -q 2>/dev/null | while read id; do docker inspect --format '{{.Name}} {{if .Config.Healthcheck}}yes{{else}}no{{end}}' \"$id\"; done | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No running containers.' };
      const yes = lines.filter((l) => /\byes\b/.test(l)).length;
      if (!yes) return { status: 'WARNING', detail: 'No healthchecks on running containers.' };
      return { status: 'PASS', detail: `${yes}/${lines.length} define healthchecks.` };
    },
  },
  {
    id: 'docker-pids-limit',
    auditId: 'docker-runtime-policy',
    title: 'PIDs limit set',
    severity: 'MEDIUM',
    weight: 4,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps -q 2>/dev/null | while read id; do docker inspect --format '{{.Name}} {{.HostConfig.PidsLimit}}' \"$id\"; done | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No running containers.' };
      const limited = lines.filter((l) => {
        const v = Number(l.trim().split(/\s+/).pop());
        return v > 0;
      });
      if (!limited.length) {
        return { status: 'WARNING', detail: 'No PIDs limits set.' };
      }
      return { status: 'PASS', detail: `${limited.length} container(s) have PIDs limits.` };
    },
  },
];

export const dockerSecretsChecks = [
  {
    id: 'docker-env-secrets',
    auditId: 'docker-secrets',
    title: 'Env vars do not obviously embed passwords',
    severity: 'HIGH',
    weight: 8,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "docker ps -q 2>/dev/null | while read id; do docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' \"$id\"; done | grep -iE 'PASSWORD=|SECRET=|API_KEY=' | head -20 || echo NONE",
    evaluate: (out) => {
      if (out.includes('NONE') || !out.trim()) {
        return { status: 'PASS', detail: 'No obvious secret env keys in sample.' };
      }
      return {
        status: 'WARNING',
        detail: 'Secret-like environment variables present — prefer Docker secrets/files.',
      };
    },
  },
  {
    id: 'docker-secrets-feature',
    auditId: 'docker-secrets',
    title: 'Docker secrets usable (swarm) or documented alternative',
    severity: 'INFO',
    weight: 2,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: 'docker secret ls 2>&1 | head -5; echo EXIT:$?',
    evaluate: (out) => {
      if (/EXIT:0/.test(out) && !/Error|is not/i.test(out)) {
        return { status: 'PASS', detail: 'Docker secrets available (swarm).' };
      }
      return {
        status: 'WARNING',
        detail: 'Docker secrets API unavailable — use mounted files/KMS instead.',
      };
    },
  },
  {
    id: 'docker-compose-env-files',
    auditId: 'docker-secrets',
    title: 'World-readable .env near compose files',
    severity: 'HIGH',
    weight: 7,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command:
      "find /home /opt /srv /var/www -xdev -name 'docker-compose*.yml' 2>/dev/null | head -20 | while read f; do d=$(dirname \"$f\"); [ -f \"$d/.env\" ] && stat -c '%a %n' \"$d/.env\"; done | head -20",
    evaluate: (out) => {
      const lines = out.trim().split('\n').filter(Boolean);
      if (!lines.length) return { status: 'SKIP', detail: 'No compose/.env pairs found.' };
      const bad = lines.filter((l) => {
        const mode = parseInt(l.split(/\s+/)[0], 8);
        return !Number.isNaN(mode) && mode & 0o004;
      });
      if (bad.length) return { status: 'FAIL', detail: bad.join('\n') };
      return { status: 'PASS', detail: 'Compose-adjacent .env files not world-readable.' };
    },
  },
  {
    id: 'docker-history-secrets-hint',
    auditId: 'docker-secrets',
    title: 'Avoid baking secrets into image layers (policy check)',
    severity: 'MEDIUM',
    weight: 5,
    requiresSudo: true,
    applicability: HAS_DOCKER,
    command: 'echo MANUAL',
    evaluate: () => ({
      status: 'WARNING',
      detail:
        'Automated layer secret scanning is out of scope — scan images with Trivy/Grype in CI.',
    }),
  },
];
