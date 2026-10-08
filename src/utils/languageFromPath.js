export function languageFromPath(filePath) {
  const name = (filePath.split('/').pop() ?? '').toLowerCase();

  if (name === 'nginx.conf' || name.endsWith('.nginx') || name.includes('nginx')) {
    return 'nginx';
  }
  if (name === '.env' || name.startsWith('.env.') || name.endsWith('.env')) {
    return 'dotenv';
  }
  if (
    name === 'docker-compose.yml' ||
    name === 'docker-compose.yaml' ||
    name === 'compose.yml' ||
    name === 'compose.yaml' ||
    name.endsWith('.yml') ||
    name.endsWith('.yaml')
  ) {
    return 'yaml';
  }
  if (name.endsWith('.json')) return 'json';
  if (name.endsWith('.sh') || name.endsWith('.bash') || name === 'bashrc' || name === '.bashrc') {
    return 'shell';
  }
  if (name.endsWith('.ini') || name.endsWith('.conf')) return 'ini';
  if (name.endsWith('.js') || name.endsWith('.mjs') || name.endsWith('.cjs')) return 'javascript';
  if (name.endsWith('.ts')) return 'typescript';
  if (name.endsWith('.md')) return 'markdown';
  if (name.endsWith('.py')) return 'python';
  if (name.endsWith('.css')) return 'css';
  if (name.endsWith('.html') || name.endsWith('.htm')) return 'html';
  return 'plaintext';
}

const EDITABLE_EXT = new Set([
  'txt', 'md', 'json', 'yml', 'yaml', 'xml', 'html', 'htm', 'css', 'js', 'mjs',
  'cjs', 'ts', 'tsx', 'jsx', 'sh', 'bash', 'zsh', 'env', 'ini', 'conf', 'cfg',
  'toml', 'py', 'rb', 'go', 'rs', 'java', 'sql', 'log', 'service', 'nginx',
]);

const EDITABLE_NAMES = new Set([
  'nginx.conf', 'dockerfile', 'makefile', '.env', '.bashrc', '.profile',
  '.gitignore', '.dockerignore', 'docker-compose.yml', 'docker-compose.yaml',
]);

export function isEditableFile({ name, type, size }) {
  if (type !== 'file') return false;
  if (size > 5 * 1024 * 1024) return false;
  const lower = name.toLowerCase();
  if (EDITABLE_NAMES.has(lower)) return true;
  const ext = lower.includes('.') ? lower.split('.').pop() : '';
  if (EDITABLE_EXT.has(ext)) return true;
  if (lower.startsWith('.env')) return true;
  return false;
}

export function isBinaryBuffer(buf) {
  if (!buf || buf.length === 0) return false;
  const slice = buf.subarray(0, Math.min(buf.length, 8192));
  return slice.includes(0);
}
