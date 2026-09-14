const S_IFMT = 0o170000;
const S_IFDIR = 0o040000;
const S_IFLNK = 0o120000;
const S_IFREG = 0o100000;

export function entryType(mode) {
  const t = mode & S_IFMT;
  if (t === S_IFDIR) return 'directory';
  if (t === S_IFLNK) return 'symlink';
  return 'file';
}

export function formatMode(mode) {
  const type = entryType(mode);
  const prefix = type === 'directory' ? 'd' : type === 'symlink' ? 'l' : '-';
  const bits = mode & 0o777;
  const chars = ['r', 'w', 'x'];
  let out = prefix;
  for (let i = 8; i >= 0; i -= 1) {
    out += bits & (1 << i) ? chars[(8 - i) % 3] : '-';
  }
  return out;
}

export function modeOctal(mode) {
  return (mode & 0o777).toString(8).padStart(4, '0');
}

export function isDirMode(mode) {
  return (mode & S_IFMT) === S_IFDIR;
}

export function isLinkMode(mode) {
  return (mode & S_IFMT) === S_IFLNK;
}

export { S_IFMT, S_IFDIR, S_IFLNK, S_IFREG };
