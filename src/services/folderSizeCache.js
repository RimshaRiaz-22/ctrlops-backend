const cache = new Map();
const TTL_MS = 60_000;

export function getCachedSize(serverId, dirPath) {
  const key = `${serverId}:${dirPath}`;
  const hit = cache.get(key);
  if (!hit) return null;
  if (Date.now() - hit.at > TTL_MS) {
    cache.delete(key);
    return null;
  }
  return hit.bytes;
}

export function setCachedSize(serverId, dirPath, bytes) {
  cache.set(`${serverId}:${dirPath}`, { bytes, at: Date.now() });
}
