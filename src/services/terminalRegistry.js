const MAX_PER_USER_SERVER = 3;
const sessions = new Map();

export function add(session) {
  sessions.set(session.sessionId, session);
}

export function remove(sessionId) {
  sessions.delete(sessionId);
}

export function get(sessionId) {
  return sessions.get(sessionId) ?? null;
}

export function countFor(userId, serverId) {
  let n = 0;
  for (const session of sessions.values()) {
    if (session.userId === userId && session.serverId === serverId) n += 1;
  }
  return n;
}

export function isAtCap(userId, serverId) {
  return countFor(userId, serverId) >= MAX_PER_USER_SERVER;
}

export function listAll() {
  return [...sessions.values()];
}

export function resetForTests() {
  sessions.clear();
}

export { MAX_PER_USER_SERVER };
